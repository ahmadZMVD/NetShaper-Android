package com.netshaper.mobile.service

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.netshaper.mobile.engine.EngineProvider
import com.netshaper.mobile.engine.GoMobileNetShaperEngine
import com.netshaper.mobile.engine.MobileSnapshot
import com.netshaper.mobile.engine.NetShaperCallback
import com.netshaper.mobile.engine.NetShaperEngine
import com.netshaper.mobile.engine.TerminalLogLine
import com.netshaper.mobile.engine.VpnBypassState
import com.netshaper.mobile.security.AppPreferencesStore
import com.netshaper.mobile.security.SecureTokenStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-scoped state coordinator bridging [NetShaperForegroundService], [ProcessLifecycleOwner],
 * and Compose ViewModels via wait-free StateFlows.
 *
 * Guarantees ZERO JNI, ZERO Keystore, and ZERO blocking I/O on the Main UI thread:
 * - Static init performs zero JNI calls.
 * - [initializeAsync] initializes `go.Seq.setContext` + initial snapshot/log catch-up on Dispatchers.IO.
 * - [engineCallback] never re-enters JNI synchronously from Go callback threads.
 */
object NetShaperRuntime {

    val isNativeCore: Boolean
        get() = EngineProvider.isNativeCore

    val engine: NetShaperEngine by lazy { EngineProvider.create() }

    private val runtimeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val initialized = AtomicBoolean(false)
    private val refreshTrigger = Channel<Unit>(Channel.CONFLATED)

    private val storeLock = Any()
    @Volatile private var cachedTokenStore: SecureTokenStore? = null
    @Volatile private var cachedPrefsStore: AppPreferencesStore? = null

    private val logLock = Any()
    private val timeFmt = ThreadLocal.withInitial { SimpleDateFormat("HH:mm:ss", Locale.US) }

    private val _snapshot = MutableStateFlow(MobileSnapshot())
    val snapshot: StateFlow<MobileSnapshot> = _snapshot.asStateFlow()

    private val _logs = MutableStateFlow<List<TerminalLogLine>>(emptyList())
    val logs: StateFlow<List<TerminalLogLine>> = _logs.asStateFlow()

    private val _vpnBypassState = MutableStateFlow(VpnBypassState.NO_VPN)
    val vpnBypassState: StateFlow<VpnBypassState> = _vpnBypassState.asStateFlow()

    private val _lastCallbackError = MutableStateFlow<String?>(null)
    val lastCallbackError: StateFlow<String?> = _lastCallbackError.asStateFlow()

    @Volatile
    var isAppInForeground: Boolean = false
        private set

    @Volatile
    private var lastLogSeq: Long = 0L

    @Volatile
    private var anyVpnPresent: Boolean = false

    init {
        runtimeScope.launch {
            for (signal in refreshTrigger) {
                refreshSnapshot()
            }
        }
    }

    fun initializeAsync(context: Context) {
        val appCtx = context.applicationContext
        if (!initialized.compareAndSet(false, true)) return
        runtimeScope.launch {
            if (isNativeCore) {
                GoMobileNetShaperEngine.setGoAndroidContext(appCtx)
            }
            probeCurrentVpnBypassState(appCtx)
            refreshSnapshot()
            pullNewLogs()
        }
    }

    val engineCallback: NetShaperCallback = object : NetShaperCallback {
        override fun onStateChange(state: String, detail: String) {
            // Never call back into Go synchronously on the Go callback dispatcher thread.
            refreshTrigger.trySend(Unit)
        }

        override fun onLogLine(seq: Long, level: String, text: String) {
            if (text.isBlank()) return
            val ts = timeFmt.get()?.format(Date()) ?: "00:00:00"
            val entry = TerminalLogLine(seq = seq, ts = ts, level = level, text = text)
            synchronized(logLock) {
                if (seq <= lastLogSeq) return
                val merged = (_logs.value + entry).takeLast(500)
                lastLogSeq = entry.seq
                _logs.value = merged
            }
        }

        override fun onError(code: String, message: String) {
            _lastCallbackError.value = if (code.isNotBlank()) "[$code] $message" else message
            refreshTrigger.trySend(Unit)
        }
    }

    fun dataDirPath(context: Context): String {
        val dir = File(context.applicationContext.filesDir, "netshaper")
        if (!dir.exists()) dir.mkdirs()
        return dir.absolutePath
    }

    fun refreshSnapshot(): MobileSnapshot {
        val parsed = MobileSnapshot.fromJson(engine.getSnapshotJson())
        _snapshot.value = parsed
        return parsed
    }

    fun pullNewLogs() {
        val since = lastLogSeq
        val raw = engine.getLogsJson(since)
        val delta = TerminalLogLine.listFromJson(raw)
        if (delta.isEmpty()) return
        synchronized(logLock) {
            val fresh = delta.filter { it.seq > lastLogSeq }
            if (fresh.isEmpty()) return
            val merged = (_logs.value + fresh).takeLast(500)
            lastLogSeq = merged.lastOrNull()?.seq ?: lastLogSeq
            _logs.value = merged
        }
    }

    fun clearLogs() {
        runtimeScope.launch {
            engine.clearLogs()
            synchronized(logLock) {
                // Keep lastLogSeq monotonic so in-flight callbacks never duplicate cleared lines.
                _logs.value = emptyList()
            }
        }
    }

    fun clearErrorBanner() {
        _lastCallbackError.value = null
    }

    fun setAppForeground(inForeground: Boolean) {
        isAppInForeground = inForeground
        runtimeScope.launch {
            engine.setAppForeground(inForeground)
            if (inForeground) {
                refreshSnapshot()
                pullNewLogs()
            }
        }
    }

    fun updateVpnTransportObserved(context: Context, vpnPresent: Boolean) {
        anyVpnPresent = vpnPresent
        probeCurrentVpnBypassState(context)
    }

    /**
     * Exact per-UID routing-loop check without deprecated `ConnectivityManager.allNetworks`.
     * Because Android scopes `cm.getNetworkCapabilities(cm.activeNetwork)` to the calling UID:
     * - If `activeNetwork` has `TRANSPORT_VPN`, NetShaper's own sockets route into v2rayNG -> ROUTING_LOOP_DETECTED.
     * - If VPN is active system-wide (`anyVpnPresent == true`) while `activeNetwork` lacks `TRANSPORT_VPN`,
     *   NetShaper is properly bypassed -> VPN_BYPASSED_SAFE.
     */
    fun probeCurrentVpnBypassState(context: Context): VpnBypassState {
        val cm = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return VpnBypassState.NO_VPN
        val activeCaps = runCatching { cm.activeNetwork?.let { cm.getNetworkCapabilities(it) } }.getOrNull()
        val selfRoutedViaVpn = activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val next = when {
            selfRoutedViaVpn -> {
                anyVpnPresent = true
                VpnBypassState.ROUTING_LOOP_DETECTED
            }
            anyVpnPresent -> VpnBypassState.VPN_BYPASSED_SAFE
            else -> VpnBypassState.NO_VPN
        }
        _vpnBypassState.value = next
        return next
    }

    fun copyToClipboard(context: Context, label: String, text: String): Boolean = runCatching {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return false
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        true
    }.getOrDefault(false)

    fun tokenStore(context: Context): SecureTokenStore {
        cachedTokenStore?.let { return it }
        return synchronized(storeLock) {
            cachedTokenStore ?: SecureTokenStore(context.applicationContext).also { cachedTokenStore = it }
        }
    }

    fun prefsStore(context: Context): AppPreferencesStore {
        cachedPrefsStore?.let { return it }
        return synchronized(storeLock) {
            cachedPrefsStore ?: AppPreferencesStore(context.applicationContext).also { cachedPrefsStore = it }
        }
    }
}
