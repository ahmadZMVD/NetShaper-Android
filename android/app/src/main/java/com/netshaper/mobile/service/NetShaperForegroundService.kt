package com.netshaper.mobile.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.UserManager
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.netshaper.mobile.MainActivity
import com.netshaper.mobile.R
import com.netshaper.mobile.engine.Formatters
import com.netshaper.mobile.engine.GoMobileNetShaperEngine
import com.netshaper.mobile.engine.MobileSnapshot
import com.netshaper.mobile.engine.MobileStartConfig
import com.netshaper.mobile.engine.VpnBypassState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.roundToInt

/**
 * Persistent `specialUse` ForegroundService running NetShaper's local SOCKS5 engine on 127.0.0.1:1080.
 *
 * - NO VpnService (preserves Android's single VpnService slot exclusively for v2rayNG).
 * - Immediate `promoteToForeground()` on every entry path before async work or stopSelf().
 * - Serializes Start/Stop via [serviceMutex] + [sessionGen] to prevent concurrency races.
 * - Uses modern per-UID `ConnectivityManager` callbacks (zero `cm.allNetworks`).
 * - Adaptive foreground (1000ms) / background (5000ms) telemetry + notification rate-limiting.
 */
class NetShaperForegroundService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val serviceMutex = Mutex()
    private val sessionGen = AtomicLong(0L)

    private var pollJob: Job? = null
    private var lastReportedNetType: String? = null
    private var lastReportedMetered: Boolean? = null

    @Volatile private var hasDirectUnderlay: Boolean = false
    @Volatile private var underlayNetType: String? = null
    @Volatile private var underlayMetered: Boolean = false

    @Volatile private var isInForegroundState: Boolean = false
    private var lastNotifState: String? = null
    private var lastNotifPower: String? = null
    private var lastNotifText: String? = null
    private var lastNotifLoop: Boolean = false
    private var lastNotifAtMs: Long = 0L

    private var defaultNetCallback: ConnectivityManager.NetworkCallback? = null
    private var underlayNetCallback: ConnectivityManager.NetworkCallback? = null
    private var vpnNetCallback: ConnectivityManager.NetworkCallback? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        registerNetworkMonitors()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Satisfy Android 12-15 startForeground() 5s contract on EVERY entry path without blocking Main thread.
        promoteToForeground(NetShaperRuntime.snapshot.value)

        if (intent == null) {
            // START_STICKY OS restart: validate CE storage unlocked before touching AndroidKeyStore.
            val um = getSystemService(Context.USER_SERVICE) as? UserManager
            if (um != null && !runCatching { um.isUserUnlocked }.getOrDefault(true)) {
                stopSelfClean()
                return START_NOT_STICKY
            }
        }

        when (intent?.action) {
            ACTION_COPY_URI -> {
                serviceScope.launch {
                    val uri = withContext(Dispatchers.IO) { NetShaperRuntime.engine.getV2RayNGProfileUri() }
                    withContext(Dispatchers.Main) {
                        NetShaperRuntime.copyToClipboard(this@NetShaperForegroundService, "NetShaper v2rayNG Profile", uri)
                        Toast.makeText(applicationContext, "Copied $uri", Toast.LENGTH_SHORT).show()
                    }
                }
                return START_STICKY
            }

            ACTION_STOP -> {
                val gen = sessionGen.incrementAndGet()
                serviceScope.launch {
                    serviceMutex.withLock {
                        stopEngineAndSelf(gen)
                    }
                }
                return START_NOT_STICKY
            }

            ACTION_START, null -> {
                val extraConfig = intent?.getStringExtra(EXTRA_CONFIG_JSON)
                val gen = sessionGen.incrementAndGet()
                serviceScope.launch {
                    val startedOk = serviceMutex.withLock {
                        if (gen != sessionGen.get()) return@withLock false
                        if (NetShaperRuntime.isNativeCore) {
                            withContext(Dispatchers.IO) {
                                GoMobileNetShaperEngine.setGoAndroidContext(applicationContext)
                            }
                        }
                        val configJson = extraConfig ?: withContext(Dispatchers.IO) { buildConfigFromStores() }
                        if (configJson == null) {
                            stopSelfClean()
                            return@withLock false
                        }
                        val result = withContext(Dispatchers.IO) {
                            NetShaperRuntime.engine.start(configJson, NetShaperRuntime.engineCallback)
                        }
                        result.onFailure { err ->
                            NetShaperRuntime.engineCallback.onError("start_failed", err.message ?: "Unable to start engine")
                            withContext(Dispatchers.IO) {
                                NetShaperRuntime.refreshSnapshot()
                                NetShaperRuntime.pullNewLogs()
                            }
                            stopSelfClean()
                            return@withLock false
                        }
                        if (gen != sessionGen.get()) return@withLock false
                        reportInitialNetworkCapabilities()
                        startTelemetryLoop(gen)
                        true
                    }
                    if (startedOk && gen == sessionGen.get()) {
                        holdBootWakeLockUntilSettled(gen)
                    }
                }
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun buildConfigFromStores(): String? {
        val prefs = NetShaperRuntime.prefsStore(this)
        val token = NetShaperRuntime.tokenStore(this).loadToken().orEmpty()
        if (token.isBlank() && NetShaperRuntime.isNativeCore) {
            return null
        }
        return MobileStartConfig(
            githubToken = token.ifBlank { "gho_phase4_mock_token" },
            codespaceName = prefs.codespaceName,
            localHost = "127.0.0.1",
            localPort = 1080,
            dataDir = NetShaperRuntime.dataDirPath(this),
            poolSize = 2,
            stopOnExit = prefs.stopOnExit,
            enableIdleParking = prefs.enableIdleParking,
            enableMetricsLog = false
        ).toJson()
    }

    private suspend fun holdBootWakeLockUntilSettled(myGen: Long) {
        val wl = acquireBoundedWakeLock("boot", MAX_WAKELOCK_MS)
        try {
            // Hold boot WakeLock outside serviceMutex so ACTION_STOP interrupts immediately (0ms wait).
            val deadline = System.currentTimeMillis() + MAX_WAKELOCK_MS
            while (myGen == sessionGen.get() && System.currentTimeMillis() < deadline) {
                val st = withContext(Dispatchers.IO) { NetShaperRuntime.refreshSnapshot().state }
                if (st == "RUNNING" || st == "STOPPED") break
                delay(250L)
            }
        } finally {
            releaseWakeLockSafely(wl)
        }
    }

    private suspend fun stopEngineAndSelf(myGen: Long) {
        pollJob?.cancel()
        pollJob = null
        val wl = acquireBoundedWakeLock("stop", STOP_WAKELOCK_MS)
        try {
            withContext(Dispatchers.IO) {
                NetShaperRuntime.engine.stop()
                NetShaperRuntime.refreshSnapshot()
                NetShaperRuntime.pullNewLogs()
            }
        } finally {
            releaseWakeLockSafely(wl)
            if (myGen == sessionGen.get()) {
                stopSelfClean()
            }
        }
    }

    private fun stopSelfClean() {
        isInForegroundState = false
        runCatching { ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE) }
        stopSelf()
    }

    private fun startTelemetryLoop(myGen: Long) {
        pollJob?.cancel()
        pollJob = serviceScope.launch {
            while (isActive && myGen == sessionGen.get()) {
                val inFg = NetShaperRuntime.isAppInForeground
                val snap = withContext(Dispatchers.IO) {
                    val s = NetShaperRuntime.refreshSnapshot()
                    if (inFg) {
                        NetShaperRuntime.pullNewLogs()
                    }
                    s
                }
                updateNotificationIfNeeded(snap, inFg)
                if (snap.state == "STOPPED") {
                    stopSelfClean()
                    break
                }
                delay(if (inFg) FOREGROUND_POLL_MS else BACKGROUND_POLL_MS)
            }
        }
    }

    private fun registerNetworkMonitors() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        NetShaperRuntime.probeCurrentVpnBypassState(this)

        // 1. Track clean non-VPN physical underlay transport type + metered state without cm.allNetworks.
        val underlayReq = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val underlayCb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                hasDirectUnderlay = true
                cm.getNetworkCapabilities(network)?.let { caps ->
                    underlayNetType = mapTransportType(caps)
                    underlayMetered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                    evaluateCombinedNetwork(cm)
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                hasDirectUnderlay = true
                underlayNetType = mapTransportType(networkCapabilities)
                underlayMetered = !networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                evaluateCombinedNetwork(cm)
            }

            override fun onLost(network: Network) {
                hasDirectUnderlay = false
                underlayNetType = null
                evaluateCombinedNetwork(cm)
            }
        }
        runCatching {
            cm.registerNetworkCallback(underlayReq, underlayCb)
            underlayNetCallback = underlayCb
        }

        // 2. Track UID-scoped active network to detect routing loops into v2rayNG TUN immediately.
        val defaultCb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                evaluateCombinedNetwork(cm, network)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                val loop = networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                if (loop) {
                    NetShaperRuntime.updateVpnTransportObserved(this@NetShaperForegroundService, true)
                } else {
                    NetShaperRuntime.probeCurrentVpnBypassState(this@NetShaperForegroundService)
                }
                evaluateCapabilities(networkCapabilities)
            }

            override fun onLost(network: Network) {
                NetShaperRuntime.probeCurrentVpnBypassState(this@NetShaperForegroundService)
                val activeNet = cm.activeNetwork
                if (activeNet == null || activeNet == network) {
                    notifyEngineNetwork("none", false)
                } else {
                    evaluateCombinedNetwork(cm, activeNet)
                }
            }
        }
        runCatching {
            cm.registerDefaultNetworkCallback(defaultCb)
            defaultNetCallback = defaultCb
        }

        // 3. Dedicated VPN overlay observer distinguishing NO_VPN vs VPN_BYPASSED_SAFE vs ROUTING_LOOP_DETECTED.
        val vpnReq = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val vpnCb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                NetShaperRuntime.updateVpnTransportObserved(this@NetShaperForegroundService, true)
            }

            override fun onLost(network: Network) {
                NetShaperRuntime.updateVpnTransportObserved(this@NetShaperForegroundService, false)
            }
        }
        runCatching {
            cm.registerNetworkCallback(vpnReq, vpnCb)
            vpnNetCallback = vpnCb
        }
    }

    private fun reportInitialNetworkCapabilities() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        evaluateCombinedNetwork(cm, cm.activeNetwork)
    }

    private fun evaluateCombinedNetwork(cm: ConnectivityManager, network: Network? = cm.activeNetwork) {
        NetShaperRuntime.probeCurrentVpnBypassState(this)
        if (network == null) {
            if (hasDirectUnderlay && underlayNetType != null) {
                notifyEngineNetwork(underlayNetType!!, underlayMetered)
            } else {
                notifyEngineNetwork("none", false)
            }
            return
        }
        val caps = cm.getNetworkCapabilities(network)
        if (caps == null) {
            notifyEngineNetwork(underlayNetType ?: "none", underlayMetered)
            return
        }
        evaluateCapabilities(caps)
    }

    private fun evaluateCapabilities(caps: NetworkCapabilities) {
        var type = mapTransportType(caps)
        var metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        if (type == null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            type = underlayNetType
            metered = underlayMetered
        }
        notifyEngineNetwork(type ?: "unknown", metered)
    }

    private fun mapTransportType(caps: NetworkCapabilities): String? = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        else -> null
    }

    private fun notifyEngineNetwork(networkType: String, isMetered: Boolean) {
        val prevType = lastReportedNetType
        val prevMetered = lastReportedMetered
        if (prevType == networkType && prevMetered == isMetered) return
        lastReportedNetType = networkType
        lastReportedMetered = isMetered

        val isHandover = prevType != null && prevType != networkType && networkType != "none"
        serviceScope.launch {
            val wl = if (isHandover) acquireBoundedWakeLock("handover", HANDOVER_WAKELOCK_MS) else null
            try {
                withContext(Dispatchers.IO) {
                    NetShaperRuntime.engine.notifyNetworkChange(networkType, isMetered)
                }
                if (isHandover) delay(2_500L)
            } finally {
                releaseWakeLockSafely(wl)
            }
        }
    }

    private fun acquireBoundedWakeLock(reason: String, timeoutMs: Long): PowerManager.WakeLock? {
        val boundedMs = timeoutMs.coerceIn(1_000L, MAX_WAKELOCK_MS)
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return null
        return runCatching {
            pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "NetShaper:Bounded_$reason").apply {
                setReferenceCounted(false)
                acquire(boundedMs)
            }
        }.getOrNull()
    }

    private fun releaseWakeLockSafely(wl: PowerManager.WakeLock?) {
        runCatching {
            if (wl != null && wl.isHeld) wl.release()
        }
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_desc)
            setShowBadge(false)
            enableLights(false)
            enableVibration(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun promoteToForeground(snap: MobileSnapshot) {
        val loopDetected = NetShaperRuntime.vpnBypassState.value == VpnBypassState.ROUTING_LOOP_DETECTED
        val text = formatNotificationText(snap, loopDetected)
        val notification = buildNotification(snap, text)
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, fgsType)
        isInForegroundState = true
        lastNotifState = snap.state
        lastNotifPower = snap.powerState
        lastNotifLoop = loopDetected
        lastNotifText = text
        lastNotifAtMs = System.currentTimeMillis()
    }

    private fun updateNotificationIfNeeded(snap: MobileSnapshot, inFg: Boolean) {
        val loopDetected = NetShaperRuntime.vpnBypassState.value == VpnBypassState.ROUTING_LOOP_DETECTED
        val text = formatNotificationText(snap, loopDetected)
        val now = System.currentTimeMillis()
        val stateChanged = snap.state != lastNotifState ||
            snap.powerState != lastNotifPower ||
            loopDetected != lastNotifLoop
        if (!stateChanged && text == lastNotifText) return

        val minInterval = if (inFg) NOTIF_MIN_INTERVAL_FG_MS else NOTIF_MIN_INTERVAL_BG_MS
        if (!stateChanged && now - lastNotifAtMs < minInterval) return

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        runCatching {
            nm.notify(NOTIFICATION_ID, buildNotification(snap, text))
            lastNotifState = snap.state
            lastNotifPower = snap.powerState
            lastNotifLoop = loopDetected
            lastNotifText = text
            lastNotifAtMs = now
        }
    }

    private fun formatNotificationText(snap: MobileSnapshot, loopDetected: Boolean): String {
        if (loopDetected) {
            return "ROUTING LOOP: Add NetShaper to v2rayNG Per-App Bypass!"
        }
        val statusLabel = when (snap.state) {
            "RUNNING" -> "CONNECTED"
            "PAUSED_OFFLINE" -> "PAUSED OFFLINE"
            else -> snap.state
        }
        val rttPart = if (snap.latencyP50Ms > 0.0) "${snap.latencyP50Ms.roundToInt()}ms" else "--"
        val idleSuffix = if (snap.powerState == "IDLE_DEEP") " · IDLE_DEEP (2→1)" else ""
        return "$statusLabel · $rttPart · ${snap.healthyWorkers}/${snap.poolSize} · " +
            "↑${Formatters.formatBytesShort(snap.bytesUp)} ↓${Formatters.formatBytesShort(snap.bytesDown)}$idleSuffix"
    }

    private fun buildNotification(snap: MobileSnapshot, contentText: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPi = PendingIntent.getActivity(
            this, 0, openIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val copyPi = PendingIntent.getForegroundService(
            this,
            1,
            Intent(this, NetShaperForegroundService::class.java).setAction(ACTION_COPY_URI),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopPi = PendingIntent.getForegroundService(
            this,
            2,
            Intent(this, NetShaperForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_netshaper)
            .setContentTitle("NetShaper · ${snap.localAddr}")
            .setContentText(contentText)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openPi)
            .addAction(0, "Copy URI", copyPi)
            .addAction(0, "Stop", stopPi)
            .build()
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        val gen = sessionGen.incrementAndGet()
        serviceScope.launch(Dispatchers.IO) {
            stopEngineAndSelf(gen)
        }
    }

    override fun onDestroy() {
        pollJob?.cancel()
        mainHandler.removeCallbacksAndMessages(null)
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        defaultNetCallback?.let { cb -> runCatching { cm?.unregisterNetworkCallback(cb) } }
        underlayNetCallback?.let { cb -> runCatching { cm?.unregisterNetworkCallback(cb) } }
        vpnNetCallback?.let { cb -> runCatching { cm?.unregisterNetworkCallback(cb) } }

        if (NetShaperRuntime.snapshot.value.isActiveOrTransitioning) {
            Thread({
                runCatching { NetShaperRuntime.engine.stop() }
            }, "netshaper-fgs-teardown").start()
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL_ID = "netshaper_tunnel_channel"
        private const val NOTIFICATION_ID = 7001

        private const val MAX_WAKELOCK_MS = 60_000L
        private const val STOP_WAKELOCK_MS = 15_000L
        private const val HANDOVER_WAKELOCK_MS = 12_000L
        private const val FOREGROUND_POLL_MS = 1_000L
        private const val BACKGROUND_POLL_MS = 5_000L
        private const val NOTIF_MIN_INTERVAL_FG_MS = 5_000L
        private const val NOTIF_MIN_INTERVAL_BG_MS = 30_000L

        const val ACTION_START = "com.netshaper.mobile.action.START"
        const val ACTION_STOP = "com.netshaper.mobile.action.STOP"
        const val ACTION_COPY_URI = "com.netshaper.mobile.action.COPY_URI"
        const val EXTRA_CONFIG_JSON = "extra_config_json"

        fun startTunnel(context: Context, config: MobileStartConfig) {
            val intent = Intent(context, NetShaperForegroundService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONFIG_JSON, config.toJson())
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun stopTunnel(context: Context) {
            val intent = Intent(context, NetShaperForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            val started = runCatching {
                context.startService(intent)
                true
            }.getOrDefault(false)
            if (!started) {
                runCatching { ContextCompat.startForegroundService(context, intent) }
            }
        }
    }
}
