package com.netshaper.mobile.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.netshaper.mobile.engine.CodespaceItem
import com.netshaper.mobile.engine.DeviceAuthPoll
import com.netshaper.mobile.engine.DeviceAuthStart
import com.netshaper.mobile.engine.Formatters
import com.netshaper.mobile.engine.MobileSnapshot
import com.netshaper.mobile.engine.MobileStartConfig
import com.netshaper.mobile.engine.QuotaReport
import com.netshaper.mobile.engine.TerminalLogLine
import com.netshaper.mobile.engine.VpnBypassState
import com.netshaper.mobile.oem.BatterySurvivalHelper
import com.netshaper.mobile.oem.PermissionReadinessState
import com.netshaper.mobile.service.NetShaperForegroundService
import com.netshaper.mobile.service.NetShaperRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class MainTab { HOME, TERMINAL, ACCOUNT }

data class AccountUiState(
    val hasToken: Boolean = false,
    val maskedToken: String? = null,
    val oauthClientId: String = "",
    val deviceAuth: DeviceAuthStart? = null,
    val isPollingDeviceAuth: Boolean = false,
    val codespaceName: String = "netshaper-edge-prod",
    val codespaces: List<CodespaceItem> = emptyList(),
    val isLoadingCodespaces: Boolean = false,
    val quotaReport: QuotaReport? = null,
    val isCheckingQuota: Boolean = false,
    val isStoppingCodespace: Boolean = false,
    val stopOnExit: Boolean = true,
    val enableIdleParking: Boolean = true,
    val vpnBannerDismissed: Boolean = false,
    val readiness: PermissionReadinessState = PermissionReadinessState()
) {
    val isBatteryUnrestricted: Boolean
        get() = readiness.batteryOptimizationIgnored
}

class NetShaperViewModel(application: Application) : AndroidViewModel(application) {

    private val appContext = application.applicationContext
    private val tokenStore = NetShaperRuntime.tokenStore(appContext)
    private val prefsStore = NetShaperRuntime.prefsStore(appContext)

    val snapshot: StateFlow<MobileSnapshot> = NetShaperRuntime.snapshot
    val logs: StateFlow<List<TerminalLogLine>> = NetShaperRuntime.logs
    val vpnBypassState: StateFlow<VpnBypassState> = NetShaperRuntime.vpnBypassState
    val isNativeCore: Boolean = NetShaperRuntime.isNativeCore

    private val _selectedTab = MutableStateFlow(MainTab.HOME)
    val selectedTab: StateFlow<MainTab> = _selectedTab.asStateFlow()

    // Zero synchronous Keystore decrypt / SharedPreferences / JNI calls on Main thread in init!
    private val _accountState = MutableStateFlow(AccountUiState())
    val accountState: StateFlow<AccountUiState> = _accountState.asStateFlow()

    private val _snackbarEvents = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val snackbarEvents: SharedFlow<String> = _snackbarEvents.asSharedFlow()

    private var devicePollJob: Job? = null

    init {
        NetShaperRuntime.initializeAsync(appContext)

        viewModelScope.launch {
            val initial = withContext(Dispatchers.IO) {
                val preview = tokenStore.maskedTokenPreview()
                val invalidated = tokenStore.consumeKeyInvalidatedNotice()
                val readiness = BatterySurvivalHelper.inspectReadiness(
                    appContext,
                    NetShaperRuntime.vpnBypassState.value
                )
                Triple(preview, invalidated, readiness) to AccountUiState(
                    hasToken = !preview.isNullOrEmpty(),
                    maskedToken = preview,
                    oauthClientId = prefsStore.oauthClientId,
                    codespaceName = prefsStore.codespaceName,
                    stopOnExit = prefsStore.stopOnExit,
                    enableIdleParking = prefsStore.enableIdleParking,
                    vpnBannerDismissed = prefsStore.vpnBannerDismissed,
                    readiness = readiness
                )
            }
            _accountState.value = initial.second
            if (initial.first.second) {
                emitSnackbar("AndroidKeyStore key was reset by an OS update — please sign in again")
            }
        }

        viewModelScope.launch {
            NetShaperRuntime.vpnBypassState.collect { vpnState ->
                val updated = withContext(Dispatchers.IO) {
                    BatterySurvivalHelper.inspectReadiness(appContext, vpnState)
                }
                _accountState.update { it.copy(readiness = updated) }
            }
        }

        viewModelScope.launch {
            NetShaperRuntime.lastCallbackError.collect { err ->
                if (!err.isNullOrBlank()) {
                    emitSnackbar(err)
                    NetShaperRuntime.clearErrorBanner()
                }
            }
        }
    }

    fun selectTab(tab: MainTab) {
        _selectedTab.value = tab
        if (tab == MainTab.ACCOUNT) {
            refreshReadinessStatus()
        }
    }

    fun refreshReadinessStatus() {
        viewModelScope.launch {
            val state = withContext(Dispatchers.IO) {
                val vpn = NetShaperRuntime.probeCurrentVpnBypassState(appContext)
                BatterySurvivalHelper.inspectReadiness(appContext, vpn)
            }
            _accountState.update { it.copy(readiness = state) }
        }
    }

    fun dismissVpnBanner() {
        _accountState.update { it.copy(vpnBannerDismissed = true) }
        viewModelScope.launch(Dispatchers.IO) {
            prefsStore.vpnBannerDismissed = true
        }
    }

    fun toggleTunnel() {
        val cur = snapshot.value
        if (cur.isActiveOrTransitioning) {
            NetShaperForegroundService.stopTunnel(appContext)
            emitSnackbar("Stopping tunnel cleanly...")
            return
        }

        val stateSnapshot = _accountState.value
        val cs = stateSnapshot.codespaceName.trim()
        Formatters.validateCodespaceName(cs)?.let { err ->
            emitSnackbar("Invalid Codespace name: $err")
            _selectedTab.value = MainTab.ACCOUNT
            return
        }

        viewModelScope.launch {
            val config = withContext(Dispatchers.IO) {
                val token = tokenStore.loadToken().orEmpty()
                if (token.isBlank() && isNativeCore) {
                    return@withContext null
                }
                MobileStartConfig(
                    githubToken = token.ifBlank { "gho_phase4_mock_token" },
                    codespaceName = cs,
                    localHost = "127.0.0.1",
                    localPort = 1080,
                    dataDir = NetShaperRuntime.dataDirPath(appContext),
                    poolSize = 2,
                    stopOnExit = stateSnapshot.stopOnExit,
                    enableIdleParking = stateSnapshot.enableIdleParking,
                    enableMetricsLog = false
                )
            }
            if (config == null) {
                _accountState.update { it.copy(hasToken = false, maskedToken = null) }
                emitSnackbar("Sign in with GitHub or save a PAT on the Account tab first")
                _selectedTab.value = MainTab.ACCOUNT
                return@launch
            }
            NetShaperForegroundService.startTunnel(appContext, config)
        }
    }

    fun copyV2RayNGProfile() {
        viewModelScope.launch {
            val uri = snapshot.value.v2rayngUri.ifBlank {
                withContext(Dispatchers.IO) { NetShaperRuntime.engine.getV2RayNGProfileUri() }
            }
            if (NetShaperRuntime.copyToClipboard(appContext, "v2rayNG SOCKS5 Profile", uri)) {
                emitSnackbar("Copied v2rayNG profile: $uri")
            } else {
                emitSnackbar("Failed to copy to clipboard")
            }
        }
    }

    fun copyHost() {
        val host = snapshot.value.localHost
        if (NetShaperRuntime.copyToClipboard(appContext, "NetShaper Host", host)) {
            emitSnackbar("Copied host: $host")
        }
    }

    fun copyPort() {
        val port = snapshot.value.localPort.toString()
        if (NetShaperRuntime.copyToClipboard(appContext, "NetShaper Port", port)) {
            emitSnackbar("Copied port: $port")
        }
    }

    fun copyText(label: String, text: String, toast: String) {
        if (NetShaperRuntime.copyToClipboard(appContext, label, text)) {
            emitSnackbar(toast)
        }
    }

    fun clearLogs() {
        NetShaperRuntime.clearLogs()
        emitSnackbar("Terminal buffer cleared")
    }

    fun copyAllLogs() {
        val current = logs.value
        if (current.isEmpty()) {
            emitSnackbar("No logs to copy")
            return
        }
        val text = current.joinToString("\n") { "${it.ts} [${it.level}] ${it.text}" }
        if (NetShaperRuntime.copyToClipboard(appContext, "NetShaper Logs", text)) {
            emitSnackbar("Copied ${current.size} log lines")
        }
    }

    fun savePatToken(pat: String) {
        val trimmed = pat.trim()
        if (trimmed.length < 10) {
            emitSnackbar("Enter a valid GitHub Personal Access Token (codespace scope)")
            return
        }
        viewModelScope.launch {
            val preview = withContext(Dispatchers.IO) {
                if (tokenStore.saveToken(trimmed)) tokenStore.maskedTokenPreview() else null
            }
            if (preview != null) {
                _accountState.update { it.copy(hasToken = true, maskedToken = preview) }
                emitSnackbar("GitHub token encrypted & saved in AndroidKeyStore")
            } else {
                emitSnackbar("Failed to encrypt token in AndroidKeyStore")
            }
        }
    }

    fun signOutAndWipeToken() {
        cancelDeviceAuth()
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                tokenStore.clearToken()
            }
            _accountState.update {
                it.copy(
                    hasToken = false,
                    maskedToken = null,
                    codespaces = emptyList(),
                    quotaReport = null
                )
            }
            emitSnackbar("Token wiped from AndroidKeyStore")
        }
    }

    fun updateOauthClientId(clientId: String) {
        val trimmed = clientId.trim()
        _accountState.update { it.copy(oauthClientId = trimmed) }
        viewModelScope.launch(Dispatchers.IO) {
            prefsStore.oauthClientId = trimmed
        }
    }

    fun startDeviceAuth(clientIdInput: String) {
        val clientId = clientIdInput.trim().ifBlank {
            if (!isNativeCore) "Ov23liNetShaperPhase4Demo" else ""
        }
        if (clientId.isBlank()) {
            emitSnackbar("Enter a GitHub OAuth App Client ID or use Option B (PAT)")
            return
        }
        updateOauthClientId(clientId)
        devicePollJob?.cancel()

        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) {
                NetShaperRuntime.engine.startDeviceAuthJson(clientId)
            }
            res.onSuccess { raw ->
                val startInfo = DeviceAuthStart.fromJson(raw)
                if (startInfo.deviceCode.isBlank() || startInfo.userCode.isBlank()) {
                    emitSnackbar("Device Flow returned empty authorization code")
                    return@onSuccess
                }
                _accountState.update {
                    it.copy(deviceAuth = startInfo, isPollingDeviceAuth = true)
                }
                emitSnackbar("Code ${startInfo.userCode} ready — verify in browser")
                beginDeviceAuthPolling(clientId, startInfo)
            }.onFailure { err ->
                emitSnackbar("Device Flow failed: ${err.message ?: "unknown error"}")
            }
        }
    }

    private fun beginDeviceAuthPolling(clientId: String, startInfo: DeviceAuthStart) {
        devicePollJob?.cancel()
        devicePollJob = viewModelScope.launch {
            var intervalSec = startInfo.interval.coerceAtLeast(2)
            val deadlineMs = System.currentTimeMillis() + startInfo.expiresIn.coerceAtLeast(60) * 1000L
            while (isActive && System.currentTimeMillis() < deadlineMs) {
                delay(intervalSec * 1000L)
                val pollRes = withContext(Dispatchers.IO) {
                    NetShaperRuntime.engine.pollDeviceAuthJson(clientId, startInfo.deviceCode)
                }
                pollRes.onSuccess { raw ->
                    val poll = DeviceAuthPoll.fromJson(raw)
                    when (poll.status) {
                        "authorized" -> {
                            val savedPreview = withContext(Dispatchers.IO) {
                                if (poll.accessToken.isNotBlank() && tokenStore.saveToken(poll.accessToken)) {
                                    tokenStore.maskedTokenPreview()
                                } else null
                            }
                            if (savedPreview != null) {
                                _accountState.update {
                                    it.copy(
                                        hasToken = true,
                                        maskedToken = savedPreview,
                                        deviceAuth = null,
                                        isPollingDeviceAuth = false
                                    )
                                }
                                emitSnackbar("Signed in to GitHub (encrypted in AndroidKeyStore)")
                                refreshCodespaces()
                            } else {
                                _accountState.update { it.copy(deviceAuth = null, isPollingDeviceAuth = false) }
                                emitSnackbar("Authorization succeeded but Keystore rejected token")
                            }
                            return@launch
                        }
                        "slow_down" -> intervalSec = (poll.interval.takeIf { it > 0 } ?: (intervalSec + 5))
                        "expired", "denied", "error" -> {
                            _accountState.update { it.copy(deviceAuth = null, isPollingDeviceAuth = false) }
                            emitSnackbar("Device Flow ${poll.status}: ${poll.error.ifBlank { "please retry" }}")
                            return@launch
                        }
                    }
                }.onFailure { err ->
                    _accountState.update { it.copy(isPollingDeviceAuth = false) }
                    emitSnackbar("Poll error: ${err.message ?: "network failure"}")
                    return@launch
                }
            }
            _accountState.update { it.copy(deviceAuth = null, isPollingDeviceAuth = false) }
        }
    }

    fun cancelDeviceAuth() {
        devicePollJob?.cancel()
        devicePollJob = null
        _accountState.update { it.copy(deviceAuth = null, isPollingDeviceAuth = false) }
    }

    fun updateCodespaceName(name: String): Boolean {
        if (!snapshot.value.canEditCodespace) {
            emitSnackbar("Stop the active tunnel before changing Codespace name")
            return false
        }
        val trimmed = name.trim()
        Formatters.validateCodespaceName(trimmed)?.let { err ->
            emitSnackbar(err)
            return false
        }
        _accountState.update { it.copy(codespaceName = trimmed, quotaReport = null) }
        viewModelScope.launch(Dispatchers.IO) {
            prefsStore.codespaceName = trimmed
        }
        emitSnackbar("Codespace set to $trimmed")
        return true
    }

    fun refreshCodespaces() {
        _accountState.update { it.copy(isLoadingCodespaces = true) }
        viewModelScope.launch {
            val token = withContext(Dispatchers.IO) {
                tokenStore.loadToken().orEmpty().ifBlank {
                    if (!isNativeCore) "gho_mock_token" else ""
                }
            }
            if (token.isBlank()) {
                _accountState.update { it.copy(isLoadingCodespaces = false) }
                emitSnackbar("Sign in or save a GitHub PAT first")
                return@launch
            }
            val res = withContext(Dispatchers.IO) {
                val r = NetShaperRuntime.engine.listCodespacesJson(token)
                NetShaperRuntime.refreshSnapshot()
                NetShaperRuntime.pullNewLogs()
                r
            }
            res.onSuccess { raw ->
                val list = CodespaceItem.listFromJson(raw)
                _accountState.update { it.copy(codespaces = list, isLoadingCodespaces = false) }
                emitSnackbar("Found ${list.size} Codespace(s)")
            }.onFailure { err ->
                _accountState.update { it.copy(isLoadingCodespaces = false) }
                emitSnackbar("Refresh failed: ${err.message ?: "API error"}")
            }
        }
    }

    fun checkQuotaNow() {
        val cs = _accountState.value.codespaceName
        _accountState.update { it.copy(isCheckingQuota = true) }
        viewModelScope.launch {
            val token = withContext(Dispatchers.IO) {
                tokenStore.loadToken().orEmpty().ifBlank {
                    if (!isNativeCore) "gho_mock_token" else ""
                }
            }
            if (token.isBlank()) {
                _accountState.update { it.copy(isCheckingQuota = false) }
                emitSnackbar("Sign in or save a GitHub PAT first")
                return@launch
            }
            val res = withContext(Dispatchers.IO) {
                val r = NetShaperRuntime.engine.checkQuotaJson(token, cs)
                NetShaperRuntime.refreshSnapshot()
                NetShaperRuntime.pullNewLogs()
                r
            }
            res.onSuccess { raw ->
                val report = QuotaReport.fromJson(raw)
                _accountState.update { it.copy(quotaReport = report, isCheckingQuota = false) }
                if (report.guardBlocked.isNotBlank()) {
                    emitSnackbar(report.guardBlocked)
                }
            }.onFailure { err ->
                _accountState.update {
                    it.copy(
                        isCheckingQuota = false,
                        quotaReport = QuotaReport(checked = true, codespaceName = cs, error = err.message ?: "Quota check failed")
                    )
                }
            }
        }
    }

    fun stopCodespaceNow() {
        val cs = _accountState.value.codespaceName
        Formatters.validateCodespaceName(cs)?.let {
            emitSnackbar(it)
            return
        }
        _accountState.update { it.copy(isStoppingCodespace = true) }
        viewModelScope.launch {
            val token = withContext(Dispatchers.IO) {
                tokenStore.loadToken().orEmpty().ifBlank {
                    if (!isNativeCore) "gho_mock_token" else ""
                }
            }
            if (token.isBlank()) {
                _accountState.update { it.copy(isStoppingCodespace = false) }
                emitSnackbar("Sign in or save a GitHub PAT first")
                return@launch
            }
            val res = withContext(Dispatchers.IO) {
                val r = NetShaperRuntime.engine.stopCodespaceNow(token, cs)
                NetShaperRuntime.pullNewLogs()
                r
            }
            res.onSuccess {
                emitSnackbar("Stop request sent for $cs")
            }.onFailure { err ->
                emitSnackbar("Stop failed: ${err.message ?: "API error"}")
            }
            _accountState.update { it.copy(isStoppingCodespace = false) }
        }
    }

    fun setStopOnExit(enabled: Boolean) {
        _accountState.update { it.copy(stopOnExit = enabled) }
        viewModelScope.launch(Dispatchers.IO) {
            prefsStore.stopOnExit = enabled
        }
    }

    fun setEnableIdleParking(enabled: Boolean) {
        _accountState.update { it.copy(enableIdleParking = enabled) }
        viewModelScope.launch(Dispatchers.IO) {
            prefsStore.enableIdleParking = enabled
        }
    }

    private fun emitSnackbar(message: String) {
        _snackbarEvents.tryEmit(message)
    }

    override fun onCleared() {
        devicePollJob?.cancel()
        super.onCleared()
    }
}
