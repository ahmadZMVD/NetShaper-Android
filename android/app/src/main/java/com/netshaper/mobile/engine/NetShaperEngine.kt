package com.netshaper.mobile.engine

interface NetShaperCallback {
    fun onStateChange(state: String, detail: String)
    fun onLogLine(seq: Long, level: String, text: String)
    fun onError(code: String, message: String)
}

interface NetShaperEngine {
    fun start(configJson: String, callback: NetShaperCallback): Result<Unit>
    fun stop(): Result<Unit>
    fun getSnapshotJson(): String
    fun getLogsJson(sinceSeq: Long): String
    fun clearLogs()
    fun notifyNetworkChange(networkType: String, isMetered: Boolean)
    fun setAppForeground(inForeground: Boolean)
    fun startDeviceAuthJson(clientId: String): Result<String>
    fun pollDeviceAuthJson(clientId: String, deviceCode: String): Result<String>
    fun listCodespacesJson(token: String): Result<String>
    fun checkQuotaJson(token: String, codespaceName: String): Result<String>
    fun stopCodespaceNow(token: String, codespaceName: String): Result<Unit>
    fun getV2RayNGProfileUri(): String
    fun coreVersion(): String
}
