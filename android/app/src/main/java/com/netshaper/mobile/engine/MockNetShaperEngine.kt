package com.netshaper.mobile.engine

import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.math.roundToInt
import kotlin.random.Random

/**
 * Interactive Phase-3 engine simulator matching mobilecore's JSON schemas byte-for-byte.
 * Simulates realistic 2-worker telemetry (PMTU=576 8K framing), live 500-line ring logs,
 * network handover / PAUSED_OFFLINE, adaptive IDLE_DEEP (2->1) parking, OAuth Device Flow,
 * Codespaces listing, and on-demand quota checks with HTTP 403 billing isolation.
 */
class MockNetShaperEngine : NetShaperEngine {

    private val lock = Any()
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "netshaper-mock-engine").apply { isDaemon = true }
    }
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    private var tickTask: ScheduledFuture<*>? = null
    private var callback: NetShaperCallback? = null

    private var state: String = "STOPPED"
    private var supervisorState: String = "SHUTDOWN"
    private var powerState: String = "ACTIVE"
    private var codespaceName: String = "netshaper-edge-prod"
    private var localHost: String = "127.0.0.1"
    private var localPort: Int = 1080
    private var poolSize: Int = 2
    private var enableIdleParking: Boolean = true
    private var stopOnExit: Boolean = true

    private var networkType: String = "cellular"
    private var isMetered: Boolean = true
    private var appInForeground: Boolean = true

    private var tickCount: Long = 0L
    private var startedAtMs: Long = 0L
    private var bytesUp: Long = 0L
    private var bytesDown: Long = 0L
    private var activeConns: Long = 0L
    private var peakConns: Long = 0L
    private var totalRouted1: Long = 0L
    private var totalRouted2: Long = 0L
    private var rtt1: Double = 256.4
    private var rtt2: Double = 274.8
    private var underlayMs: Double = 118.2
    private var guardCalls5m: Int = 0
    private var guardCallsHour: Int = 0
    private var lastError: String = ""

    private var devicePollCount: Int = 0
    private var mockCodespaceState: String = "Available"

    private var nextSeq: Long = 0L
    private val logRing = ArrayDeque<TerminalLogLine>(500)

    init {
        appendLog(
            "INFO",
            "[UI] NetShaper Phase-3 Mock Engine ready | proxy=127.0.0.1:1080 | pool=2 | max_ch=64"
        )
    }

    override fun start(configJson: String, callback: NetShaperCallback): Result<Unit> = runCatching {
        val cfg = JSONObject(configJson)
        val cs = cfg.optString("codespace_name").trim()
        Formatters.validateCodespaceName(cs)?.let { throw IllegalArgumentException(it) }

        synchronized(lock) {
            tickTask?.cancel(false)
            this.callback = callback
            codespaceName = cs
            localHost = cfg.optString("local_host", "127.0.0.1").ifBlank { "127.0.0.1" }
            localPort = cfg.optInt("local_port", 1080).let { if (it <= 0) 1080 else it }
            poolSize = cfg.optInt("pool_size", 2).coerceIn(1, 4)
            enableIdleParking = cfg.optBoolean("enable_idle_parking", true)
            stopOnExit = cfg.optBoolean("stop_on_exit", true)

            state = "STARTING"
            supervisorState = "STARTING_TUNNELS"
            powerState = "ACTIVE"
            tickCount = 0L
            startedAtMs = System.currentTimeMillis()
            bytesUp = 0L
            bytesDown = 0L
            activeConns = 0L
            peakConns = 0L
            totalRouted1 = 0L
            totalRouted2 = 0L
            lastError = ""
            guardCalls5m = (guardCalls5m + 1).coerceAtMost(6)
            guardCallsHour = (guardCallsHour + 1).coerceAtMost(24)
            mockCodespaceState = "Available"
        }

        appendLog(
            "INFO",
            "[Start] codespace=$codespaceName local=$localHost:$localPort pool=$poolSize max_ch=64 (Mock Phase-3)"
        )
        notifyState("STARTING", "booting")

        tickTask = scheduler.scheduleWithFixedDelay({ runSimulationTick() }, 900L, 1000L, TimeUnit.MILLISECONDS)
    }

    override fun stop(): Result<Unit> = runCatching {
        val hadRunning: Boolean
        val cs: String
        val doStopVm: Boolean
        synchronized(lock) {
            tickTask?.cancel(false)
            tickTask = null
            hadRunning = state != "STOPPED"
            cs = codespaceName
            doStopVm = stopOnExit && hadRunning
            state = "STOPPING"
            supervisorState = "SHUTDOWN"
        }
        if (hadRunning) {
            notifyState("STOPPING", "shutdown")
            appendLog("INFO", "[Stop] draining active SOCKS5 streams and closing outer tunnels...")
            if (doStopVm) {
                mockCodespaceState = "Shutdown"
                appendLog("SUCCESS", "[Stop] codespace=$cs stopped via GitHub REST API (mock)")
            }
        }
        synchronized(lock) {
            state = "STOPPED"
            supervisorState = "SHUTDOWN"
            powerState = "ACTIVE"
            activeConns = 0L
            startedAtMs = 0L
        }
        notifyState("STOPPED", "stopped")
    }

    private fun runSimulationTick() {
        var stateChangedTo: Pair<String, String>? = null
        var logEvent: Pair<String, String>? = null

        synchronized(lock) {
            if (state == "STOPPED" || state == "STOPPING") return
            tickCount++

            if (networkType == "none") {
                if (state != "PAUSED_OFFLINE") {
                    state = "PAUSED_OFFLINE"
                    supervisorState = "PAUSED_OFFLINE"
                    activeConns = 0L
                    stateChangedTo = "PAUSED_OFFLINE" to "network_offline"
                }
                return
            }

            when {
                tickCount == 1L -> {
                    supervisorState = "PROBING_E2E"
                    logEvent = "INFO" to "[BootGate] tunnel-1 E2E RTT=248ms jitter=21ms micro_payload=OK wan=20.120.56.11:443 (PMTU=576 8K)"
                }
                tickCount == 2L -> {
                    state = "RUNNING"
                    supervisorState = "HEALTHY"
                    guardCalls5m = (guardCalls5m + 1).coerceAtMost(6)
                    guardCallsHour = (guardCallsHour + 1).coerceAtMost(24)
                    activeConns = 6L
                    peakConns = 6L
                    totalRouted1 = 9L
                    totalRouted2 = 7L
                    stateChangedTo = "RUNNING" to "healthy"
                    logEvent = "SUCCESS" to "[Ready] $localHost:$localPort | pool=$poolSize/$poolSize | route=balanced | underlay=118ms"
                }
                else -> {
                    if (state != "RUNNING") {
                        state = "RUNNING"
                        supervisorState = "HEALTHY"
                        stateChangedTo = "RUNNING" to "healthy"
                    }

                    // Demonstrate realistic Adaptive Idle Scaling (ACTIVE -> IDLE_LIGHT -> IDLE_DEEP -> ACTIVE)
                    if (enableIdleParking && poolSize >= 2) {
                        val cycle = tickCount % 75L
                        when {
                            cycle == 35L -> {
                                powerState = "IDLE_LIGHT"
                                activeConns = 0L
                                logEvent = "INFO" to "[Power] 0 active channels — entering IDLE_LIGHT (underlay 90s, probe 60s)"
                            }
                            cycle == 42L -> {
                                powerState = "IDLE_DEEP"
                                activeConns = 0L
                                logEvent = "INFO" to "[Power] parked tunnel-2 (IDLE_DEEP 2->1) — 0 failovers, instant wake on next request"
                            }
                            cycle == 55L -> {
                                powerState = "ACTIVE"
                                activeConns = 8L
                                logEvent = "SUCCESS" to "[Power] traffic detected — instant wake on tunnel-1 & unparking tunnel-2"
                            }
                        }
                    } else {
                        powerState = "ACTIVE"
                    }

                    underlayMs = (108.0 + Random.nextDouble(-9.0, 14.0)).coerceIn(85.0, 165.0)
                    rtt1 = (248.0 + Random.nextDouble(-18.0, 26.0)).coerceIn(195.0, 340.0)
                    rtt2 = (264.0 + Random.nextDouble(-20.0, 28.0)).coerceIn(205.0, 360.0)

                    if (powerState == "ACTIVE") {
                        val deltaUp = Random.nextLong(6_000L, 42_000L)
                        val deltaDown = Random.nextLong(48_000L, 380_000L)
                        bytesUp += deltaUp
                        bytesDown += deltaDown
                        activeConns = Random.nextLong(5L, 22L)
                        if (activeConns > peakConns) peakConns = activeConns
                        totalRouted1 += Random.nextLong(1L, 4L)
                        totalRouted2 += Random.nextLong(1L, 4L)
                    } else {
                        activeConns = 0L
                    }

                    if (tickCount % 15L == 0L) {
                        val hw = if (powerState == "IDLE_DEEP") 1 else poolSize
                        logEvent = "INFO" to "[Stats] workers=$hw/$poolSize p50=${rtt1.roundToInt()}ms active=$activeConns/64 power=$powerState net=$networkType"
                    }
                }
            }
        }

        logEvent?.let { appendLog(it.first, it.second) }
        stateChangedTo?.let { notifyState(it.first, it.second) }
    }

    override fun getSnapshotJson(): String = synchronized(lock) {
        val isRunning = state == "RUNNING" || state == "DEGRADED"
        val isParked = isRunning && powerState == "IDLE_DEEP" && poolSize >= 2
        val healthyCount = when {
            !isRunning -> 0
            isParked -> 1
            else -> poolSize
        }
        val parkedCount = if (isParked) 1 else 0
        val uptime = if (isRunning && startedAtMs > 0L) {
            ((System.currentTimeMillis() - startedAtMs) / 1000L).coerceAtLeast(0L)
        } else 0L

        val workers = JSONArray()
        for (i in 1..poolSize) {
            val wState = when {
                state == "STOPPED" || state == "STOPPING" || state == "PAUSED_OFFLINE" -> "DEAD"
                state == "STARTING" -> if (i == 1 && tickCount >= 1L) "HEALTHY" else "STARTING"
                i == 2 && isParked -> "PARKED"
                else -> "HEALTHY"
            }
            val wRtt = if (i == 1) rtt1 else rtt2
            val wStreams = when {
                wState != "HEALTHY" -> 0L
                isParked -> activeConns
                i == 1 -> (activeConns + 1L) / 2L
                else -> activeConns / 2L
            }
            val rho = if (underlayMs > 50.0) wRtt / underlayMs else 1.0
            workers.put(JSONObject().apply {
                put("id", "tunnel-$i")
                put("state", wState)
                put("slow_lane_degraded", false)
                put("wan_remote", if (wState == "HEALTHY") "20.120.56.11:443" else "")
                put("pmtu576_active", wState == "HEALTHY")
                put("active_streams", wStreams)
                put("max_streams", 32)
                put("ewma_rtt_ms", (wRtt * 10.0).roundToInt() / 10.0)
                put("ewma_jitter_ms", if (i == 1) 24.3 else 31.8)
                put("relative_rho", (rho * 100.0).roundToInt() / 100.0)
                put("stream_error_rate", 0.0)
                put("total_routed", if (i == 1) totalRouted1 else totalRouted2)
                put("dial_failures", 0)
                put("boot_retries", 0)
                put("restarts", 0)
                put("last_boot_ms", if (i == 1) 9420 else 8890)
            })
        }

        JSONObject().apply {
            put("core_version", coreVersion())
            put("state", state)
            put("supervisor_state", supervisorState)
            put("power_state", powerState)
            put("codespace_name", codespaceName)
            put("local_host", localHost)
            put("local_port", localPort)
            put("local_addr", "$localHost:$localPort")
            put("v2rayng_uri", "socks://$localHost:$localPort#NetShaper")
            put("network_type", networkType)
            put("is_metered", isMetered)
            put("app_in_foreground", appInForeground)
            put("pool_size", poolSize)
            put("healthy_workers", healthyCount)
            put("degraded_workers", 0)
            put("parked_workers", parkedCount)
            put("routing_mode", if (isParked) "single_primary" else "balanced")
            put("primary_tunnel_id", if (isParked) "tunnel-1" else "")
            put("latency_p50_ms", if (isRunning) ((rtt1 * 10.0).roundToInt() / 10.0) else 0.0)
            put("underlay_ms", if (isRunning) ((underlayMs * 10.0).roundToInt() / 10.0) else 0.0)
            put("active_conns", activeConns)
            put("peak_conns", peakConns)
            put("max_active_conns", 64)
            put("queued_conns", 0)
            put("semaphore_rejects", 0)
            put("bytes_up", bytesUp)
            put("bytes_down", bytesDown)
            put("uptime_sec", uptime)
            put("guard_calls_5m", guardCalls5m)
            put("guard_max_5m", 6)
            put("guard_calls_hour", guardCallsHour)
            put("guard_max_hour", 24)
            put("guard_cooldown_ms", 0)
            put("guard_budget_wait_ms", 0)
            put("guard_throttle_wait_ms", 0)
            put("guard_throttle_reason", "")
            put("guard_rate_limits", 0)
            put("workers", workers)
            put("last_error", lastError)
        }.toString()
    }

    override fun getLogsJson(sinceSeq: Long): String = synchronized(lock) {
        val arr = JSONArray()
        for (ln in logRing) {
            if (ln.seq > sinceSeq) {
                arr.put(JSONObject().apply {
                    put("seq", ln.seq)
                    put("ts", ln.ts)
                    put("level", ln.level)
                    put("text", ln.text)
                })
            }
        }
        arr.toString()
    }

    override fun clearLogs() {
        synchronized(lock) { logRing.clear() }
    }

    override fun notifyNetworkChange(networkType: String, isMetered: Boolean) {
        val normalized = networkType.lowercase(Locale.US).ifBlank { "unknown" }
        var stateEvent: Pair<String, String>? = null
        var logText: Pair<String, String>? = null

        synchronized(lock) {
            val prev = this.networkType
            this.networkType = normalized
            this.isMetered = isMetered
            if (state != "STOPPED" && state != "STOPPING") {
                if (normalized == "none") {
                    state = "PAUSED_OFFLINE"
                    supervisorState = "PAUSED_OFFLINE"
                    activeConns = 0L
                    stateEvent = "PAUSED_OFFLINE" to "network_offline"
                    logText = "WARN" to "[Net] Connectivity lost — PAUSED_OFFLINE (0 API calls)"
                } else if (prev == "none") {
                    state = "RUNNING"
                    supervisorState = "HEALTHY"
                    powerState = "ACTIVE"
                    stateEvent = "RUNNING" to "network_restored"
                    logText = "SUCCESS" to "[Net] Connectivity restored ($normalized, metered=$isMetered) — tunnels resumed"
                } else if (prev != normalized) {
                    powerState = "ACTIVE"
                    logText = "INFO" to "[Net] Handover $prev -> $normalized (metered=$isMetered) — underlay baseline reset"
                }
            }
        }
        logText?.let { appendLog(it.first, it.second) }
        stateEvent?.let { notifyState(it.first, it.second) }
    }

    override fun setAppForeground(inForeground: Boolean) {
        synchronized(lock) { appInForeground = inForeground }
    }

    override fun startDeviceAuthJson(clientId: String): Result<String> = runCatching {
        synchronized(lock) { devicePollCount = 0 }
        appendLog("INFO", "[Auth] Started GitHub OAuth Device Flow (mock, clientId=${clientId.ifBlank { "default" }})")
        JSONObject().apply {
            put("device_code", "mock_device_code_netshaper_v7")
            put("user_code", "NS70-8421")
            put("verification_uri", "https://github.com/login/device")
            put("expires_in", 900)
            put("interval", 3)
        }.toString()
    }

    override fun pollDeviceAuthJson(clientId: String, deviceCode: String): Result<String> = runCatching {
        val pollNum = synchronized(lock) {
            devicePollCount++
            devicePollCount
        }
        if (pollNum < 2) {
            JSONObject().apply {
                put("status", "pending")
                put("interval", 3)
            }.toString()
        } else {
            appendLog("SUCCESS", "[Auth] GitHub OAuth Device Flow authorized (token encrypted in AndroidKeyStore)")
            JSONObject().apply {
                put("status", "authorized")
                put("access_token", "gho_MockNetShaperPhase3Token7000123456")
                put("interval", 3)
            }.toString()
        }
    }

    override fun listCodespacesJson(token: String): Result<String> = runCatching {
        if (token.isBlank()) throw IllegalArgumentException("GitHub token is required")
        synchronized(lock) {
            guardCalls5m = (guardCalls5m + 1).coerceAtMost(6)
            guardCallsHour = (guardCallsHour + 1).coerceAtMost(24)
        }
        appendLog("INFO", "[API] Fetched 2 Codespaces via GitHub REST API (mock)")
        val arr = JSONArray()
        arr.put(JSONObject().apply {
            put("name", "netshaper-edge-prod")
            put("display_name", "NetShaper Edge Relay")
            put("state", mockCodespaceState)
            put("owner_login", "netshaper-user")
            put("repository", "netshaper-user/relay-box")
            put("machine", JSONObject().apply {
                put("name", "basicLinux32gb")
                put("display_name", "2 cores, 8 GB RAM, 32 GB storage")
                put("cpus", 2)
                put("memory_in_bytes", 8L * 1024L * 1024L * 1024L)
                put("storage_in_bytes", 32L * 1024L * 1024L * 1024L)
            })
        })
        arr.put(JSONObject().apply {
            put("name", "netshaper-backup-eu")
            put("display_name", "NetShaper Backup EU")
            put("state", "Shutdown")
            put("owner_login", "netshaper-user")
            put("repository", "netshaper-user/relay-backup")
            put("machine", JSONObject().apply {
                put("name", "standardLinux32gb")
                put("display_name", "4 cores, 16 GB RAM, 32 GB storage")
                put("cpus", 4)
                put("memory_in_bytes", 16L * 1024L * 1024L * 1024L)
                put("storage_in_bytes", 32L * 1024L * 1024L * 1024L)
            })
        })
        arr.toString()
    }

    override fun checkQuotaJson(token: String, codespaceName: String): Result<String> = runCatching {
        if (token.isBlank()) throw IllegalArgumentException("GitHub token is required")
        synchronized(lock) {
            guardCalls5m = (guardCalls5m + 1).coerceAtMost(6)
            guardCallsHour = (guardCallsHour + 1).coerceAtMost(24)
        }
        val target = codespaceName.ifBlank { this.codespaceName }
        appendLog("SUCCESS", "[Quota] $target | state=$mockCodespaceState | 2 cores, 8 GB RAM (billing 403 isolated)")
        JSONObject().apply {
            put("checked", true)
            put("codespace_name", target)
            put("codespace_state", mockCodespaceState)
            put("machine_display", "2 cores, 8 GB RAM, 32 GB storage")
            put("cpus", 2)
            put("memory_gb", 8)
            put("storage_gb", 32)
            put("billing_available", false)
            put("core_hours_used", 0.0)
            put("core_hours_included", 0.0)
            put("billing_note", "Billing scope unavailable (HTTP 403 isolated — 0 WAF penalty) — showing machine tier")
            put("guard_blocked", "")
            put("error", "")
        }.toString()
    }

    override fun stopCodespaceNow(token: String, codespaceName: String): Result<Unit> = runCatching {
        if (token.isBlank()) throw IllegalArgumentException("GitHub token is required")
        Formatters.validateCodespaceName(codespaceName)?.let { throw IllegalArgumentException(it) }
        mockCodespaceState = "Shutdown"
        appendLog("SUCCESS", "[API] Stopped Codespace '$codespaceName' immediately (mock)")
    }

    override fun getV2RayNGProfileUri(): String = synchronized(lock) {
        "socks://$localHost:$localPort#NetShaper"
    }

    override fun coreVersion(): String = "v7.0-mobile-core6.4 (mock)"

    private fun appendLog(level: String, text: String) {
        val line: TerminalLogLine
        val cb: NetShaperCallback?
        val fg: Boolean
        synchronized(lock) {
            nextSeq++
            line = TerminalLogLine(
                seq = nextSeq,
                ts = timeFmt.format(Date()),
                level = level,
                text = text
            )
            if (logRing.size >= 500) logRing.removeFirst()
            logRing.addLast(line)
            cb = callback
            fg = appInForeground
        }
        if (fg) {
            runCatching { cb?.onLogLine(line.seq, line.level, line.text) }
        }
    }

    private fun notifyState(newState: String, detail: String) {
        val cb = synchronized(lock) { callback }
        runCatching { cb?.onStateChange(newState, detail) }
    }
}
