package com.netshaper.mobile.engine

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

enum class VpnBypassState {
    NO_VPN,
    VPN_BYPASSED_SAFE,
    ROUTING_LOOP_DETECTED
}

private fun JSONObject.safeDouble(key: String, fallback: Double = 0.0): Double {
    val v = optDouble(key, fallback)
    return if (v.isNaN() || v.isInfinite()) fallback else v
}

data class MobileStartConfig(
    val githubToken: String,
    val codespaceName: String,
    val localHost: String = "127.0.0.1",
    val localPort: Int = 1080,
    val dataDir: String,
    val poolSize: Int = 2,
    val stopOnExit: Boolean = true,
    val enableIdleParking: Boolean = true,
    val enableMetricsLog: Boolean = false
) {
    fun toJson(): String = JSONObject().apply {
        put("github_token", githubToken)
        put("codespace_name", codespaceName)
        put("local_host", localHost)
        put("local_port", localPort)
        put("data_dir", dataDir)
        put("pool_size", poolSize)
        put("stop_on_exit", stopOnExit)
        put("enable_idle_parking", enableIdleParking)
        put("enable_metrics_log", enableMetricsLog)
    }.toString()
}

data class WorkerSnapshot(
    val id: String = "",
    val state: String = "DEAD",
    val slowLaneDegraded: Boolean = false,
    val wanRemote: String = "",
    val pmtu576Active: Boolean = false,
    val activeStreams: Long = 0L,
    val maxStreams: Int = 32,
    val ewmaRttMs: Double = 0.0,
    val ewmaJitterMs: Double = 0.0,
    val relativeRho: Double = 0.0,
    val streamErrorRate: Double = 0.0,
    val totalRouted: Long = 0L,
    val dialFailures: Long = 0L,
    val bootRetries: Int = 0,
    val restarts: Long = 0L,
    val lastBootMs: Long = 0L
)

data class MobileSnapshot(
    val coreVersion: String = "v7.0-mobile-core6.4",
    val state: String = "STOPPED",
    val supervisorState: String = "SHUTDOWN",
    val powerState: String = "ACTIVE",
    val codespaceName: String = "",
    val localHost: String = "127.0.0.1",
    val localPort: Int = 1080,
    val localAddr: String = "127.0.0.1:1080",
    val v2rayngUri: String = "socks://127.0.0.1:1080#NetShaper",
    val networkType: String = "unknown",
    val isMetered: Boolean = false,
    val appInForeground: Boolean = true,
    val poolSize: Int = 2,
    val healthyWorkers: Int = 0,
    val degradedWorkers: Int = 0,
    val parkedWorkers: Int = 0,
    val routingMode: String = "balanced",
    val primaryTunnelId: String = "",
    val latencyP50Ms: Double = 0.0,
    val underlayMs: Double = 0.0,
    val activeConns: Long = 0L,
    val peakConns: Long = 0L,
    val maxActiveConns: Int = 64,
    val queuedConns: Long = 0L,
    val semaphoreRejects: Long = 0L,
    val bytesUp: Long = 0L,
    val bytesDown: Long = 0L,
    val uptimeSec: Long = 0L,
    val guardCalls5m: Int = 0,
    val guardMax5m: Int = 6,
    val guardCallsHour: Int = 0,
    val guardMaxHour: Int = 24,
    val guardCooldownMs: Long = 0L,
    val guardBudgetWaitMs: Long = 0L,
    val guardThrottleWaitMs: Long = 0L,
    val guardThrottleReason: String = "",
    val guardRateLimits: Long = 0L,
    val workers: List<WorkerSnapshot> = emptyList(),
    val lastError: String = ""
) {
    val isActiveOrTransitioning: Boolean
        get() = state != "STOPPED"

    val canEditCodespace: Boolean
        get() = state == "STOPPED"

    companion object {
        fun fromJson(raw: String): MobileSnapshot = runCatching {
            val o = JSONObject(raw)
            val workersArr = o.optJSONArray("workers")
            val workers = buildList {
                if (workersArr != null) {
                    for (i in 0 until workersArr.length()) {
                        val w = workersArr.optJSONObject(i) ?: continue
                        add(
                            WorkerSnapshot(
                                id = w.optString("id"),
                                state = w.optString("state", "DEAD"),
                                slowLaneDegraded = w.optBoolean("slow_lane_degraded", false),
                                wanRemote = w.optString("wan_remote"),
                                pmtu576Active = w.optBoolean("pmtu576_active", false),
                                activeStreams = w.optLong("active_streams", 0L),
                                maxStreams = w.optInt("max_streams", 32),
                                ewmaRttMs = w.safeDouble("ewma_rtt_ms", 0.0),
                                ewmaJitterMs = w.safeDouble("ewma_jitter_ms", 0.0),
                                relativeRho = w.safeDouble("relative_rho", 0.0),
                                streamErrorRate = w.safeDouble("stream_error_rate", 0.0),
                                totalRouted = w.optLong("total_routed", 0L),
                                dialFailures = w.optLong("dial_failures", 0L),
                                bootRetries = w.optInt("boot_retries", 0),
                                restarts = w.optLong("restarts", 0L),
                                lastBootMs = w.optLong("last_boot_ms", 0L)
                            )
                        )
                    }
                }
            }
            val host = o.optString("local_host", "127.0.0.1").ifBlank { "127.0.0.1" }
            val port = o.optInt("local_port", 1080).let { if (it <= 0) 1080 else it }
            MobileSnapshot(
                coreVersion = o.optString("core_version", "v7.0-mobile-core6.4"),
                state = o.optString("state", "STOPPED"),
                supervisorState = o.optString("supervisor_state", "SHUTDOWN"),
                powerState = o.optString("power_state", "ACTIVE"),
                codespaceName = o.optString("codespace_name"),
                localHost = host,
                localPort = port,
                localAddr = o.optString("local_addr", "$host:$port").ifBlank { "$host:$port" },
                v2rayngUri = o.optString("v2rayng_uri", "socks://$host:$port#NetShaper")
                    .ifBlank { "socks://$host:$port#NetShaper" },
                networkType = o.optString("network_type", "unknown"),
                isMetered = o.optBoolean("is_metered", false),
                appInForeground = o.optBoolean("app_in_foreground", true),
                poolSize = o.optInt("pool_size", 2),
                healthyWorkers = o.optInt("healthy_workers", 0),
                degradedWorkers = o.optInt("degraded_workers", 0),
                parkedWorkers = o.optInt("parked_workers", 0),
                routingMode = o.optString("routing_mode", "balanced"),
                primaryTunnelId = o.optString("primary_tunnel_id"),
                latencyP50Ms = o.safeDouble("latency_p50_ms", 0.0),
                underlayMs = o.safeDouble("underlay_ms", 0.0),
                activeConns = o.optLong("active_conns", 0L),
                peakConns = o.optLong("peak_conns", 0L),
                maxActiveConns = o.optInt("max_active_conns", 64),
                queuedConns = o.optLong("queued_conns", 0L),
                semaphoreRejects = o.optLong("semaphore_rejects", 0L),
                bytesUp = o.optLong("bytes_up", 0L),
                bytesDown = o.optLong("bytes_down", 0L),
                uptimeSec = o.optLong("uptime_sec", 0L),
                guardCalls5m = o.optInt("guard_calls_5m", 0),
                guardMax5m = o.optInt("guard_max_5m", 6),
                guardCallsHour = o.optInt("guard_calls_hour", 0),
                guardMaxHour = o.optInt("guard_max_hour", 24),
                guardCooldownMs = o.optLong("guard_cooldown_ms", 0L),
                guardBudgetWaitMs = o.optLong("guard_budget_wait_ms", 0L),
                guardThrottleWaitMs = o.optLong("guard_throttle_wait_ms", 0L),
                guardThrottleReason = o.optString("guard_throttle_reason"),
                guardRateLimits = o.optLong("guard_rate_limits", 0L),
                workers = workers,
                lastError = o.optString("last_error")
            )
        }.getOrElse { MobileSnapshot() }
    }
}

data class TerminalLogLine(
    val seq: Long,
    val unixMs: Long = 0L,
    val ts: String,
    val level: String,
    val text: String
) {
    fun formattedLocalTime(): String {
        if (unixMs > 0L) {
            return Instant.ofEpochMilli(unixMs)
                .atZone(ZoneId.systemDefault())
                .format(LOCAL_TIME_FORMATTER)
        }
        return ts.ifBlank { "--:--:--" }
    }

    companion object {
        private val LOCAL_TIME_FORMATTER: DateTimeFormatter =
            DateTimeFormatter.ofPattern("HH:mm:ss", Locale.US)

        fun formatEpochLocalTime(unixMs: Long): String =
            Instant.ofEpochMilli(unixMs)
                .atZone(ZoneId.systemDefault())
                .format(LOCAL_TIME_FORMATTER)

        fun listFromJson(raw: String): List<TerminalLogLine> = runCatching {
            val arr = JSONArray(raw)
            buildList(arr.length()) {
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val unixMs = o.optLong("unix_ms", 0L)
                    add(
                        TerminalLogLine(
                            seq = o.optLong("seq", 0L),
                            unixMs = unixMs,
                            ts = o.optString("ts", ""),
                            level = o.optString("level", "INFO"),
                            text = o.optString("text", "")
                        )
                    )
                }
            }
        }.getOrElse { emptyList() }
    }
}

data class DeviceAuthStart(
    val deviceCode: String,
    val userCode: String,
    val verificationUri: String,
    val expiresIn: Int,
    val interval: Int
) {
    companion object {
        fun fromJson(raw: String): DeviceAuthStart = runCatching {
            val o = JSONObject(raw)
            DeviceAuthStart(
                deviceCode = o.optString("device_code"),
                userCode = o.optString("user_code"),
                verificationUri = o.optString("verification_uri", "https://github.com/login/device"),
                expiresIn = o.optInt("expires_in", 900),
                interval = o.optInt("interval", 5).coerceAtLeast(1)
            )
        }.getOrElse {
            DeviceAuthStart(
                deviceCode = "",
                userCode = "",
                verificationUri = "https://github.com/login/device",
                expiresIn = 0,
                interval = 5
            )
        }
    }
}

data class DeviceAuthPoll(
    val status: String,
    val accessToken: String = "",
    val error: String = "",
    val interval: Int = 5
) {
    companion object {
        fun fromJson(raw: String): DeviceAuthPoll = runCatching {
            val o = JSONObject(raw)
            DeviceAuthPoll(
                status = o.optString("status", "error"),
                accessToken = o.optString("access_token"),
                error = o.optString("error"),
                interval = o.optInt("interval", 5)
            )
        }.getOrElse {
            DeviceAuthPoll(status = "error", error = "Malformed OAuth poll response")
        }
    }
}

data class CodespaceMachineInfo(
    val name: String = "",
    val displayName: String = "",
    val cpus: Int = 0,
    val memoryInBytes: Long = 0L,
    val storageInBytes: Long = 0L
) {
    val memoryGb: Int get() = (memoryInBytes / (1024L * 1024L * 1024L)).toInt()
    val storageGb: Int get() = (storageInBytes / (1024L * 1024L * 1024L)).toInt()
}

data class CodespaceItem(
    val name: String,
    val displayName: String,
    val state: String,
    val ownerLogin: String,
    val repository: String,
    val machine: CodespaceMachineInfo
) {
    companion object {
        fun listFromJson(raw: String): List<CodespaceItem> = runCatching {
            val arr = JSONArray(raw)
            buildList(arr.length()) {
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val m = o.optJSONObject("machine")
                    add(
                        CodespaceItem(
                            name = o.optString("name"),
                            displayName = o.optString("display_name"),
                            state = o.optString("state", "Unknown"),
                            ownerLogin = o.optString("owner_login"),
                            repository = o.optString("repository"),
                            machine = CodespaceMachineInfo(
                                name = m?.optString("name").orEmpty(),
                                displayName = m?.optString("display_name").orEmpty(),
                                cpus = m?.optInt("cpus", 0) ?: 0,
                                memoryInBytes = m?.optLong("memory_in_bytes", 0L) ?: 0L,
                                storageInBytes = m?.optLong("storage_in_bytes", 0L) ?: 0L
                            )
                        )
                    )
                }
            }
        }.getOrElse { emptyList() }
    }
}

data class QuotaReport(
    val checked: Boolean = false,
    val codespaceName: String = "",
    val codespaceState: String = "",
    val machineDisplay: String = "",
    val cpus: Int = 0,
    val memoryGb: Int = 0,
    val storageGb: Int = 0,
    val billingAvailable: Boolean = false,
    val coreHoursUsed: Double = 0.0,
    val coreHoursIncluded: Double = 0.0,
    val billingNote: String = "",
    val guardBlocked: String = "",
    val error: String = ""
) {
    companion object {
        fun fromJson(raw: String): QuotaReport = runCatching {
            val o = JSONObject(raw)
            QuotaReport(
                checked = o.optBoolean("checked", true),
                codespaceName = o.optString("codespace_name"),
                codespaceState = o.optString("codespace_state"),
                machineDisplay = o.optString("machine_display"),
                cpus = o.optInt("cpus", 0),
                memoryGb = o.optInt("memory_gb", 0),
                storageGb = o.optInt("storage_gb", 0),
                billingAvailable = o.optBoolean("billing_available", false),
                coreHoursUsed = o.safeDouble("core_hours_used", 0.0),
                coreHoursIncluded = o.safeDouble("core_hours_included", 0.0),
                billingNote = o.optString("billing_note"),
                guardBlocked = o.optString("guard_blocked"),
                error = o.optString("error")
            )
        }.getOrElse {
            QuotaReport(checked = true, error = "Malformed quota response")
        }
    }
}

object Formatters {
    private val codespaceNameRegex = Regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$")

    fun validateCodespaceName(name: String): String? {
        if (name.isBlank()) return "Codespace name cannot be empty"
        if (name != name.trim()) return "Codespace name must not contain leading/trailing spaces"
        if (name.startsWith("-")) return "Codespace name must not start with '-'"
        if (!codespaceNameRegex.matches(name)) {
            return "Must be 2..128 alphanumeric, '.', '_', or '-' characters"
        }
        return null
    }

    fun formatBytesShort(bytes: Long): String {
        val b = bytes.coerceAtLeast(0L).toDouble()
        val kb = 1024.0
        val mb = kb * 1024.0
        val gb = mb * 1024.0
        return when {
            b >= gb -> String.format(Locale.US, "%.2f GB", b / gb)
            b >= mb -> String.format(Locale.US, "%.1f MB", b / mb)
            b >= kb -> String.format(Locale.US, "%.0f KB", b / kb)
            else -> "${bytes.coerceAtLeast(0L)} B"
        }
    }

    fun formatUptime(sec: Long): String {
        if (sec <= 0L) return "00s"
        val h = sec / 3600L
        val m = (sec % 3600L) / 60L
        val s = sec % 60L
        return when {
            h > 0L -> String.format(Locale.US, "%dh %02dm", h, m)
            m > 0L -> String.format(Locale.US, "%02dm %02ds", m, s)
            else -> String.format(Locale.US, "%02ds", s)
        }
    }

    fun formatCountdownMs(ms: Long): String {
        if (ms <= 0L) return "0s"
        return formatUptime((ms + 999L) / 1000L)
    }
}
