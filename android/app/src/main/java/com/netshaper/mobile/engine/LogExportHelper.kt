package com.netshaper.mobile.engine

import android.content.Context
import android.net.Uri
import android.os.Build
import com.netshaper.mobile.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

data class ArchiveExportResult(
    val fileCount: Int,
    val rawBytesIncluded: Long,
    val zipBytesWritten: Long
)

/**
 * Memory-bounded log export utilities backed by Android Storage Access Framework (SAF).
 * Requires zero legacy storage permissions on API 26-35.
 */
object LogExportHelper {

    private const val STREAM_BUFFER_BYTES = 64 * 1024

    private val FILE_STAMP_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss", Locale.US)
    private val LOCAL_ISO_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ISO_OFFSET_DATE_TIME
    private val UTC_ISO_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ISO_INSTANT

    fun defaultRecentFilename(nowMs: Long = System.currentTimeMillis()): String {
        val stamp = Instant.ofEpochMilli(nowMs)
            .atZone(ZoneId.systemDefault())
            .format(FILE_STAMP_FORMATTER)
        return "netshaper_recent_${stamp}.txt"
    }

    fun defaultArchiveFilename(nowMs: Long = System.currentTimeMillis()): String {
        val stamp = Instant.ofEpochMilli(nowMs)
            .atZone(ZoneId.systemDefault())
            .format(FILE_STAMP_FORMATTER)
        return "netshaper_archive_${stamp}.zip"
    }

    fun buildRecentLogsText(
        logs: List<TerminalLogLine>,
        snapshot: MobileSnapshot,
        exportedAtMs: Long = System.currentTimeMillis()
    ): String {
        val zone = ZoneId.systemDefault()
        val instant = Instant.ofEpochMilli(exportedAtMs)
        val localIso = instant.atZone(zone).format(LOCAL_ISO_FORMATTER)
        val utcIso = UTC_ISO_FORMATTER.format(instant)
        val sb = StringBuilder(logs.size * 128 + 384)
        sb.append("# NetShaper Mobile — Recent Terminal Export\n")
        sb.append("# AppVersion: ").append(BuildConfig.VERSION_NAME).append('\n')
        sb.append("# ExportedLocal: ").append(localIso).append(" (Zone: ").append(zone.id).append(")\n")
        sb.append("# ExportedUTC: ").append(utcIso).append('\n')
        sb.append("# State: ").append(snapshot.state)
            .append(" | Power: ").append(snapshot.powerState)
            .append(" | Net: ").append(snapshot.networkType)
            .append(" | Pool: ").append(snapshot.healthyWorkers)
            .append('/').append(snapshot.poolSize).append('\n')
        sb.append("# Lines: ").append(logs.size).append('\n')
        sb.append("# ------------------------------------------------------------\n")
        for (line in logs) {
            sb.append(line.formattedLocalTime())
                .append(" [").append(line.level).append("] ")
                .append(line.text)
                .append('\n')
        }
        return sb.toString()
    }

    fun writeRecentLogsToUri(
        context: Context,
        uri: Uri,
        logs: List<TerminalLogLine>,
        snapshot: MobileSnapshot,
        exportedAtMs: Long = System.currentTimeMillis()
    ): Long {
        val payload = buildRecentLogsText(logs, snapshot, exportedAtMs)
            .toByteArray(StandardCharsets.UTF_8)
        val rawOut = openDocumentOutputStream(context, uri)
        rawOut.use { out ->
            BufferedOutputStream(out, STREAM_BUFFER_BYTES).use { buf ->
                buf.write(payload)
                buf.flush()
            }
        }
        return payload.size.toLong()
    }

    fun collectArchivableFiles(logDir: File): List<File> {
        if (!logDir.exists() || !logDir.isDirectory) return emptyList()
        val entries = logDir.listFiles() ?: return emptyList()
        return entries.filter { file ->
            if (!file.isFile) return@filter false
            val name = file.name
            if (name.endsWith(".tmp") || name.contains(".rotating.") || name == "codespace_state_cache.json") {
                return@filter false
            }
            name == "netshaper_mobile.jsonl" ||
                name == "netshaper_mobile.jsonl.1" ||
                name == "netshaper_mobile.log" ||
                name == "netshaper_mobile.log.1" ||
                name == "netshaper_mobile_metrics.ndjson" ||
                (name.startsWith("archive_") && name.endsWith(".jsonl.gz")) ||
                name.endsWith(".jsonl") ||
                name.endsWith(".jsonl.gz") ||
                name.endsWith(".ndjson")
        }.sortedWith(compareBy<File> { it.lastModified() }.thenBy { it.name })
    }

    fun writeFullArchiveZip(
        context: Context,
        uri: Uri,
        logDir: File,
        snapshot: MobileSnapshot,
        recentLogs: List<TerminalLogLine>,
        exportedAtMs: Long = System.currentTimeMillis()
    ): ArchiveExportResult {
        val zone = ZoneId.systemDefault()
        val instant = Instant.ofEpochMilli(exportedAtMs)
        val offsetSeconds = zone.rules.getOffset(instant).totalSeconds
        val files = collectArchivableFiles(logDir)
        val manifestFiles = JSONArray()
        val warnings = JSONArray()
        var totalRawBytes = 0L
        var bundledFileCount = 0

        val rawOut = openDocumentOutputStream(context, uri)
        val countingOut = CountingOutputStream(BufferedOutputStream(rawOut, STREAM_BUFFER_BYTES))

        ZipOutputStream(countingOut).use { zos ->
            val buf = ByteArray(STREAM_BUFFER_BYTES)

            // 1. Always embed the live UI ring buffer in local timezone for immediate triage.
            val recentBytes = buildRecentLogsText(recentLogs, snapshot, exportedAtMs)
                .toByteArray(StandardCharsets.UTF_8)
            val recentEntry = ZipEntry("recent_terminal.txt").apply {
                time = exportedAtMs
            }
            zos.putNextEntry(recentEntry)
            zos.write(recentBytes)
            zos.closeEntry()
            totalRawBytes += recentBytes.size.toLong()
            bundledFileCount++
            manifestFiles.put(JSONObject().apply {
                put("archive_path", "recent_terminal.txt")
                put("format", "txt_local_tz")
                put("bytes", recentBytes.size.toLong())
                put("mtime_unix_ms", exportedAtMs)
                put("sha256", sha256Hex(recentBytes))
            })

            // 2. Stream historical active JSONL and gzipped archive segments with bounded memory.
            for (file in files) {
                val archivePath = "logs/${file.name}"
                try {
                    val digest = MessageDigest.getInstance("SHA-256")
                    var fileBytes = 0L
                    val entry = ZipEntry(archivePath).apply {
                        val mtime = file.lastModified()
                        if (mtime > 0L) time = mtime
                    }
                    zos.putNextEntry(entry)
                    BufferedInputStream(FileInputStream(file), STREAM_BUFFER_BYTES).use { input ->
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            if (n > 0) {
                                zos.write(buf, 0, n)
                                digest.update(buf, 0, n)
                                fileBytes += n.toLong()
                            }
                        }
                    }
                    zos.closeEntry()
                    totalRawBytes += fileBytes
                    bundledFileCount++
                    manifestFiles.put(JSONObject().apply {
                        put("archive_path", archivePath)
                        put("format", detectFormat(file.name))
                        put("bytes", fileBytes)
                        put("mtime_unix_ms", file.lastModified())
                        put("sha256", digest.digest().toHexString())
                    })
                } catch (ioe: IOException) {
                    runCatching { zos.closeEntry() }
                    warnings.put("Skipped ${file.name}: ${ioe.message ?: "I/O race during rotation"}")
                }
            }

            // 3. Write self-describing data-mining manifest last with verified byte counts and hashes.
            val manifest = JSONObject().apply {
                put("schema_version", "1.0")
                put("generator", "NetShaper Mobile Stage-3 Telemetry Archiver")
                put("app_version", BuildConfig.VERSION_NAME)
                put("android_sdk", Build.VERSION.SDK_INT)
                put("device_manufacturer", Build.MANUFACTURER)
                put("device_model", Build.MODEL)
                put("exported_at_unix_ms", exportedAtMs)
                put("exported_at_local_iso", instant.atZone(zone).format(LOCAL_ISO_FORMATTER))
                put("exported_at_utc_iso", UTC_ISO_FORMATTER.format(instant))
                put("timezone_id", zone.id)
                put("timezone_offset_seconds", offsetSeconds)
                put("locale", Locale.getDefault().toLanguageTag())
                put("recent_lines_included", recentLogs.size)
                put("historical_segment_count", files.size)
                put("total_raw_bytes", totalRawBytes)
                put("snapshot", JSONObject().apply {
                    put("state", snapshot.state)
                    put("power_state", snapshot.powerState)
                    put("network_type", snapshot.networkType)
                    put("is_metered", snapshot.isMetered)
                    put("codespace_name", snapshot.codespaceName)
                    put("healthy_tunnels", snapshot.healthyWorkers)
                    put("pool_size", snapshot.poolSize)
                    put("active_conns", snapshot.activeConns)
                    put("bytes_up", snapshot.bytesUp)
                    put("bytes_down", snapshot.bytesDown)
                    put("total_routed", snapshot.workers.sumOf { it.totalRouted })
                    put("total_dial_failures", snapshot.workers.sumOf { it.dialFailures })
                    put("semaphore_rejects", snapshot.semaphoreRejects)
                })
                put("data_mining_schema", JSONObject().apply {
                    put("jsonl_version", 1)
                    put("primary_events", JSONArray(listOf("POOL_SUMMARY", "SESSION_ROLLUP", "ERROR_CLUSTER")))
                    put("clustering_fields", JSONArray(listOf("cluster_sig", "repeat_count", "first_unix_ms", "last_unix_ms")))
                    put("timestamp_note", "Every JSONL record carries unix_ms (epoch ms) and ts (UTC ISO-8601); recent_terminal.txt uses local timezone.")
                })
                put("included_files", manifestFiles)
                if (warnings.length() > 0) {
                    put("warnings", warnings)
                }
            }

            val manifestBytes = manifest.toString(2).toByteArray(StandardCharsets.UTF_8)
            zos.putNextEntry(ZipEntry("archive_manifest.json").apply { time = exportedAtMs })
            zos.write(manifestBytes)
            zos.closeEntry()
            zos.finish()
        }

        return ArchiveExportResult(
            fileCount = bundledFileCount + 1,
            rawBytesIncluded = totalRawBytes,
            zipBytesWritten = countingOut.bytesWritten
        )
    }

    private fun openDocumentOutputStream(context: Context, uri: Uri): OutputStream {
        return context.contentResolver.openOutputStream(uri, "w")
            ?: context.contentResolver.openOutputStream(uri)
            ?: throw IOException("Unable to open destination URI for writing")
    }

    private fun detectFormat(name: String): String = when {
        name.endsWith(".jsonl.gz") -> "jsonl_gzip"
        name.endsWith(".jsonl") -> "jsonl"
        name.endsWith(".ndjson") -> "ndjson"
        name.endsWith(".log") || name.endsWith(".log.1") -> "legacy_log"
        else -> "telemetry"
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(bytes).toHexString()
    }

    private fun ByteArray.toHexString(): String {
        val chars = CharArray(size * 2)
        val hex = "0123456789abcdef"
        for (i in indices) {
            val v = this[i].toInt() and 0xFF
            chars[i * 2] = hex[v ushr 4]
            chars[i * 2 + 1] = hex[v and 0x0F]
        }
        return String(chars)
    }

    private class CountingOutputStream(out: OutputStream) : FilterOutputStream(out) {
        var bytesWritten: Long = 0L
            private set

        override fun write(b: Int) {
            out.write(b)
            bytesWritten++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            bytesWritten += len.toLong()
        }
    }
}
