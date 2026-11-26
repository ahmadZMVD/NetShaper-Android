package com.netshaper.mobile.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netshaper.mobile.engine.Formatters
import com.netshaper.mobile.engine.MobileSnapshot
import com.netshaper.mobile.engine.WorkerSnapshot
import com.netshaper.mobile.ui.theme.GlassCard
import com.netshaper.mobile.ui.theme.IecPowerGlyph
import com.netshaper.mobile.ui.theme.NetShaperColors
import java.util.Locale
import kotlin.math.roundToInt

@Composable
fun HomeScreen(
    snapshot: MobileSnapshot,
    onPowerClick: () -> Unit,
    onCopyProfile: () -> Unit,
    onCopyHost: () -> Unit,
    onCopyPort: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 1. Hero Glass Card with 96dp circular Power Button
        HeroPowerCard(snapshot = snapshot, onPowerClick = onPowerClick)

        // 2. 3-Column Metric Row: LATENCY | POOL | CHANNELS
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            val latencyText = if (snapshot.latencyP50Ms > 0.0) "${snapshot.latencyP50Ms.roundToInt()} ms" else "--"
            MetricPillCard(
                modifier = Modifier.weight(1f),
                label = "LATENCY",
                value = latencyText,
                valueColor = NetShaperColors.TextPrimary
            )
            MetricPillCard(
                modifier = Modifier.weight(1f),
                label = "POOL",
                value = "${snapshot.healthyWorkers} / ${snapshot.poolSize}",
                valueColor = if (snapshot.healthyWorkers > 0) NetShaperColors.Emerald else NetShaperColors.TextMuted
            )
            MetricPillCard(
                modifier = Modifier.weight(1f),
                label = "CHANNELS",
                value = "${snapshot.activeConns} / ${snapshot.maxActiveConns}",
                valueColor = NetShaperColors.ElectricBlue
            )
        }

        // 3. Transfer & WAF Guard Card
        TransferAndGuardCard(snapshot = snapshot)

        // 4. 2-Worker Live Strip
        WorkerLiveStrip(workers = snapshot.workers)

        // 5. v2rayNG Quick-Connect Card
        V2RayNGQuickConnectCard(
            snapshot = snapshot,
            onCopyProfile = onCopyProfile,
            onCopyHost = onCopyHost,
            onCopyPort = onCopyPort
        )

        Spacer(modifier = Modifier.height(12.dp))
    }
}

@Composable
private fun HeroPowerCard(
    snapshot: MobileSnapshot,
    onPowerClick: () -> Unit
) {
    val ringColor by animateColorAsState(
        targetValue = when (snapshot.state) {
            "RUNNING" -> NetShaperColors.Emerald
            "STARTING", "DEGRADED", "STOPPING", "PAUSED_OFFLINE" -> NetShaperColors.Amber
            else -> NetShaperColors.SlateRing
        },
        animationSpec = tween(350),
        label = "ringColor"
    )
    val fillColor by animateColorAsState(
        targetValue = when (snapshot.state) {
            "RUNNING" -> NetShaperColors.EmeraldFill
            "STARTING", "DEGRADED", "STOPPING", "PAUSED_OFFLINE" -> NetShaperColors.AmberFill
            else -> NetShaperColors.GlassElevated
        },
        animationSpec = tween(350),
        label = "fillColor"
    )
    val glowColor = when (snapshot.state) {
        "RUNNING" -> NetShaperColors.EmeraldGlow
        "STARTING", "DEGRADED", "STOPPING", "PAUSED_OFFLINE" -> NetShaperColors.AmberGlow
        else -> Color.Transparent
    }

    GlassCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Centered 96dp circular Power Button + glowing radial halo
            Box(
                modifier = Modifier.size(124.dp),
                contentAlignment = Alignment.Center
            ) {
                if (glowColor != Color.Transparent) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        drawCircle(
                            brush = Brush.radialGradient(
                                colors = listOf(glowColor, Color.Transparent),
                                radius = size.minDimension / 2f
                            )
                        )
                    }
                }
                Box(
                    modifier = Modifier
                        .size(96.dp)
                        .clip(CircleShape)
                        .background(fillColor)
                        .border(3.dp, ringColor, CircleShape)
                        .clickable(onClick = onPowerClick),
                    contentAlignment = Alignment.Center
                ) {
                    IecPowerGlyph(
                        modifier = Modifier.size(38.dp),
                        color = NetShaperColors.TextPrimary
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            val primaryLine: String
            val primaryColor: Color
            when (snapshot.state) {
                "RUNNING" -> {
                    primaryLine = "SOCKS5 ${snapshot.localAddr} · ${Formatters.formatUptime(snapshot.uptimeSec)}"
                    primaryColor = NetShaperColors.Emerald
                }
                "STARTING" -> {
                    primaryLine = if (snapshot.guardThrottleWaitMs > 0L) {
                        "WAF throttle · retry in ${Formatters.formatCountdownMs(snapshot.guardThrottleWaitMs)}"
                    } else {
                        "Booting (${snapshot.supervisorState})..."
                    }
                    primaryColor = NetShaperColors.Amber
                }
                "DEGRADED" -> {
                    primaryLine = "Degraded (${snapshot.supervisorState}) · ${snapshot.localAddr}"
                    primaryColor = NetShaperColors.Amber
                }
                "PAUSED_OFFLINE" -> {
                    primaryLine = "Paused Offline · Waiting for Wi-Fi / Cellular"
                    primaryColor = NetShaperColors.Amber
                }
                "STOPPING" -> {
                    primaryLine = "Ordered shutdown in progress..."
                    primaryColor = NetShaperColors.Amber
                }
                else -> {
                    if (snapshot.lastError.isNotBlank()) {
                        primaryLine = snapshot.lastError
                        primaryColor = NetShaperColors.Coral
                    } else {
                        primaryLine = "Press to start local SOCKS5 proxy"
                        primaryColor = NetShaperColors.TextSecondary
                    }
                }
            }

            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Text(
                    text = primaryLine,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = primaryColor,
                    textAlign = TextAlign.Center,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )

                Spacer(modifier = Modifier.height(8.dp))

                val powerBadgeText = when (snapshot.powerState) {
                    "IDLE_DEEP" -> "IDLE_DEEP (2→1)"
                    "IDLE_LIGHT" -> "IDLE_LIGHT"
                    else -> "ACTIVE"
                }
                val powerBadgeColor = when (snapshot.powerState) {
                    "IDLE_DEEP" -> NetShaperColors.Amber
                    "IDLE_LIGHT" -> NetShaperColors.ElectricBlue
                    else -> NetShaperColors.Emerald
                }
                val underlayText = if (snapshot.underlayMs > 0.0) "${snapshot.underlayMs.roundToInt()}ms" else "--"

                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SmallMetaChip(text = "Route: ${snapshot.routingMode.ifBlank { "balanced" }}")
                    SmallMetaChip(text = "Underlay $underlayText")
                    SmallMetaChip(text = powerBadgeText, accent = powerBadgeColor)
                }
            }
        }
    }
}

@Composable
private fun SmallMetaChip(text: String, accent: Color = NetShaperColors.TextMuted) {
    Text(
        text = text,
        fontSize = 10.sp,
        fontWeight = FontWeight.Medium,
        color = accent,
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(NetShaperColors.GlassTrack)
            .border(1.dp, accent.copy(alpha = 0.25f), RoundedCornerShape(8.dp))
            .padding(horizontal = 7.dp, vertical = 3.dp)
    )
}

@Composable
private fun MetricPillCard(
    modifier: Modifier = Modifier,
    label: String,
    value: String,
    valueColor: Color
) {
    GlassCard(modifier = modifier, cornerRadius = 14.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = label,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.6.sp,
                color = NetShaperColors.TextMuted
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = valueColor,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun TransferAndGuardCard(snapshot: MobileSnapshot) {
    GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 14.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "↑  ${Formatters.formatBytesShort(snapshot.bytesUp)}",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.TextPrimary
                )
                Text(
                    text = "↓  ${Formatters.formatBytesShort(snapshot.bytesDown)}",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.Emerald
                )
            }

            val guardText = when {
                snapshot.guardCooldownMs > 0L ->
                    "WAF Cooldown: ${Formatters.formatCountdownMs(snapshot.guardCooldownMs)} (${snapshot.guardCalls5m}/${snapshot.guardMax5m} 5m)"
                snapshot.guardBudgetWaitMs > 0L ->
                    "API Budget ${snapshot.guardCalls5m}/${snapshot.guardMax5m} (5m) · unlocks in ${Formatters.formatCountdownMs(snapshot.guardBudgetWaitMs)}"
                else ->
                    "WAF Guard: ${snapshot.guardCalls5m}/${snapshot.guardMax5m} (5m) · ${snapshot.guardCallsHour}/${snapshot.guardMaxHour} (1h)"
            }
            val guardColor = if (snapshot.guardThrottleWaitMs > 0L) NetShaperColors.Amber else NetShaperColors.TextMuted

            Text(
                text = guardText,
                fontSize = 11.sp,
                color = guardColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            // Slim WAF 5-minute budget progress bar
            val fraction = if (snapshot.guardMax5m > 0) {
                (snapshot.guardCalls5m.toFloat() / snapshot.guardMax5m.toFloat()).coerceIn(0f, 1f)
            } else 0f
            val barColor = when {
                fraction >= 1f -> NetShaperColors.Coral
                fraction >= 0.8f -> NetShaperColors.Amber
                else -> NetShaperColors.ElectricBlue
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(5.dp)
                    .clip(RoundedCornerShape(3.dp))
                    .background(NetShaperColors.ProgressTrack)
            ) {
                if (fraction > 0f) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(fraction.coerceAtLeast(0.05f))
                            .height(5.dp)
                            .clip(RoundedCornerShape(3.dp))
                            .background(barColor)
                    )
                }
            }
        }
    }
}

@Composable
private fun WorkerLiveStrip(workers: List<WorkerSnapshot>) {
    val displayWorkers = if (workers.isNotEmpty()) {
        workers
    } else {
        listOf(
            WorkerSnapshot(id = "tunnel-1", state = "DEAD"),
            WorkerSnapshot(id = "tunnel-2", state = "DEAD")
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        displayWorkers.take(2).forEach { w ->
            WorkerBadgeTile(worker = w, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun WorkerBadgeTile(worker: WorkerSnapshot, modifier: Modifier = Modifier) {
    val dotColor = when (worker.state) {
        "HEALTHY" -> NetShaperColors.Emerald
        "PARKED" -> NetShaperColors.Amber
        "STARTING", "DEGRADED", "DRAINING" -> NetShaperColors.Amber
        else -> NetShaperColors.TextMuted
    }

    GlassCard(modifier = modifier, cornerRadius = 14.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(dotColor)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = worker.id,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NetShaperColors.TextPrimary
                    )
                }
                Text(
                    text = "${worker.activeStreams}/${worker.maxStreams}",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = NetShaperColors.TextMuted
                )
            }

            if (worker.state == "PARKED") {
                Text(
                    text = "PARKED (IDLE_DEEP)",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.Amber,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(NetShaperColors.AmberFill)
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                )
            } else {
                val rttLabel = if (worker.state == "HEALTHY" && worker.ewmaRttMs > 0.0) {
                    "${worker.ewmaRttMs.roundToInt()}ms · ρ=${String.format(Locale.US, "%.2f", worker.relativeRho)}"
                } else {
                    worker.state
                }
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    Text(
                        text = rttLabel,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = NetShaperColors.TextSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                if (worker.pmtu576Active) {
                    Text(
                        text = "PMTU=576 · 8K",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NetShaperColors.ElectricBlue,
                        modifier = Modifier
                            .clip(RoundedCornerShape(5.dp))
                            .background(NetShaperColors.ElectricBlueFill)
                            .padding(horizontal = 5.dp, vertical = 2.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun V2RayNGQuickConnectCard(
    snapshot: MobileSnapshot,
    onCopyProfile: () -> Unit,
    onCopyHost: () -> Unit,
    onCopyPort: () -> Unit
) {
    GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 14.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = "v2rayNG QUICK-CONNECT (COEXISTENCE MODE)",
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.6.sp,
                color = NetShaperColors.TextMuted
            )

            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onCopyProfile,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp),
                        shape = RoundedCornerShape(11.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NetShaperColors.ElectricBlue,
                            contentColor = NetShaperColors.TextPrimary
                        ),
                        contentPadding = PaddingValues(horizontal = 12.dp)
                    ) {
                        Text(
                            text = "Copy v2rayNG Profile (${snapshot.v2rayngUri})",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        SecondaryGlassPillButton(
                            text = "Copy Host (${snapshot.localHost})",
                            onClick = onCopyHost,
                            modifier = Modifier.weight(1f)
                        )
                        SecondaryGlassPillButton(
                            text = "Copy Port (${snapshot.localPort})",
                            onClick = onCopyPort,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            Text(
                text = "1. Import clipboard in v2rayNG   2. Add NetShaper to v2rayNG Per-App Bypass",
                fontSize = 11.sp,
                lineHeight = 15.sp,
                color = NetShaperColors.TextMuted
            )
        }
    }
}

@Composable
private fun SecondaryGlassPillButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .height(34.dp)
            .clip(RoundedCornerShape(9.dp))
            .background(NetShaperColors.GlassElevated)
            .border(1.dp, NetShaperColors.GlassHairline, RoundedCornerShape(9.dp))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            color = NetShaperColors.TextSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}
