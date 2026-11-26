package com.netshaper.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netshaper.mobile.engine.VpnBypassState
import com.netshaper.mobile.oem.BatterySurvivalHelper
import com.netshaper.mobile.oem.OemVendor
import com.netshaper.mobile.oem.PermissionReadinessState
import com.netshaper.mobile.ui.theme.NetShaperColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BatterySurvivalWizardSheet(
    readiness: PermissionReadinessState,
    onRequestNotifications: () -> Unit,
    onCopyPackageId: (String) -> Unit,
    onRefreshStatus: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = Color(0xFF101621),
        contentColor = NetShaperColors.TextPrimary
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Permissions & Survival Wizard",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = NetShaperColors.TextPrimary
            )
            Text(
                text = "Detected Device: ${readiness.oemVendor.displayName}",
                fontSize = 12.sp,
                color = NetShaperColors.ElectricBlue,
                fontWeight = FontWeight.SemiBold
            )

            // Step 1: Persistent Foreground Service Notifications (API 33+ runtime + permanent-denial fallback)
            WizardStepCard(
                step = "Step 1 · Persistent Status Notification",
                status = if (readiness.notificationsGranted) "GRANTED ✓" else "ACTION NEEDED",
                statusColor = if (readiness.notificationsGranted) NetShaperColors.Emerald else NetShaperColors.Amber,
                instructions = listOf(
                    "Keeps NetShaper visible as an active specialUse service notification with 1-tap Copy URI & Stop controls.",
                    "Zero Restricted-Settings permissions required — works cleanly from Android 8 through Android 15."
                ),
                buttonLabel = if (readiness.notificationsGranted) {
                    "Notification Settings (Enabled ✓)"
                } else if (readiness.canPromptPostNotifications) {
                    "Grant Notification Permission"
                } else {
                    "Open App Notification Settings"
                },
                onClick = {
                    onRequestNotifications()
                    onRefreshStatus()
                }
            )

            // Step 2: Standard Android Doze Battery Optimization Exemption
            WizardStepCard(
                step = "Step 2 · Android Battery Exemption",
                status = if (readiness.batteryOptimizationIgnored) "UNRESTRICTED ✓" else "OPTIMIZED",
                statusColor = if (readiness.batteryOptimizationIgnored) NetShaperColors.Emerald else NetShaperColors.Amber,
                instructions = listOf(
                    "Exempt NetShaper from Android Doze so the local 127.0.0.1:1080 SOCKS5 proxy survives screen-off periods alongside v2rayNG."
                ),
                buttonLabel = if (readiness.batteryOptimizationIgnored) {
                    "Battery Optimization Unrestricted ✓"
                } else {
                    "Disable Battery Optimization"
                },
                onClick = {
                    BatterySurvivalHelper.requestIgnoreBatteryOptimizations(context)
                    onRefreshStatus()
                }
            )

            // Step 3: OEM-Specific PowerGenie / MIUI / OneUI / ColorOS / FuntouchOS Survival Steps
            val (oemTitle, oemSteps, oemBtn) = when (readiness.oemVendor) {
                OemVendor.HUAWEI -> Triple(
                    "Step 3 · Huawei EMUI / HarmonyOS PowerGenie",
                    listOf(
                        "1. Open App Launch -> locate NetShaper",
                        "2. Toggle OFF 'Manage automatically' to Manage Manually",
                        "3. Enable Auto-launch, Secondary launch, and Run in background"
                    ),
                    "Open Huawei App Launch Settings"
                )
                OemVendor.XIAOMI -> Triple(
                    "Step 3 · Xiaomi MIUI / HyperOS AutoStart",
                    listOf(
                        "1. Open Autostart and enable NetShaper",
                        "2. Set Battery Saver to 'No restrictions'",
                        "3. Lock NetShaper in Recents so memory cleaner keeps 127.0.0.1:1080 alive"
                    ),
                    "Open Xiaomi AutoStart Settings"
                )
                OemVendor.SAMSUNG -> Triple(
                    "Step 3 · Samsung OneUI & Auto Blocker Notes",
                    listOf(
                        "1. App Info -> Battery -> select 'Unrestricted'",
                        "2. Device Care -> Battery -> Never sleeping apps -> add NetShaper",
                        "3. Sideloading on OneUI 6.1+: if Auto Blocker prompts once, tap 'Install anyway' (APK uses zero accessibility or hidden permissions)."
                    ),
                    "Open Samsung Battery Settings"
                )
                OemVendor.OPPO -> Triple(
                    "Step 3 · Oppo / Realme / OnePlus ColorOS",
                    listOf(
                        "1. Battery -> App Battery Management -> allow Foreground & Background activity",
                        "2. Enable Auto-launch so background tunnel restarts cleanly"
                    ),
                    "Open ColorOS Background Settings"
                )
                OemVendor.VIVO -> Triple(
                    "Step 3 · Vivo / iQOO FuntouchOS",
                    listOf(
                        "1. Background Power Consumption -> select 'High background power usage'",
                        "2. Enable Autostart in iManager if listed"
                    ),
                    "Open Vivo Background Settings"
                )
                OemVendor.GENERIC -> Triple(
                    "Step 3 · Background Battery Policy",
                    listOf(
                        "1. Open App Info -> App Battery Usage -> select 'Unrestricted'",
                        "2. Ensure 'Pause app activity if unused' is disabled"
                    ),
                    "Open App Info Settings"
                )
            }

            WizardStepCard(
                step = oemTitle,
                status = "RECOMMENDED",
                statusColor = NetShaperColors.ElectricBlue,
                instructions = oemSteps,
                buttonLabel = oemBtn,
                onClick = {
                    BatterySurvivalHelper.openOemBackgroundSettings(context, readiness.oemVendor)
                    onRefreshStatus()
                }
            )

            // Step 4: v2rayNG Per-App Bypass Reminder with live BuildConfig package ID
            val (vpnStatus, vpnColor) = when (readiness.vpnBypassState) {
                VpnBypassState.ROUTING_LOOP_DETECTED -> "LOOP DETECTED" to NetShaperColors.Coral
                VpnBypassState.VPN_BYPASSED_SAFE -> "BYPASSED SAFE ✓" to NetShaperColors.Emerald
                VpnBypassState.NO_VPN -> "CRITICAL" to NetShaperColors.ElectricBlue
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(NetShaperColors.GlassCard)
                    .border(
                        1.dp,
                        if (readiness.vpnBypassState == VpnBypassState.ROUTING_LOOP_DETECTED) {
                            NetShaperColors.Coral
                        } else {
                            NetShaperColors.GlassHairline
                        },
                        RoundedCornerShape(14.dp)
                    )
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Step 4 · v2rayNG Routing-Loop Prevention",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NetShaperColors.TextPrimary,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        text = vpnStatus,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = vpnColor,
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(vpnColor.copy(alpha = 0.16f))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }

                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    Text(
                        text = "Target Package ID: ${readiness.appPackageId}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = NetShaperColors.ElectricBlue
                    )
                }

                listOf(
                    "1. In v2rayNG -> Settings -> Per-app Proxy -> enable 'Bypass mode'.",
                    "2. Check '${readiness.appPackageId}' so NetShaper's outer Dev Tunnels TLS traffic goes directly to Wi-Fi/Cellular.",
                    "3. Import NetShaper's SOCKS5 URI (socks://127.0.0.1:1080#NetShaper)."
                ).forEach { line ->
                    Text(
                        text = line,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        color = NetShaperColors.TextSecondary
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = { onCopyPackageId(readiness.appPackageId) },
                        modifier = Modifier
                            .weight(1f)
                            .height(38.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NetShaperColors.ElectricBlue,
                            contentColor = NetShaperColors.TextPrimary
                        )
                    ) {
                        Text(text = "Copy Package ID", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                    Button(
                        onClick = { BatterySurvivalHelper.openAppDetailsSettings(context) },
                        modifier = Modifier
                            .weight(1f)
                            .height(38.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NetShaperColors.GlassElevated,
                            contentColor = NetShaperColors.TextPrimary
                        )
                    ) {
                        Text(text = "App Info", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                TextButton(onClick = onDismiss) {
                    Text("Done", color = NetShaperColors.TextPrimary, fontWeight = FontWeight.SemiBold)
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun WizardStepCard(
    step: String,
    status: String,
    statusColor: Color,
    instructions: List<String>,
    buttonLabel: String,
    onClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(NetShaperColors.GlassCard)
            .border(1.dp, NetShaperColors.GlassHairline, RoundedCornerShape(14.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = step,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = NetShaperColors.TextPrimary,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = status,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                color = statusColor,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(statusColor.copy(alpha = 0.16f))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }

        instructions.forEach { line ->
            Text(
                text = line,
                fontSize = 12.sp,
                lineHeight = 16.sp,
                color = NetShaperColors.TextSecondary
            )
        }

        Button(
            onClick = onClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(38.dp),
            shape = RoundedCornerShape(10.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = NetShaperColors.GlassElevated,
                contentColor = NetShaperColors.TextPrimary
            )
        ) {
            Text(text = buttonLabel, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}
