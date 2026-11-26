package com.netshaper.mobile.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.netshaper.mobile.BuildConfig
import com.netshaper.mobile.engine.VpnBypassState
import com.netshaper.mobile.oem.BatterySurvivalHelper
import com.netshaper.mobile.ui.theme.GlassCard
import com.netshaper.mobile.ui.theme.NetShaperColors
import com.netshaper.mobile.viewmodel.MainTab
import com.netshaper.mobile.viewmodel.NetShaperViewModel

@Composable
fun MainScreen(viewModel: NetShaperViewModel) {
    val context = LocalContext.current
    val snapshot by viewModel.snapshot.collectAsStateWithLifecycle()
    val logs by viewModel.logs.collectAsStateWithLifecycle()
    val accountState by viewModel.accountState.collectAsStateWithLifecycle()
    val selectedTab by viewModel.selectedTab.collectAsStateWithLifecycle()
    val vpnBypassState by viewModel.vpnBypassState.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    var showSurvivalWizard by remember { mutableStateOf(false) }
    var notifPromptedOnce by remember { mutableStateOf(false) }

    val notifLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { viewModel.refreshReadinessStatus() }
    )

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notifPromptedOnce = true
                notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    LaunchedEffect(Unit) {
        viewModel.snackbarEvents.collect { msg ->
            snackbarHostState.showSnackbar(msg)
        }
    }

    val ambientColor by animateColorAsState(
        targetValue = when {
            vpnBypassState == VpnBypassState.ROUTING_LOOP_DETECTED -> NetShaperColors.Coral.copy(alpha = 0.16f)
            snapshot.state == "RUNNING" -> NetShaperColors.Emerald.copy(alpha = 0.14f)
            snapshot.state in listOf("STARTING", "DEGRADED", "STOPPING", "PAUSED_OFFLINE") ->
                NetShaperColors.Amber.copy(alpha = 0.12f)
            else -> NetShaperColors.ElectricBlue.copy(alpha = 0.08f)
        },
        animationSpec = tween(450),
        label = "ambientAura"
    )

    Scaffold(
        containerColor = NetShaperColors.Canvas,
        snackbarHost = {
            SnackbarHost(hostState = snackbarHostState) { data ->
                Snackbar(
                    snackbarData = data,
                    containerColor = Color(0xEB142A4A),
                    contentColor = NetShaperColors.TextPrimary,
                    shape = RoundedCornerShape(14.dp)
                )
            }
        }
    ) { innerPadding ->
        // Fill screen behind translucent system bars first, then respect Scaffold systemBar insets ONCE.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(NetShaperColors.Canvas)
                .background(
                    Brush.verticalGradient(
                        colors = listOf(ambientColor, Color.Transparent),
                        startY = 0f,
                        endY = 720f
                    )
                )
                .padding(innerPadding)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp)
            ) {
                Spacer(modifier = Modifier.height(10.dp))
                TopStatusHeader(
                    state = snapshot.state,
                    isNativeCore = viewModel.isNativeCore
                )

                when (vpnBypassState) {
                    VpnBypassState.ROUTING_LOOP_DETECTED -> {
                        Spacer(modifier = Modifier.height(10.dp))
                        RoutingLoopCriticalBanner(
                            appPackageId = BuildConfig.APPLICATION_ID,
                            onOpenWizard = {
                                viewModel.refreshReadinessStatus()
                                showSurvivalWizard = true
                            }
                        )
                    }
                    VpnBypassState.VPN_BYPASSED_SAFE -> {
                        if (!accountState.vpnBannerDismissed) {
                            Spacer(modifier = Modifier.height(10.dp))
                            VpnBypassSafeBanner(onDismiss = viewModel::dismissVpnBanner)
                        }
                    }
                    VpnBypassState.NO_VPN -> Unit
                }

                Spacer(modifier = Modifier.height(12.dp))
                SegmentedTabControl(
                    selectedTab = selectedTab,
                    onSelectTab = viewModel::selectTab
                )
                Spacer(modifier = Modifier.height(12.dp))

                Box(modifier = Modifier.weight(1f)) {
                    when (selectedTab) {
                        MainTab.HOME -> HomeScreen(
                            snapshot = snapshot,
                            onPowerClick = viewModel::toggleTunnel,
                            onCopyProfile = viewModel::copyV2RayNGProfile,
                            onCopyHost = viewModel::copyHost,
                            onCopyPort = viewModel::copyPort
                        )

                        MainTab.TERMINAL -> TerminalScreen(
                            logs = logs,
                            onClear = viewModel::clearLogs,
                            onCopyAll = viewModel::copyAllLogs,
                            onCopyLine = { line ->
                                viewModel.copyText(
                                    label = "NetShaper Log Line",
                                    text = "${line.ts} [${line.level}] ${line.text}",
                                    toast = "Copied log line"
                                )
                            }
                        )

                        MainTab.ACCOUNT -> AccountScreen(
                            snapshot = snapshot,
                            accountState = accountState,
                            onStartDeviceAuth = viewModel::startDeviceAuth,
                            onCancelDeviceAuth = viewModel::cancelDeviceAuth,
                            onCopyDeviceCode = { code ->
                                viewModel.copyText("GitHub Device Code", code, "Copied code $code")
                            },
                            onSavePat = viewModel::savePatToken,
                            onSignOut = viewModel::signOutAndWipeToken,
                            onRefreshCodespaces = viewModel::refreshCodespaces,
                            onApplyCodespaceName = viewModel::updateCodespaceName,
                            onCheckQuota = viewModel::checkQuotaNow,
                            onStopCodespaceNow = viewModel::stopCodespaceNow,
                            onSetStopOnExit = viewModel::setStopOnExit,
                            onSetEnableIdleParking = viewModel::setEnableIdleParking,
                            onOpenSurvivalWizard = {
                                viewModel.refreshReadinessStatus()
                                showSurvivalWizard = true
                            }
                        )
                    }
                }
            }
        }
    }

    if (showSurvivalWizard) {
        BatterySurvivalWizardSheet(
            readiness = accountState.readiness,
            onRequestNotifications = {
                val activity = context as? android.app.Activity
                val canShowSystemDialog = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
                    (!notifPromptedOnce || (activity != null && ActivityCompat.shouldShowRequestPermissionRationale(activity, Manifest.permission.POST_NOTIFICATIONS)))
                if (canShowSystemDialog) {
                    notifPromptedOnce = true
                    notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    BatterySurvivalHelper.openNotificationSettings(context)
                }
            },
            onCopyPackageId = { pkg ->
                viewModel.copyText("NetShaper Package ID", pkg, "Copied package ID: $pkg")
            },
            onRefreshStatus = viewModel::refreshReadinessStatus,
            onDismiss = { showSurvivalWizard = false }
        )
    }
}

@Composable
private fun TopStatusHeader(state: String, isNativeCore: Boolean) {
    val (label, accent, fill) = when (state) {
        "RUNNING" -> Triple("CONNECTED", NetShaperColors.Emerald, NetShaperColors.EmeraldFill)
        "STARTING" -> Triple("STARTING", NetShaperColors.Amber, NetShaperColors.AmberFill)
        "DEGRADED" -> Triple("DEGRADED", NetShaperColors.Amber, NetShaperColors.AmberFill)
        "STOPPING" -> Triple("STOPPING", NetShaperColors.Amber, NetShaperColors.AmberFill)
        "PAUSED_OFFLINE" -> Triple("PAUSED_OFFLINE", NetShaperColors.Amber, NetShaperColors.AmberFill)
        else -> Triple("DISCONNECTED", NetShaperColors.TextMuted, NetShaperColors.GlassElevated)
    }

    val pulse = rememberInfiniteTransition(label = "statusDotPulse")
    val dotAlpha by pulse.animateFloat(
        initialValue = 1f,
        targetValue = if (state == "STARTING" || state == "RUNNING") 0.4f else 1f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Reverse),
        label = "dotAlpha"
    )

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "NetShaper",
                fontSize = 21.sp,
                fontWeight = FontWeight.Bold,
                color = NetShaperColors.TextPrimary
            )
            Text(
                text = "v7.0",
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                color = NetShaperColors.TextMuted
            )
            val coreColor = if (isNativeCore) NetShaperColors.Emerald else NetShaperColors.Amber
            Text(
                text = if (isNativeCore) "CORE" else "MOCK",
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.6.sp,
                color = coreColor,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(coreColor.copy(alpha = 0.16f))
                    .border(1.dp, coreColor.copy(alpha = 0.45f), RoundedCornerShape(6.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }

        Row(
            modifier = Modifier
                .clip(RoundedCornerShape(14.dp))
                .background(fill)
                .border(1.dp, accent.copy(alpha = 0.55f), RoundedCornerShape(14.dp))
                .padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .alpha(dotAlpha)
                    .clip(CircleShape)
                    .background(accent)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = label,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.5.sp,
                color = accent
            )
        }
    }
}

@Composable
private fun RoutingLoopCriticalBanner(
    appPackageId: String,
    onOpenWizard: () -> Unit
) {
    GlassCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 12.dp,
        containerColor = NetShaperColors.CoralFill,
        borderColor = NetShaperColors.Coral
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "ROUTING LOOP DETECTED — v2rayNG is capturing NetShaper's sockets. Add $appPackageId to v2rayNG Per-App Bypass!",
                fontSize = 11.sp,
                lineHeight = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = NetShaperColors.TextPrimary,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Wizard",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = NetShaperColors.Canvas,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(NetShaperColors.Coral)
                    .clickable(onClick = onOpenWizard)
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            )
        }
    }
}

@Composable
private fun VpnBypassSafeBanner(onDismiss: () -> Unit) {
    GlassCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 12.dp,
        containerColor = NetShaperColors.EmeraldFill,
        borderColor = NetShaperColors.Emerald.copy(alpha = 0.45f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "v2rayNG active · NetShaper bypassed cleanly (${BuildConfig.APPLICATION_ID})",
                fontSize = 11.sp,
                lineHeight = 15.sp,
                color = NetShaperColors.TextPrimary,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Dismiss",
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color = NetShaperColors.Emerald,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .clickable(onClick = onDismiss)
                    .padding(horizontal = 6.dp, vertical = 3.dp)
            )
        }
    }
}

@Composable
private fun SegmentedTabControl(
    selectedTab: MainTab,
    onSelectTab: (MainTab) -> Unit
) {
    GlassCard(
        modifier = Modifier
            .fillMaxWidth()
            .height(40.dp),
        cornerRadius = 12.dp,
        containerColor = NetShaperColors.GlassTrack
    ) {
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(3.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            val items = listOf(
                MainTab.HOME to "Home",
                MainTab.TERMINAL to "Terminal",
                MainTab.ACCOUNT to "Account"
            )
            items.forEach { (tab, title) ->
                val active = tab == selectedTab
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxSize()
                        .clip(RoundedCornerShape(9.dp))
                        .background(if (active) NetShaperColors.GlassElevated else Color.Transparent)
                        .then(
                            if (active) {
                                Modifier.border(1.dp, NetShaperColors.GlassHairline, RoundedCornerShape(9.dp))
                            } else Modifier
                        )
                        .clickable { onSelectTab(tab) },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = title,
                        fontSize = 13.sp,
                        fontWeight = if (active) FontWeight.SemiBold else FontWeight.Medium,
                        color = if (active) NetShaperColors.TextPrimary else NetShaperColors.TextMuted
                    )
                }
            }
        }
    }
}
