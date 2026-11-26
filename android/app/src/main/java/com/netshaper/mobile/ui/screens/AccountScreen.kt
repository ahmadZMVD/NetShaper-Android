package com.netshaper.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netshaper.mobile.engine.CodespaceItem
import com.netshaper.mobile.engine.MobileSnapshot
import com.netshaper.mobile.oem.BatterySurvivalHelper
import com.netshaper.mobile.ui.theme.GlassCard
import com.netshaper.mobile.ui.theme.NetShaperColors
import com.netshaper.mobile.viewmodel.AccountUiState
import java.util.Locale

@Composable
fun AccountScreen(
    snapshot: MobileSnapshot,
    accountState: AccountUiState,
    onStartDeviceAuth: (String) -> Unit,
    onCancelDeviceAuth: () -> Unit,
    onCopyDeviceCode: (String) -> Unit,
    onSavePat: (String) -> Unit,
    onSignOut: () -> Unit,
    onRefreshCodespaces: () -> Unit,
    onApplyCodespaceName: (String) -> Boolean,
    onCheckQuota: () -> Unit,
    onStopCodespaceNow: () -> Unit,
    onSetStopOnExit: (Boolean) -> Unit,
    onSetEnableIdleParking: (Boolean) -> Unit,
    onOpenSurvivalWizard: () -> Unit
) {
    val context = LocalContext.current
    var clientIdInput by remember { mutableStateOf(accountState.oauthClientId) }
    var patInput by remember { mutableStateOf("") }
    var codespaceInput by remember { mutableStateOf(accountState.codespaceName) }
    var showStopConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(accountState.codespaceName) {
        codespaceInput = accountState.codespaceName
    }
    LaunchedEffect(accountState.oauthClientId) {
        clientIdInput = accountState.oauthClientId
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 1. GitHub Sign-In Card (Option A: OAuth Device Flow | Option B: Encrypted PAT)
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 14.dp) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "GITHUB AUTHENTICATION (ZERO-GMS)",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 0.6.sp,
                        color = NetShaperColors.TextMuted
                    )
                    if (accountState.hasToken) {
                        Text(
                            text = "Wipe Token",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = NetShaperColors.Coral,
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .clickable(onClick = onSignOut)
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }

                // Keystore Vault Status Pill
                val vaultLabel = if (accountState.hasToken) {
                    "Encrypted in AndroidKeyStore · ${accountState.maskedToken ?: "••••"}"
                } else {
                    "No GitHub token stored — sign in below"
                }
                val vaultColor = if (accountState.hasToken) NetShaperColors.Emerald else NetShaperColors.Amber
                Text(
                    text = vaultLabel,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium,
                    color = vaultColor,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(9.dp))
                        .background(NetShaperColors.GlassTrack)
                        .border(1.dp, vaultColor.copy(alpha = 0.35f), RoundedCornerShape(9.dp))
                        .padding(horizontal = 10.dp, vertical = 8.dp)
                )

                // Option A: OAuth Device Flow
                Text(
                    text = "Option A · OAuth Device Flow",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.TextPrimary
                )

                val activeDevice = accountState.deviceAuth
                if (activeDevice != null) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(NetShaperColors.ElectricBlueFill)
                            .border(1.dp, NetShaperColors.ElectricBlue.copy(alpha = 0.55f), RoundedCornerShape(12.dp))
                            .padding(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "ENTER THIS CODE ON GITHUB",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            letterSpacing = 0.6.sp,
                            color = NetShaperColors.TextSecondary
                        )
                        Text(
                            text = activeDevice.userCode,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 26.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 3.sp,
                            color = NetShaperColors.TextPrimary,
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .clickable { onCopyDeviceCode(activeDevice.userCode) }
                                .padding(horizontal = 10.dp, vertical = 4.dp)
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    onCopyDeviceCode(activeDevice.userCode)
                                    BatterySurvivalHelper.openExternalBrowser(context, activeDevice.verificationUri)
                                },
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(9.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = NetShaperColors.ElectricBlue)
                            ) {
                                Text("Copy & Open Browser", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            }
                            TextButton(onClick = onCancelDeviceAuth) {
                                Text("Cancel", color = NetShaperColors.TextSecondary, fontSize = 12.sp)
                            }
                        }
                        if (accountState.isPollingDeviceAuth) {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(14.dp),
                                        strokeWidth = 2.dp,
                                        color = NetShaperColors.Emerald
                                    )
                                    Text(
                                        text = "Waiting for GitHub authorization...",
                                        fontSize = 11.sp,
                                        color = NetShaperColors.TextSecondary
                                    )
                                }
                                accountState.deviceAuthStatusNote?.let { note ->
                                    Text(
                                        text = note,
                                        fontSize = 10.sp,
                                        color = NetShaperColors.Amber
                                    )
                                }
                            }
                        }
                    }
                } else {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        OutlinedTextField(
                            value = clientIdInput,
                            onValueChange = { clientIdInput = it },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            placeholder = { Text("GitHub OAuth Client ID (178c6fc778ccc68e1d6a)", fontSize = 12.sp) },
                            colors = glassTextFieldColors(),
                            shape = RoundedCornerShape(10.dp)
                        )
                    }
                    Button(
                        onClick = { onStartDeviceAuth(clientIdInput) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(40.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NetShaperColors.GlassElevated,
                            contentColor = NetShaperColors.TextPrimary
                        )
                    ) {
                        Text("Sign in with GitHub (Device Flow)", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }

                // Option B: Direct Token Entry
                Text(
                    text = "Option B · Direct GitHub Token (Prefer Option A if unsure)",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.TextPrimary
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        OutlinedTextField(
                            value = patInput,
                            onValueChange = { patInput = it },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            placeholder = { Text("gho_... or ghp_... (codespace scope)", fontSize = 12.sp) },
                            colors = glassTextFieldColors(),
                            shape = RoundedCornerShape(10.dp)
                        )
                    }
                    Button(
                        onClick = {
                            onSavePat(patInput)
                            patInput = ""
                        },
                        modifier = Modifier.height(52.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = NetShaperColors.ElectricBlue),
                        contentPadding = PaddingValues(horizontal = 14.dp)
                    ) {
                        Text("Save", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        // 2. Codespace Selector Card (Strictly Locked While Active)
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 14.dp) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "CODESPACE TARGET",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 0.6.sp,
                        color = NetShaperColors.TextMuted
                    )
                    if (!snapshot.canEditCodespace) {
                        Text(
                            text = "LOCKED WHILE ACTIVE",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = NetShaperColors.Amber
                        )
                    }
                }

                Button(
                    onClick = onRefreshCodespaces,
                    enabled = !accountState.isLoadingCodespaces,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(38.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NetShaperColors.GlassElevated,
                        contentColor = NetShaperColors.TextPrimary
                    )
                ) {
                    if (accountState.isLoadingCodespaces) {
                        CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp, color = NetShaperColors.ElectricBlue)
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text("Refresh Codespaces", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }

                if (accountState.codespaces.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        accountState.codespaces.forEach { item ->
                            CodespaceOptionRow(
                                item = item,
                                selected = item.name == accountState.codespaceName,
                                enabled = snapshot.canEditCodespace,
                                onSelect = {
                                    if (onApplyCodespaceName(item.name)) {
                                        codespaceInput = item.name
                                    }
                                }
                            )
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        OutlinedTextField(
                            value = codespaceInput,
                            onValueChange = { codespaceInput = it },
                            enabled = snapshot.canEditCodespace,
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            placeholder = { Text("my-codespace-name", fontSize = 12.sp) },
                            colors = glassTextFieldColors(),
                            shape = RoundedCornerShape(10.dp)
                        )
                    }
                    val dirty = codespaceInput.trim() != accountState.codespaceName
                    Button(
                        onClick = { onApplyCodespaceName(codespaceInput) },
                        enabled = snapshot.canEditCodespace,
                        modifier = Modifier.height(52.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (dirty) NetShaperColors.ElectricBlue else NetShaperColors.GlassElevated,
                            contentColor = NetShaperColors.TextPrimary
                        ),
                        contentPadding = PaddingValues(horizontal = 14.dp)
                    ) {
                        Text("Apply", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        // 3. On-Demand Quota & VM Safety Controls Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 14.dp) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "ON-DEMAND QUOTA & CONTROLS",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 0.6.sp,
                    color = NetShaperColors.TextMuted
                )

                Button(
                    onClick = onCheckQuota,
                    enabled = !accountState.isCheckingQuota,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(40.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NetShaperColors.ElectricBlue,
                        contentColor = NetShaperColors.TextPrimary
                    )
                ) {
                    if (accountState.isCheckingQuota) {
                        CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp, color = NetShaperColors.TextPrimary)
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text("Check Quota Now (0 Background Calls)", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }

                val q = accountState.quotaReport
                if (q != null && q.checked) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(NetShaperColors.GlassTrack)
                            .border(1.dp, NetShaperColors.GlassHairline, RoundedCornerShape(10.dp))
                            .padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(3.dp)
                    ) {
                        when {
                            q.guardBlocked.isNotBlank() -> Text(q.guardBlocked, fontSize = 11.sp, color = NetShaperColors.Amber)
                            q.error.isNotBlank() -> Text(q.error, fontSize = 11.sp, color = NetShaperColors.Coral)
                            else -> {
                                Text("VM State: ${q.codespaceState}", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = NetShaperColors.TextPrimary)
                                Text("Tier: ${q.machineDisplay}", fontSize = 11.sp, color = NetShaperColors.TextSecondary)
                                Text("Specs: ${q.cpus} vCPU · ${q.memoryGb} GB RAM · ${q.storageGb} GB Disk", fontSize = 11.sp, color = NetShaperColors.TextMuted)
                                if (q.billingAvailable) {
                                    Text(
                                        "Core-Hours: ${String.format(Locale.US, "%.2f", q.coreHoursUsed)} / ${q.coreHoursIncluded.toInt()} hr",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = NetShaperColors.Emerald
                                    )
                                }
                                if (q.billingNote.isNotBlank()) {
                                    Text(q.billingNote, fontSize = 10.sp, lineHeight = 14.sp, color = NetShaperColors.TextMuted)
                                }
                            }
                        }
                    }
                }

                Button(
                    onClick = { showStopConfirm = true },
                    enabled = !accountState.isStoppingCodespace,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(38.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NetShaperColors.CoralFill,
                        contentColor = NetShaperColors.Coral
                    )
                ) {
                    Text(
                        text = if (accountState.isStoppingCodespace) "Stopping Codespace..." else "Stop Codespace Now",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        // 4. Settings & Background Survival Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 14.dp) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "POWER & BACKGROUND SURVIVAL",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 0.6.sp,
                    color = NetShaperColors.TextMuted
                )

                SettingToggleRow(
                    title = "Stop Codespace on Disconnect",
                    subtitle = "Conserves GitHub core-hours when you stop NetShaper",
                    checked = accountState.stopOnExit,
                    onCheckedChange = onSetStopOnExit
                )

                SettingToggleRow(
                    title = "Adaptive Idle Parking (2→1 after 10m)",
                    subtitle = "Parks tunnel-2 during idle periods; wakes in 0ms on traffic",
                    checked = accountState.enableIdleParking,
                    onCheckedChange = onSetEnableIdleParking
                )

                Button(
                    onClick = onOpenSurvivalWizard,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(42.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NetShaperColors.GlassElevated,
                        contentColor = NetShaperColors.TextPrimary
                    )
                ) {
                    val statusTag = if (accountState.readiness.allCriticalReady) {
                        "✓ Ready"
                    } else {
                        "Setup Needed"
                    }
                    Text(
                        text = "Permissions & Survival Wizard ($statusTag)",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))
    }

    if (showStopConfirm) {
        AlertDialog(
            onDismissRequest = { showStopConfirm = false },
            containerColor = Color(0xFF141A24),
            titleContentColor = NetShaperColors.TextPrimary,
            textContentColor = NetShaperColors.TextSecondary,
            title = { Text("Stop Codespace Now?", fontWeight = FontWeight.Bold) },
            text = {
                Text("This immediately sends a stop command to '${accountState.codespaceName}' on GitHub. Any active SSH sessions will close.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showStopConfirm = false
                        onStopCodespaceNow()
                    }
                ) {
                    Text("Stop VM", color = NetShaperColors.Coral, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showStopConfirm = false }) {
                    Text("Cancel", color = NetShaperColors.TextSecondary)
                }
            }
        )
    }
}

@Composable
private fun CodespaceOptionRow(
    item: CodespaceItem,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit
) {
    val isAvailable = item.state.equals("Available", ignoreCase = true)
    val stateColor = if (isAvailable) NetShaperColors.Emerald else NetShaperColors.TextMuted
    val borderColor = if (selected) NetShaperColors.ElectricBlue else NetShaperColors.GlassHairline

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(if (selected) NetShaperColors.ElectricBlueFill else NetShaperColors.GlassTrack)
            .border(1.dp, borderColor, RoundedCornerShape(10.dp))
            .clickable(enabled = enabled, onClick = onSelect)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.name,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = NetShaperColors.TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            val specText = buildString {
                if (item.repository.isNotBlank()) append(item.repository)
                if (item.machine.cpus > 0) {
                    if (isNotEmpty()) append(" · ")
                    append("${item.machine.cpus}c/${item.machine.memoryGb}GB")
                }
            }
            if (specText.isNotBlank()) {
                Text(
                    text = specText,
                    fontSize = 10.sp,
                    color = NetShaperColors.TextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = item.state,
            fontSize = 10.sp,
            fontWeight = FontWeight.SemiBold,
            color = stateColor,
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(stateColor.copy(alpha = 0.14f))
                .padding(horizontal = 7.dp, vertical = 3.dp)
        )
    }
}

@Composable
private fun SettingToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 10.dp)) {
            Text(text = title, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = NetShaperColors.TextPrimary)
            Text(text = subtitle, fontSize = 11.sp, lineHeight = 14.sp, color = NetShaperColors.TextMuted)
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = NetShaperColors.TextPrimary,
                checkedTrackColor = NetShaperColors.Emerald,
                checkedBorderColor = NetShaperColors.Emerald,
                uncheckedThumbColor = NetShaperColors.TextMuted,
                uncheckedTrackColor = NetShaperColors.GlassTrack,
                uncheckedBorderColor = NetShaperColors.GlassHairline
            )
        )
    }
}

@Composable
private fun glassTextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = NetShaperColors.ElectricBlue,
    unfocusedBorderColor = NetShaperColors.GlassHairline,
    disabledBorderColor = NetShaperColors.GlassHairline.copy(alpha = 0.5f),
    focusedContainerColor = NetShaperColors.GlassInput,
    unfocusedContainerColor = NetShaperColors.GlassInput,
    disabledContainerColor = NetShaperColors.GlassTrack,
    focusedTextColor = NetShaperColors.TextPrimary,
    unfocusedTextColor = NetShaperColors.TextPrimary,
    disabledTextColor = NetShaperColors.TextMuted,
    focusedPlaceholderColor = NetShaperColors.TextMuted,
    unfocusedPlaceholderColor = NetShaperColors.TextMuted,
    cursorColor = NetShaperColors.ElectricBlue
)
