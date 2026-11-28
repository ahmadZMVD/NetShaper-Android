package com.netshaper.mobile.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.DragInteraction
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netshaper.mobile.engine.LogExportHelper
import com.netshaper.mobile.engine.TerminalLogLine
import com.netshaper.mobile.service.NetShaperRuntime
import com.netshaper.mobile.ui.theme.DownArrowGlyph
import com.netshaper.mobile.ui.theme.GlassCard
import com.netshaper.mobile.ui.theme.NetShaperColors
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.Locale
import kotlin.math.abs

@Composable
fun TerminalScreen(
    logs: List<TerminalLogLine>,
    onClear: () -> Unit,
    onCopyAll: () -> Unit,
    onCopyLine: (TerminalLogLine) -> Unit,
    onExportRecentLogs: (Uri) -> Unit,
    onExportFullArchive: (Uri) -> Unit
) {
    val listState = rememberLazyListState()
    val hScroll = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()

    var highlightedSeq by remember { mutableLongStateOf(-1L) }
    var downloadMenuExpanded by remember { mutableStateOf(false) }
    var autoFollow by remember { mutableStateOf(true) }
    var programmaticScroll by remember { mutableStateOf(false) }

    val recentLogLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        if (uri != null) {
            onExportRecentLogs(uri)
        }
    }

    val fullArchiveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        if (uri != null) {
            onExportFullArchive(uri)
        }
    }

    val isAtBottom by remember {
        derivedStateOf {
            val info = listState.layoutInfo
            val total = info.totalItemsCount
            if (total == 0) {
                true
            } else {
                val lastVisible = info.visibleItemsInfo.lastOrNull()
                lastVisible != null &&
                    lastVisible.index >= total - 1 &&
                    (lastVisible.offset + lastVisible.size) <= info.viewportEndOffset + 32
            }
        }
    }

    // Open immediately at the latest log entry when entering the Terminal tab.
    LaunchedEffect(Unit) {
        if (logs.isNotEmpty()) {
            programmaticScroll = true
            try {
                listState.scrollToItem(logs.lastIndex)
            } finally {
                programmaticScroll = false
            }
        }
    }

    // Genuine user touch drags cancel programmatic scroll so upward inspection pauses auto-follow immediately.
    LaunchedEffect(listState) {
        listState.interactionSource.interactions.collect { interaction ->
            if (interaction is DragInteraction.Start) {
                programmaticScroll = false
            }
        }
    }

    LaunchedEffect(listState) {
        var sawUserScroll = false
        snapshotFlow { Triple(listState.isScrollInProgress, isAtBottom, programmaticScroll) }
            .collect { (scrolling, atBottom, prog) ->
                if (scrolling && !prog) {
                    sawUserScroll = true
                    if (!atBottom) {
                        autoFollow = false
                    }
                } else if (!scrolling && sawUserScroll && !prog) {
                    sawUserScroll = false
                    autoFollow = atBottom
                }
            }
    }

    // Key on last seq (NOT logs.size, which stalls at 2500 once the ring buffer saturates).
    LaunchedEffect(logs.lastOrNull()?.seq) {
        if (autoFollow && logs.isNotEmpty()) {
            programmaticScroll = true
            try {
                val lastVisibleIndex = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
                if (abs(logs.lastIndex - lastVisibleIndex) > 25) {
                    listState.scrollToItem(logs.lastIndex)
                } else {
                    listState.animateScrollToItem(logs.lastIndex)
                }
            } finally {
                programmaticScroll = false
            }
        }
    }

    LaunchedEffect(highlightedSeq) {
        if (highlightedSeq >= 0L) {
            delay(850L)
            highlightedSeq = -1L
        }
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(3.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Ring: ${logs.size} / ${NetShaperRuntime.MAX_TERMINAL_LINES}",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.TextSecondary
                )

                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    TerminalBarButton(label = "Clear", onClick = onClear)
                    TerminalBarButton(label = "Copy All", onClick = onCopyAll)
                    Box {
                        TerminalBarButton(
                            label = "Download \u25BE",
                            onClick = { downloadMenuExpanded = true }
                        )
                        DropdownMenu(
                            expanded = downloadMenuExpanded,
                            onDismissRequest = { downloadMenuExpanded = false },
                            containerColor = NetShaperColors.GlassElevated,
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, NetShaperColors.GlassHairline)
                        ) {
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(
                                            text = "Recent Terminal Logs (.txt)",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = NetShaperColors.TextPrimary
                                        )
                                        Text(
                                            text = "Current ${logs.size}-line buffer in local time",
                                            fontSize = 10.sp,
                                            color = NetShaperColors.TextMuted
                                        )
                                    }
                                },
                                onClick = {
                                    downloadMenuExpanded = false
                                    recentLogLauncher.launch(LogExportHelper.defaultRecentFilename())
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(
                                            text = "Full History Archive (.zip)",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = NetShaperColors.TextPrimary
                                        )
                                        Text(
                                            text = "JSONL + gzipped segments + manifest",
                                            fontSize = 10.sp,
                                            color = NetShaperColors.TextMuted
                                        )
                                    }
                                },
                                onClick = {
                                    downloadMenuExpanded = false
                                    fullArchiveLauncher.launch(LogExportHelper.defaultArchiveFilename())
                                }
                            )
                        }
                    }
                }
            }

            Text(
                text = "Swipe \u2194 for full lines \u00B7 Tap row to copy \u00B7 Local device time",
                fontSize = 10.sp,
                color = NetShaperColors.TextMuted
            )
        }

        // Single outer horizontalScroll + finite contentWidth around LazyColumn prevents
        // Compose Foundation ScrollingLayoutNode.measure crash when scrolling horizontally across rows.
        GlassCard(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(bottom = 12.dp),
            cornerRadius = 14.dp,
            containerColor = NetShaperColors.GlassTerminal
        ) {
            if (logs.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        text = "No log events buffered.",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = NetShaperColors.TextMuted
                    )
                }
            } else {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
                        val contentWidth = maxOf(maxWidth, 920.dp)
                        LazyColumn(
                            state = listState,
                            modifier = Modifier
                                .fillMaxHeight()
                                .horizontalScroll(hScroll)
                                .width(contentWidth),
                            contentPadding = PaddingValues(top = 10.dp, bottom = 52.dp)
                        ) {
                            items(items = logs, key = { it.seq }) { line ->
                                val lineColor = when (line.level.uppercase(Locale.US)) {
                                    "SUCCESS" -> NetShaperColors.Emerald
                                    "WARN" -> NetShaperColors.Amber
                                    "ERROR" -> NetShaperColors.Coral
                                    else -> NetShaperColors.TextPrimary
                                }
                                val rowBg = if (highlightedSeq == line.seq) {
                                    NetShaperColors.ElectricBlueFill
                                } else {
                                    Color.Transparent
                                }

                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(rowBg)
                                        .clickable {
                                            highlightedSeq = line.seq
                                            onCopyLine(line)
                                        }
                                        .padding(horizontal = 12.dp, vertical = 3.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = line.formattedLocalTime(),
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        color = NetShaperColors.TextMuted,
                                        softWrap = false,
                                        maxLines = 1
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = line.text,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        color = lineColor,
                                        softWrap = false,
                                        maxLines = 1
                                    )
                                }
                            }
                        }

                        val showJumpToBottom = logs.isNotEmpty() && (!autoFollow || !isAtBottom)
                        androidx.compose.animation.AnimatedVisibility(
                            visible = showJumpToBottom,
                            enter = fadeIn(),
                            exit = fadeOut(),
                            modifier = Modifier
                                .align(Alignment.BottomEnd)
                                .padding(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .clip(CircleShape)
                                    .background(NetShaperColors.GlassElevated)
                                    .border(1.dp, NetShaperColors.ElectricBlue, CircleShape)
                                    .clickable {
                                        autoFollow = true
                                        if (logs.isNotEmpty()) {
                                            coroutineScope.launch {
                                                programmaticScroll = true
                                                try {
                                                    listState.animateScrollToItem(logs.lastIndex)
                                                } finally {
                                                    programmaticScroll = false
                                                }
                                            }
                                        }
                                    },
                                contentAlignment = Alignment.Center
                            ) {
                                DownArrowGlyph(
                                    modifier = Modifier.size(18.dp),
                                    color = NetShaperColors.ElectricBlue
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun TerminalBarButton(label: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .height(30.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(NetShaperColors.GlassElevated)
            .border(1.dp, NetShaperColors.GlassHairline, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 9.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            color = NetShaperColors.TextPrimary,
            softWrap = false,
            maxLines = 1
        )
    }
}
