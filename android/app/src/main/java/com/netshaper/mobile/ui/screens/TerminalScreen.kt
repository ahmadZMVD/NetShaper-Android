package com.netshaper.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import com.netshaper.mobile.engine.TerminalLogLine
import com.netshaper.mobile.ui.theme.GlassCard
import com.netshaper.mobile.ui.theme.NetShaperColors
import kotlinx.coroutines.delay
import java.util.Locale

@Composable
fun TerminalScreen(
    logs: List<TerminalLogLine>,
    onClear: () -> Unit,
    onCopyAll: () -> Unit,
    onCopyLine: (TerminalLogLine) -> Unit
) {
    val listState = rememberLazyListState()
    val hScroll = rememberScrollState()
    var highlightedSeq by remember { mutableLongStateOf(-1L) }

    // Key on last seq (NOT logs.size, which stalls at 500 once the ring buffer saturates).
    LaunchedEffect(logs.lastOrNull()?.seq) {
        if (logs.isNotEmpty()) {
            val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            if (logs.size <= 12 || lastVisible >= logs.size - 4) {
                listState.animateScrollToItem(logs.lastIndex)
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
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text = "Ring: ${logs.size} / 500",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NetShaperColors.TextSecondary
                )
                Text(
                    text = "Swipe ↔ for full lines · Tap row to copy",
                    fontSize = 10.sp,
                    color = NetShaperColors.TextMuted
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TerminalBarButton(label = "Clear", onClick = onClear)
                TerminalBarButton(label = "Copy All", onClick = onCopyAll)
            }
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
                            contentPadding = PaddingValues(vertical = 10.dp)
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
                                        text = line.ts,
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
            .height(32.dp)
            .clip(RoundedCornerShape(9.dp))
            .background(NetShaperColors.GlassElevated)
            .border(1.dp, NetShaperColors.GlassHairline, RoundedCornerShape(9.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = NetShaperColors.TextPrimary
        )
    }
}
