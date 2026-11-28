package com.netshaper.mobile.ui.theme

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Crisp custom Canvas IEC Power symbol matching `drawIECPowerGlyph` in Windows v7.0 (`ui_windows.go`):
 * open 280-degree arc + rounded top stem.
 */
@Composable
fun IecPowerGlyph(
    modifier: Modifier = Modifier.size(38.dp),
    color: Color = NetShaperColors.TextPrimary,
    strokeWidth: Dp = 3.5.dp
) {
    Canvas(modifier = modifier) {
        val sw = strokeWidth.toPx()
        val inset = sw * 1.4f
        val arcSize = size.minDimension - inset * 2f
        val topLeft = Offset((size.width - arcSize) / 2f, (size.height - arcSize) / 2f + sw * 0.4f)

        // Open 280° arc leaving an 80° gap centered at 12 o'clock (-90°).
        drawArc(
            color = color,
            startAngle = -50f,
            sweepAngle = 280f,
            useCenter = false,
            topLeft = topLeft,
            size = Size(arcSize, arcSize),
            style = Stroke(width = sw, cap = StrokeCap.Round)
        )

        // Centered vertical power stem cleanly inside the top opening.
        val cx = size.width / 2f
        val stemTop = topLeft.y - sw * 0.8f
        val stemBottom = size.height / 2f + sw * 0.35f
        drawLine(
            color = color,
            start = Offset(cx, stemTop),
            end = Offset(cx, stemBottom),
            strokeWidth = sw,
            cap = StrokeCap.Round
        )
    }
}

/**
 * Compact crisp downward arrow drawn via custom Compose Canvas vectors.
 */
@Composable
fun DownArrowGlyph(
    modifier: Modifier = Modifier.size(18.dp),
    color: Color = NetShaperColors.TextPrimary,
    strokeWidth: Dp = 2.2.dp
) {
    Canvas(modifier = modifier) {
        val sw = strokeWidth.toPx()
        val cx = size.width / 2f
        val topY = size.height * 0.22f
        val tipY = size.height * 0.78f
        val wingX = size.width * 0.26f
        val wingY = tipY - size.height * 0.24f

        drawLine(
            color = color,
            start = Offset(cx, topY),
            end = Offset(cx, tipY - sw * 0.35f),
            strokeWidth = sw,
            cap = StrokeCap.Round
        )

        val chevron = Path().apply {
            moveTo(cx - wingX, wingY)
            lineTo(cx, tipY)
            lineTo(cx + wingX, wingY)
        }
        drawPath(
            path = chevron,
            color = color,
            style = Stroke(
                width = sw,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round
            )
        )
    }
}
