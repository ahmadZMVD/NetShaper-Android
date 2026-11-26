package com.netshaper.mobile.ui.theme

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Apple-Glass obsidian dark palette with exact color parity against Windows NetShaper v7.0 (`ui_windows.go`).
 */
object NetShaperColors {
    val Canvas = Color(0xFF0B0F16)
    val GlassCard = Color(0xD9141A24)
    val GlassTrack = Color(0xCC0F141D)
    val GlassElevated = Color(0xE61E2634)
    val GlassTerminal = Color(0xEB090D13)
    val GlassInput = Color(0xFF1A212D)
    val GlassHairline = Color(0x24FFFFFF)       // rgba(255,255,255,0.14)
    val GlassHighlight = Color(0x14FFFFFF)

    val TextPrimary = Color(0xFFF4F7FC)
    val TextSecondary = Color(0xFFC4CDDA)
    val TextMuted = Color(0xFF8E99AA)

    val Emerald = Color(0xFF34D399)
    val EmeraldFill = Color(0x2E34D399)
    val EmeraldGlow = Color(0x3834D399)

    val Amber = Color(0xFFF5B441)
    val AmberFill = Color(0x2EF5B441)
    val AmberGlow = Color(0x38F5B441)

    val Coral = Color(0xFFFF5F57)
    val CoralFill = Color(0x33FF5F57)

    val ElectricBlue = Color(0xFF3894FF)
    val ElectricBlueFill = Color(0x2E3894FF)

    val SlateRing = Color(0x8294A3B8)
    val ProgressTrack = Color(0x26FFFFFF)
}

private val NetShaperDarkColorScheme = darkColorScheme(
    primary = NetShaperColors.ElectricBlue,
    onPrimary = NetShaperColors.TextPrimary,
    secondary = NetShaperColors.Emerald,
    onSecondary = NetShaperColors.Canvas,
    tertiary = NetShaperColors.Amber,
    background = NetShaperColors.Canvas,
    onBackground = NetShaperColors.TextPrimary,
    surface = NetShaperColors.GlassCard,
    onSurface = NetShaperColors.TextPrimary,
    surfaceVariant = NetShaperColors.GlassElevated,
    onSurfaceVariant = NetShaperColors.TextSecondary,
    outline = NetShaperColors.GlassHairline,
    error = NetShaperColors.Coral,
    onError = NetShaperColors.TextPrimary
)

private val NetShaperTypography = Typography(
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 20.sp,
        letterSpacing = (-0.2).sp,
        color = NetShaperColors.TextPrimary
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp,
        color = NetShaperColors.TextPrimary
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        color = NetShaperColors.TextSecondary
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 11.sp,
        letterSpacing = 0.6.sp,
        color = NetShaperColors.TextMuted
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 10.sp,
        color = NetShaperColors.TextMuted
    )
)

@Composable
fun NetShaperTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = NetShaperDarkColorScheme,
        typography = NetShaperTypography,
        content = content
    )
}

/**
 * Reusable frosted Apple-Glass container with subtle top specular gradient and 1dp hairline border.
 */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 16.dp,
    containerColor: Color = NetShaperColors.GlassCard,
    borderColor: Color = NetShaperColors.GlassHairline,
    content: @Composable BoxScope.() -> Unit
) {
    val shape = RoundedCornerShape(cornerRadius)
    Box(
        modifier = modifier
            .clip(shape)
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        containerColor.copy(alpha = (containerColor.alpha + 0.04f).coerceAtMost(1f)),
                        containerColor
                    )
                )
            )
            .border(BorderStroke(1.dp, borderColor), shape),
        content = content
    )
}
