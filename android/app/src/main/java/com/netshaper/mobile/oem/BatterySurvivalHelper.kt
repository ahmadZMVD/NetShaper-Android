package com.netshaper.mobile.oem

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.netshaper.mobile.BuildConfig
import com.netshaper.mobile.engine.VpnBypassState
import java.util.Locale

enum class OemVendor(val displayName: String) {
    HUAWEI("Huawei EMUI / HarmonyOS"),
    XIAOMI("Xiaomi MIUI / HyperOS"),
    SAMSUNG("Samsung OneUI"),
    OPPO("Oppo / Realme / OnePlus ColorOS"),
    VIVO("Vivo / iQOO FuntouchOS"),
    GENERIC("Android (AOSP / Pixel)")
}

data class PermissionReadinessState(
    val notificationsGranted: Boolean = true,
    val canPromptPostNotifications: Boolean = false,
    val batteryOptimizationIgnored: Boolean = false,
    val vpnBypassState: VpnBypassState = VpnBypassState.NO_VPN,
    val oemVendor: OemVendor = OemVendor.GENERIC,
    val appPackageId: String = BuildConfig.APPLICATION_ID
) {
    val allCriticalReady: Boolean
        get() = notificationsGranted &&
            batteryOptimizationIgnored &&
            vpnBypassState != VpnBypassState.ROUTING_LOOP_DETECTED
}

object BatterySurvivalHelper {

    fun detectOemVendor(): OemVendor {
        val fp = "${Build.MANUFACTURER} ${Build.BRAND}".lowercase(Locale.US)
        return when {
            fp.contains("huawei") || fp.contains("honor") -> OemVendor.HUAWEI
            fp.contains("xiaomi") || fp.contains("redmi") || fp.contains("poco") -> OemVendor.XIAOMI
            fp.contains("samsung") -> OemVendor.SAMSUNG
            fp.contains("oppo") || fp.contains("realme") || fp.contains("oneplus") -> OemVendor.OPPO
            fp.contains("vivo") || fp.contains("iqoo") -> OemVendor.VIVO
            else -> OemVendor.GENERIC
        }
    }

    fun inspectReadiness(
        context: Context,
        vpnBypassState: VpnBypassState = VpnBypassState.NO_VPN
    ): PermissionReadinessState {
        val appCtx = context.applicationContext
        val runtimeGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                appCtx,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        val osNotifsEnabled = runCatching {
            NotificationManagerCompat.from(appCtx).areNotificationsEnabled()
        }.getOrDefault(true)

        return PermissionReadinessState(
            notificationsGranted = runtimeGranted && osNotifsEnabled,
            canPromptPostNotifications = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !runtimeGranted,
            batteryOptimizationIgnored = isIgnoringBatteryOptimizations(appCtx),
            vpnBypassState = vpnBypassState,
            oemVendor = detectOemVendor(),
            appPackageId = BuildConfig.APPLICATION_ID
        )
    }

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return runCatching { pm.isIgnoringBatteryOptimizations(context.packageName) }.getOrDefault(false)
    }

    fun openNotificationSettings(context: Context): Boolean {
        val specific = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (launchIfResolvable(context, specific)) return true
        return openAppDetailsSettings(context)
    }

    @SuppressLint("BatteryLife")
    fun requestIgnoreBatteryOptimizations(context: Context): Boolean {
        val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (launchIfResolvable(context, direct)) return true

        val fallback = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (launchIfResolvable(context, fallback)) return true

        return openAppDetailsSettings(context)
    }

    fun openOemBackgroundSettings(context: Context, vendor: OemVendor = detectOemVendor()): Boolean {
        val candidates = when (vendor) {
            OemVendor.HUAWEI -> listOf(
                componentIntent("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
                componentIntent("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"),
                componentIntent("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")
            )
            OemVendor.XIAOMI -> listOf(
                componentIntent("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
                componentIntent("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity")
            )
            OemVendor.SAMSUNG -> listOf(
                componentIntent("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity"),
                componentIntent("com.samsung.android.sm", "com.samsung.android.sm.battery.ui.BatteryActivity"),
                componentIntent("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity")
            )
            OemVendor.OPPO -> listOf(
                componentIntent("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
                componentIntent("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity"),
                componentIntent("com.oplus.battery", "com.oplus.powermanager.fuelgaue.PowerUsageModelActivity")
            )
            OemVendor.VIVO -> listOf(
                componentIntent("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager"),
                componentIntent("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")
            )
            OemVendor.GENERIC -> emptyList()
        }

        for (intent in candidates) {
            if (launchIfResolvable(context, intent)) return true
        }
        return openAppDetailsSettings(context)
    }

    fun openAppDetailsSettings(context: Context): Boolean {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return launchIfResolvable(context, intent)
    }

    fun openExternalBrowser(context: Context, url: String): Boolean {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return launchIfResolvable(context, intent)
    }

    private fun componentIntent(pkg: String, cls: String): Intent = Intent().apply {
        component = ComponentName(pkg, cls)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    private fun launchIfResolvable(context: Context, intent: Intent): Boolean {
        return try {
            val pm = context.packageManager
            val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.resolveActivity(intent, 0)
            }
            if (resolved != null && resolved.activityInfo?.exported != false) {
                context.startActivity(intent)
                true
            } else {
                false
            }
        } catch (_: ActivityNotFoundException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: Throwable) {
            false
        }
    }
}
