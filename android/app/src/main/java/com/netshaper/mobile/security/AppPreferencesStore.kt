package com.netshaper.mobile.security

import android.content.Context

/**
 * Non-secret user preferences stored in MODE_PRIVATE SharedPreferences.
 * GitHub tokens are NEVER placed here — they live strictly in [SecureTokenStore].
 */
class AppPreferencesStore(context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var codespaceName: String
        get() = prefs.getString(KEY_CODESPACE_NAME, DEFAULT_CODESPACE) ?: DEFAULT_CODESPACE
        set(value) { prefs.edit().putString(KEY_CODESPACE_NAME, value.trim()).apply() }

    var oauthClientId: String
        get() {
            val saved = prefs.getString(KEY_OAUTH_CLIENT_ID, "")?.trim().orEmpty()
            return saved.ifBlank { DEFAULT_OAUTH_CLIENT_ID }
        }
        set(value) { prefs.edit().putString(KEY_OAUTH_CLIENT_ID, value.trim()).apply() }

    var stopOnExit: Boolean
        get() = prefs.getBoolean(KEY_STOP_ON_EXIT, true)
        set(value) { prefs.edit().putBoolean(KEY_STOP_ON_EXIT, value).apply() }

    var enableIdleParking: Boolean
        get() = prefs.getBoolean(KEY_ENABLE_IDLE_PARKING, true)
        set(value) { prefs.edit().putBoolean(KEY_ENABLE_IDLE_PARKING, value).apply() }

    var vpnBannerDismissed: Boolean
        get() = prefs.getBoolean(KEY_VPN_BANNER_DISMISSED, false)
        set(value) { prefs.edit().putBoolean(KEY_VPN_BANNER_DISMISSED, value).apply() }

    companion object {
        private const val PREFS_NAME = "netshaper_app_prefs"
        private const val KEY_CODESPACE_NAME = "codespace_name"
        private const val KEY_OAUTH_CLIENT_ID = "oauth_client_id"
        private const val KEY_STOP_ON_EXIT = "stop_on_exit"
        private const val KEY_ENABLE_IDLE_PARKING = "enable_idle_parking"
        private const val KEY_VPN_BANNER_DISMISSED = "vpn_banner_dismissed"
        const val DEFAULT_CODESPACE = "netshaper-edge-prod"
        const val DEFAULT_OAUTH_CLIENT_ID = "178c6fc778ccc68e1d6a"
    }
}
