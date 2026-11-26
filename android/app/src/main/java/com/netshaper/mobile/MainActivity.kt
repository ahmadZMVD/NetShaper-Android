package com.netshaper.mobile

import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModelProvider
import com.netshaper.mobile.service.NetShaperRuntime
import com.netshaper.mobile.ui.screens.MainScreen
import com.netshaper.mobile.ui.theme.NetShaperTheme
import com.netshaper.mobile.viewmodel.NetShaperViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: NetShaperViewModel by lazy {
        ViewModelProvider(this)[NetShaperViewModel::class.java]
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )
        super.onCreate(savedInstanceState)

        setContent {
            NetShaperTheme {
                MainScreen(viewModel = viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Refresh live permissions, OEM battery exemption, and UID-scoped v2rayNG bypass state
        // every time user returns from Android / OEM system Settings.
        NetShaperRuntime.probeCurrentVpnBypassState(this)
        viewModel.refreshReadinessStatus()
    }
}
