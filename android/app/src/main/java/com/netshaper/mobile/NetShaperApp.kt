package com.netshaper.mobile

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.netshaper.mobile.service.NetShaperRuntime

class NetShaperApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Zero Main-thread JNI: go.Seq.setContext + initial Go snapshot/logs hydrate asynchronously on Dispatchers.IO.
        NetShaperRuntime.initializeAsync(this)

        // Single authoritative foreground/background observer preventing Activity rotation thrash.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                NetShaperRuntime.setAppForeground(true)
                NetShaperRuntime.probeCurrentVpnBypassState(this@NetShaperApp)
            }

            override fun onStop(owner: LifecycleOwner) {
                NetShaperRuntime.setAppForeground(false)
            }
        })
    }
}
