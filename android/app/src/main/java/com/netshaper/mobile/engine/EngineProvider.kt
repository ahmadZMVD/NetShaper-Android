package com.netshaper.mobile.engine

/**
 * Phase-4 Automatic Core Factory.
 *
 * Automatically binds [GoMobileNetShaperEngine] whenever `android/app/libs/netshaper-core.aar` is
 * present in the build (without triggering Main-thread JNI initialization), falling back cleanly to
 * [MockNetShaperEngine] ONLY for local UI preview builds where the native `.aar` has not yet been generated.
 */
object EngineProvider {
    val isNativeCore: Boolean by lazy { GoMobileNetShaperEngine.isAarPresent() }

    fun create(): NetShaperEngine {
        return if (isNativeCore) GoMobileNetShaperEngine() else MockNetShaperEngine()
    }
}
