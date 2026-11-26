plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.netshaper.mobile"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.netshaper.mobile"
        minSdk = 26
        targetSdk = 35
        versionCode = 700
        versionName = "7.0.0"

        vectorDrawables {
            useSupportLibrary = true
        }
    }

    signingConfigs {
        val ksPath = System.getenv("RELEASE_KEYSTORE_PATH")
            ?.takeIf { it.isNotBlank() }
            ?: System.getenv("NETSHAPER_KEYSTORE_FILE")
        val ksPass = System.getenv("RELEASE_KEYSTORE_PASSWORD")
            ?: System.getenv("NETSHAPER_STORE_PASSWORD")
        val ksAlias = System.getenv("RELEASE_KEY_ALIAS")
            ?: System.getenv("NETSHAPER_KEY_ALIAS")
        val ksKeyPass = System.getenv("RELEASE_KEY_PASSWORD")
            ?: System.getenv("NETSHAPER_KEY_PASSWORD")

        if (!ksPath.isNullOrBlank() && file(ksPath).exists()) {
            create("release") {
                storeFile = file(ksPath)
                storePassword = ksPass
                keyAlias = ksAlias
                keyPassword = ksKeyPass
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            manifestPlaceholders["appName"] = "NetShaper"
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Uses real publisher v1/v2/v3 JKS keystore when secrets exist; falls back to debug key only for test CI builds.
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
        debug {
            isMinifyEnabled = false
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            manifestPlaceholders["appName"] = "NetShaper Debug"
        }
    }

    // ABI splits + universal APK without setting defaultConfig.ndk.abiFilters (avoids AGP 8.7 conflict).
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    // Link compiled pure-Go engine when present; local mock preview compiles cleanly without it.
    val coreAar = file("libs/netshaper-core.aar")
    if (coreAar.exists()) {
        implementation(files(coreAar))
    }

    // 100% ZERO GMS / ZERO Firebase / ZERO deprecated androidx.security:security-crypto.
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
