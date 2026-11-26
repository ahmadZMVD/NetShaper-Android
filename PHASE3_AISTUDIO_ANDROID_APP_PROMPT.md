# MASTER BUILD PROMPT — PHASE 3: NETSHAPER ANDROID APP (ZERO-GMS, HUAWEI-SAFE, `v2rayNG` COEXISTENCE)

## 0. MISSION & HARD CONSTRAINTS

Build the **NetShaper Android** native application (**Kotlin + Jetpack Compose + Material 3 Dark Apple-Glass UI**, minSdk `26`, targetSdk `35`) that acts as a **local SOCKS5 proxy tunnel engine (`127.0.0.1:1080`)** designed to run **alongside `v2rayNG`** (NOT instead of it).

**NON-NEGOTIABLE RULES:**
1. **NO `VpnService` in NetShaper!** `v2rayNG` owns Android's single `VpnService` slot. NetShaper runs as an Android **`ForegroundService` (`foregroundServiceType="specialUse"`)** exposing local TCP SOCKS5 on `127.0.0.1:1080`.
2. **100% ZERO Google Play Services (ZERO GMS / ZERO Firebase / ZERO Play Integrity / ZERO Google Auth):** Must install and run identically on **Huawei EMUI / HarmonyOS (no GMS)**, Xiaomi MIUI, Samsung OneUI, and AOSP.
3. **ZERO Deprecated Alpha Crypto Libraries:** Do NOT use deprecated `androidx.security:security-crypto` alpha! Implement clean, self-contained **Android Keystore (`AndroidKeyStore`) + `AES/GCM/NoPadding` (`256-bit` key)** in ~60 lines of standard JDK/Android SDK Kotlin to encrypt the GitHub OAuth token / PAT inside standard private `SharedPreferences`.
4. **Dual-Engine Swappable Architecture (`NetShaperEngine`):**
   - Implement `MockNetShaperEngine` as the default active provider in Phase 3 so the app compiles, installs, and runs interactively on a real phone immediately from AI Studio Build (simulating realistic 2-worker telemetry, live logs, handover states, `IDLE_DEEP` parking, and v2rayNG profile copy).
   - Implement `GoMobileNetShaperEngine` in a clean separate file (or toggleable factory) wired 1-to-1 to the exact `mobilecore` FFI contract below so linking `app/libs/netshaper-core.aar` in Phase 4 is a **1-line swap**.

---

## 1. EXACT `mobilecore` FFI CONTRACT & JSON SCHEMAS (BYTE-FOR-BYTE MATCH)

When `netshaper-core.aar` (built from Go package `mobilecore`) is added to `app/libs/`, `gomobile bind` exposes Java/Kotlin class `mobilecore.Mobilecore` and interface `mobilecore.MobileCallback`:

### 1.1 Kotlin Engine Abstraction (`NetShaperEngine`)
```kotlin
interface NetShaperCallback {
    fun onStateChange(state: String, detail: String)
    fun onLogLine(seq: Long, level: String, text: String)
    fun onError(code: String, message: String)
}

interface NetShaperEngine {
    fun start(configJson: String, callback: NetShaperCallback): Result<Unit>
    fun stop(): Result<Unit>
    fun getSnapshotJson(): String
    fun getLogsJson(sinceSeq: Long): String
    fun clearLogs()
    fun notifyNetworkChange(networkType: String, isMetered: Boolean)
    fun setAppForeground(inForeground: Boolean)
    fun startDeviceAuthJson(clientId: String): Result<String>
    fun pollDeviceAuthJson(clientId: String, deviceCode: String): Result<String>
    fun listCodespacesJson(token: String): Result<String>
    fun checkQuotaJson(token: String, codespaceName: String): Result<String>
    fun stopCodespaceNow(token: String, codespaceName: String): Result<Unit>
    fun getV2RayNGProfileUri(): String
    fun coreVersion(): String
}
```

### 1.2 Input `configJson` for `start(configJson, callback)`
```json
{
  "github_token": "gho_or_pat_from_keystore_memory_only",
  "codespace_name": "my-codespace-name",
  "local_host": "127.0.0.1",
  "local_port": 1080,
  "data_dir": "/data/user/0/com.netshaper.mobile/files/netshaper",
  "pool_size": 2,
  "stop_on_exit": true,
  "enable_idle_parking": true,
  "enable_metrics_log": false
}
```

### 1.3 Output Schema for `getSnapshotJson()` (Parse with `org.json.JSONObject` or `kotlinx.serialization`)
```json
{
  "core_version": "v7.0-mobile-core6.4",
  "state": "RUNNING",
  "supervisor_state": "HEALTHY",
  "power_state": "ACTIVE",
  "codespace_name": "my-codespace-name",
  "local_host": "127.0.0.1",
  "local_port": 1080,
  "local_addr": "127.0.0.1:1080",
  "v2rayng_uri": "socks://127.0.0.1:1080#NetShaper",
  "network_type": "cellular",
  "is_metered": true,
  "app_in_foreground": true,
  "pool_size": 2,
  "healthy_workers": 2,
  "degraded_workers": 0,
  "parked_workers": 0,
  "routing_mode": "balanced",
  "primary_tunnel_id": "",
  "latency_p50_ms": 265.4,
  "underlay_ms": 118.2,
  "active_conns": 12,
  "peak_conns": 28,
  "max_active_conns": 64,
  "queued_conns": 0,
  "semaphore_rejects": 0,
  "bytes_up": 1048576,
  "bytes_down": 8388608,
  "uptime_sec": 342,
  "guard_calls_5m": 2,
  "guard_max_5m": 6,
  "guard_calls_hour": 4,
  "guard_max_hour": 24,
  "guard_cooldown_ms": 0,
  "guard_budget_wait_ms": 0,
  "guard_throttle_wait_ms": 0,
  "guard_throttle_reason": "",
  "guard_rate_limits": 0,
  "workers": [
    {
      "id": "tunnel-1",
      "state": "HEALTHY",
      "slow_lane_degraded": false,
      "wan_remote": "20.120.56.11:443",
      "pmtu576_active": true,
      "active_streams": 6,
      "max_streams": 32,
      "ewma_rtt_ms": 258.1,
      "ewma_jitter_ms": 31.4,
      "relative_rho": 2.18,
      "stream_error_rate": 0.0,
      "total_routed": 45,
      "dial_failures": 0,
      "boot_retries": 0,
      "restarts": 0,
      "last_boot_ms": 9420
    }
  ],
  "last_error": ""
}
```

### 1.4 Output Schema for `getLogsJson(sinceSeq)`
```json
[
  { "seq": 1, "ts": "12:04:10", "level": "INFO", "text": "[Start] codespace=my-cs local=127.0.0.1:1080 pool=2 max_ch=64" },
  { "seq": 2, "ts": "12:04:19", "level": "SUCCESS", "text": "[Ready] 127.0.0.1:1080 | pool=2/2 | route=balanced | underlay=118ms" }
]
```

### 1.5 Auth / Codespaces / Quota JSON Schemas
- `startDeviceAuthJson`: `{"device_code":"...","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}`
- `pollDeviceAuthJson`: `{"status":"authorized|pending|slow_down|expired|denied|error","access_token":"...","error":"...","interval":5}`
- `listCodespacesJson`: `[{"name":"...","display_name":"...","state":"Available|Shutdown","owner_login":"...","repository":"...","machine":{"name":"...","display_name":"...","cpus":2,"memory_in_bytes":8589934592,"storage_in_bytes":34359738368}}]`
- `checkQuotaJson`: `{"checked":true,"codespace_name":"...","codespace_state":"Available","machine_display":"2 cores, 8 GB RAM","cpus":2,"memory_gb":8,"storage_gb":32,"billing_available":false,"core_hours_used":0,"core_hours_included":0,"billing_note":"...","guard_blocked":"","error":""}`

---

## 2. REQUIRED ANDROID SYSTEM ARCHITECTURE

1. **`NetShaperForegroundService` (`Service`):**
   - Manifest declaration:
     - Permissions: `INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`, `WAKE_LOCK`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`.
     - `<service android:name=".service.NetShaperForegroundService" android:exported="false" android:foregroundServiceType="specialUse">` with `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="Persistent local SOCKS5 multi-tunnel supervisor for user-initiated proxy traffic" />`.
   - **Persistent Notification:** Shows live status (`CONNECTED · 265ms · 2/2 · ↑1.2MB ↓8.4MB`), `IDLE_DEEP` badge when parked, and quick action buttons (`Copy URI`, `Stop`).
   - **Bounded WakeLock Policy:** Acquire `PowerManager.PARTIAL_WAKE_LOCK` with a hard timeout `<= 15_000L` ms **ONLY** during initial boot, cellular handover recovery, or graceful stop — **NEVER** hold a continuous WakeLock!
   - **`ConnectivityManager.NetworkCallback`:**
     - Monitor `onAvailable`, `onLost`, `onCapabilitiesChanged`.
     - Map `TRANSPORT_WIFI` -> `"wifi"`, `TRANSPORT_CELLULAR` -> `"cellular"`, `TRANSPORT_ETHERNET` -> `"ethernet"`, lost -> `"none"`, and pass `isMetered = !caps.hasCapability(NET_CAPABILITY_NOT_METERED)` to `engine.notifyNetworkChange(type, isMetered)`.
   - **Active `TRANSPORT_VPN` Routing-Loop Safety Banner:**
     - Detect when `NetworkCapabilities.hasTransport(TRANSPORT_VPN)` is active (meaning `v2rayNG` is running) and show a helpful dismissible status pill reminding the user: **"v2rayNG VPN active — ensure NetShaper is in v2rayNG's Per-App Bypass list to prevent routing loops!"**
   - **Process Lifecycle Observer (`ProcessLifecycleOwner` / Activity `onStart`/`onStop`):**
     - Call `engine.setAppForeground(true/false)` so Go throttles background log/snapshot emissions while screen is off.

2. **Secure Token Vault (`SecureTokenStore`):**
   - Uses `KeyStore.getInstance("AndroidKeyStore")` + `KeyGenerator.getInstance(KEY_ALGORITHM_AES, "AndroidKeyStore")` (`AES/GCM/NoPadding`, 256-bit key alias `"netshaper_github_token_key"`).
   - Encrypts/decrypts the GitHub OAuth token or PAT as `Base64(iv[12] || ciphertext)` in `MODE_PRIVATE` `SharedPreferences`. Never logs the token.

3. **OEM & Huawei Survival Helper (`BatterySurvivalHelper`):**
   - Requests `Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` safely.
   - Provides a dedicated **"Background Survival Wizard"** sheet with safe `try/catch` intent launchers (checking `resolveActivity` first so it never crashes on any phone!) for:
     - **Huawei EMUI / HarmonyOS:** `com.huawei.systemmanager` (`StartupNormalAppListActivity` / `ProtectActivity`) with clear 3-step visual instructions ("App Launch -> NetShaper -> Manage Manually -> Enable Auto-launch, Secondary launch, Run in background").
     - **Xiaomi MIUI / HyperOS:** `com.miui.securitycenter` (`AutoStartManagementActivity`).
     - **Samsung OneUI / Generic Android:** Standard App Info / Battery Unrestricted settings fallback.

---

## 3. VISUAL DESIGN & 3-TAB UI (APPLE-GLASS DARK PARITY WITH WINDOWS v7.0)

Use **Jetpack Compose + Material 3 Dark** matching NetShaper v7.0's refined obsidian Apple-Glass aesthetic (`#0B0F16` canvas, `#141A24` translucent glass cards with `1dp` `rgba(255,255,255,0.14)` hairline borders, Emerald `#34D399` connected, Amber `#F5B441` starting/degraded, Coral `#FF5F57` error, Electric Blue `#3894FF` accent):

1. **Tab 1 — `Home`:**
   - Top status header (`NetShaper v7.0` + animated status pill: `DISCONNECTED` / `STARTING` / `CONNECTED` / `DEGRADED` / `PAUSED_OFFLINE`).
   - Hero Glass Card with centered **96dp circular Power Button** (subtle glowing radial halo + IEC power icon), SOCKS5 address + uptime line, routing mode + underlay baseline + power state (`ACTIVE` / `IDLE_LIGHT` / `IDLE_DEEP (2→1)`).
   - **3-Column Metric Row:** `LATENCY (p50 ms)` | `POOL (2/2)` | `CHANNELS (12/64)`.
   - **Transfer & WAF Guard Card:** `↑ Upload` / `↓ Download`, `WAF Guard: X/6 (5m) · Y/24 (1h)` with slim progress bar and live countdown if throttled.
   - **2-Worker Live Strip:** Compact badges for `tunnel-1` and `tunnel-2` (`RTT`, `rho`, `PMTU=576 8K` badge, `PARKED` badge when in `IDLE_DEEP`).
   - **`v2rayNG` Quick-Connect Card (User-Friendly!):**
     - Primary 1-tap button: **"Copy v2rayNG Profile (`socks://127.0.0.1:1080#NetShaper`)"** (with snackbar confirmation).
     - Secondary 1-tap manual fallback pills: **Copy Host (`127.0.0.1`)** & **Copy Port (`1080`)**.
     - Concise 2-step setup hint ("1. Import clipboard in v2rayNG  2. Add NetShaper to v2rayNG Per-App Bypass").

2. **Tab 2 — `Terminal`:**
   - Top bar with `Ring: N / 500`, `Clear`, and `Copy All` buttons.
   - Monospace (`FontFamily.Monospace`) dark terminal card supporting **BOTH vertical and horizontal scroll** (`horizontalScroll` inside `LazyColumn` or synced horizontal scroll state) so long lines are NEVER truncated, with color-coded severity (`SUCCESS` green, `WARN` amber, `ERROR` coral) and tap-row-to-copy.

3. **Tab 3 — `Account`:**
   - **GitHub Sign-In Card:**
     - **Option A (OAuth Device Flow):** Enter optional OAuth Client ID -> tap **"Sign in with GitHub (Device Flow)"** -> displays huge copyable `ABCD-1234` user code + button to open `https://github.com/login/device` in system browser while polling `pollDeviceAuthJson`.
     - **Option B (Personal Access Token — Fastest Setup):** Paste GitHub PAT (`codespace` scope) -> saved encrypted in `AndroidKeyStore` (with masked display + Sign Out / Wipe Token button).
   - **Codespace Selector Card:**
     - **"Refresh Codespaces"** button (`listCodespacesJson`) -> selectable dropdown/list of user's Codespaces showing live `Available`/`Shutdown` badge and machine specs, PLUS manual Codespace Name text field (locked while tunnel is active!).
   - **On-Demand Quota & Controls Card:**
     - **"Check Quota Now (0 Background Calls)"** (`checkQuotaJson`) displaying VM state, CPU/RAM/Disk tier, and billing/403 note.
     - **"Stop Codespace Now"** (`stopCodespaceNow`) safety button.
   - **Settings & Background Survival Card:**
     - Switches for `Stop Codespace on Disconnect`, `Adaptive Idle Parking (2→1 after 10m)`, and button to open the **Huawei / Battery Survival Wizard**.

---

## 4. CLOUD CI/CD GITHUB ACTIONS WORKFLOW (`.github/workflows/build-android.yml`)

Include this exact GitHub Actions workflow in the repository so building `netshaper-core.aar` (`arm64-v8a`, `armeabi-v7a`, `x86_64`) and Android APKs requires **ZERO local Android NDK installation**:

```yaml
name: Build NetShaper Android (.aar + Universal & Split APKs)

on:
  workflow_dispatch:
  push:
    branches: [ main ]

jobs:
  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'

      - name: Set up Go 1.22
        uses: actions/setup-go@v5
        with:
          go-version: '1.22.10'

      - name: Set up Android SDK & NDK
        uses: android-actions/setup-android@v3
      - name: Install NDK 26.3
        run: sdkmanager "ndk;26.3.11579264"

      - name: Run Pure-Go Mobilecore Unit & Chaos Suite (MT-01..MT-15)
        working-directory: mobilecore
        run: |
          go mod tidy
          python3 verify_mobile_parity.py
          go vet ./...
          go test -race -v -count=1 ./...

      - name: Install gomobile & Build netshaper-core.aar (arm64, arm, amd64)
        working-directory: mobilecore
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/26.3.11579264
        run: |
          go install golang.org/x/mobile/cmd/gomobile@latest
          go install golang.org/x/mobile/cmd/gobind@latest
          export PATH="$PATH:$(go env GOPATH)/bin"
          gomobile init
          go get golang.org/x/mobile/bind
          mkdir -p ../android/app/libs
          gomobile bind \
            -target=android/arm64,android/arm,android/amd64 \
            -androidapi=26 \
            -ldflags="-s -w" \
            -o ../android/app/libs/netshaper-core.aar \
            .

      - name: Build Android APKs (Universal + ABI Splits)
        working-directory: android
        run: |
          chmod +x gradlew
          ./gradlew assembleRelease assembleDebug

      - name: Upload Build Artifacts (.aar + APKs)
        uses: actions/upload-artifact@v4
        with:
          name: netshaper-android-artifacts
          path: |
            android/app/libs/netshaper-core.aar
            android/app/build/outputs/apk/**/*.apk
```

---

## 5. GRADLE & PHASE-4 LINKING SPECIFICATION

In `app/build.gradle.kts`:
- Configure `implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))` so dropping `netshaper-core.aar` into `app/libs/` works immediately.
- Configure ABI splits (`arm64-v8a`, `armeabi-v7a`, `x86_64`) with `isUniversalApk = true` so users can install either a compact per-device APK (~12 MB) or a universal APK on Huawei/Xiaomi/Samsung devices.
- Keep `EngineProvider.create()` defaulting to `MockNetShaperEngine()` during Phase 3, with a clearly documented 1-line switch to `GoMobileNetShaperEngine()` once `netshaper-core.aar` is present.

Generate the complete, compilable Android project cleanly organized by package (`ui/theme`, `ui/screens`, `engine`, `service`, `security`, `oem`, `viewmodel`).
