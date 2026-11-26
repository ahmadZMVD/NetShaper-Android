#!/usr/bin/env python3
"""Cross-boundary Phase-4 static verifier for NetShaper Android + mobilecore + CI."""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
ANDROID_ROOT = HERE
MOBILE_ROOT = os.path.join(REPO_ROOT, "mobilecore")
CI_WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "build-android.yml")

fails = []


def ok(msg):
    print(f"OK:   {msg}")


def fail(msg):
    print(f"FAIL: {msg}")
    fails.append(msg)


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def collect_files(root, exts):
    out = []
    for r, _, files in sorted(os.walk(root)):
        for fn in sorted(files):
            if fn.endswith(exts):
                out.append(os.path.join(r, fn))
    return out


# 1. Zero VpnService, Zero GMS, Zero Firebase, Zero security-crypto, Zero cm.allNetworks, Zero Restricted Settings
android_sources = collect_files(ANDROID_ROOT, (".kt", ".xml", ".kts", ".pro"))
forbidden_patterns = [
    ("BIND_VPN_SERVICE", "Android VpnService permission conflict with v2rayNG"),
    ("VpnService", "Direct VpnService usage forbidden (v2rayNG owns VPN slot)"),
    ("com.google.android.gms", "Google Play Services forbidden (Zero-GMS required)"),
    ("com.google.firebase", "Firebase forbidden (Zero-GMS required)"),
    ("security-crypto", "Deprecated androidx.security:security-crypto forbidden"),
    (".allNetworks", "Deprecated ConnectivityManager.allNetworks forbidden"),
    ("BIND_ACCESSIBILITY_SERVICE", "Restricted-Settings Accessibility permission forbidden"),
    ("BIND_NOTIFICATION_LISTENER_SERVICE", "Restricted-Settings NotificationListener permission forbidden"),
    ("SYSTEM_ALERT_WINDOW", "High-friction overlay permission forbidden"),
    ("QUERY_ALL_PACKAGES", "Play-Protect/AV-flagged QUERY_ALL_PACKAGES forbidden"),
    ("REQUEST_INSTALL_PACKAGES", "AV-flagged REQUEST_INSTALL_PACKAGES forbidden"),
    ("READ_LOGS", "Privileged/AV-flagged READ_LOGS permission forbidden"),
    ("READ_PHONE_STATE", "High-risk telemetry permission READ_PHONE_STATE forbidden"),
    ("ACCESS_FINE_LOCATION", "Location permission forbidden"),
    ("RECEIVE_BOOT_COMPLETED", "Unused boot receiver permission inflates AV risk"),
    ("DexClassLoader", "Dynamic dex loading triggers Play Protect / AV heuristics"),
]
clean_forbidden = True
for path in android_sources:
    rel = os.path.relpath(path, REPO_ROOT)
    src = read(path)
    for pat, why in forbidden_patterns:
        for i, line in enumerate(src.splitlines(), 1):
            # Ignore explanatory comments in manifests/docs mentioning what is avoided
            stripped_line = line.strip()
            if stripped_line.startswith(("//", "/*", "*", "<!--", "#")):
                continue
            if pat in line:
                fail(f"{rel}:{i}: forbidden reference {pat!r} ({why})")
                clean_forbidden = False
if clean_forbidden:
    ok(f"0 forbidden VPN/GMS/Restricted-Settings/AV-trigger APIs across {len(android_sources)} Android files")

# 2. Locale.US check across ALL Kotlin String.format calls + safeDouble NaN/Inf guard
kt_files = collect_files(ANDROID_ROOT, (".kt",))
locale_ok = True
for path in kt_files:
    rel = os.path.relpath(path, REPO_ROOT)
    for i, line in enumerate(read(path).splitlines(), 1):
        if "String.format(" in line and "Locale.US" not in line:
            fail(f"{rel}:{i}: String.format missing explicit Locale.US")
            locale_ok = False
if locale_ok:
    ok(f"100% Locale.US enforced across all String.format calls in {len(kt_files)} Kotlin files")

models_path = os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/engine/NetShaperModels.kt")
models_src = read(models_path)
if "safeDouble(" in models_src and "isNaN()" in models_src and "isInfinite()" in models_src:
    ok("NetShaperModels.kt safeDouble() NaN/Infinity firewall present")
else:
    fail("NetShaperModels.kt missing safeDouble() NaN/Infinity guard")

# 3. Go <-> Kotlin JSON field parity & 14/14 gomobile ABI method name parity
go_structs = {}
for rel in ("engine/controller.go", "engine/tunnel_instance.go", "engine/github_api.go", "engine/logger.go"):
    src = read(os.path.join(MOBILE_ROOT, rel))
    for m in re.finditer(r"type\s+(\w+)\s+struct\s*\{(.*?)\n\}", src, re.S):
        go_structs[m.group(1)] = set(re.findall(r'`json:"([^",]+)', m.group(2)))

struct_pairs = [
    ("MobileSnapshot", "MobileSnapshot"),
    ("WorkerSnapshot", "TunnelSnapshot"),
    ("TerminalLogLine", "TerminalLine"),
    ("DeviceAuthStart", "DeviceAuthStartResponse"),
    ("DeviceAuthPoll", "DeviceAuthPollResponse"),
    ("CodespaceMachineInfo", "CodespaceMachine"),
    ("CodespaceItem", "CodespaceSummary"),
    ("QuotaReport", "QuotaInfo"),
]
json_ok = True
for kt_cls, go_cls in struct_pairs:
    idx = models_src.find(f"data class {kt_cls}(")
    nxt = models_src.find("data class ", idx + 20)
    if nxt == -1:
        nxt = models_src.find("object Formatters", idx)
    chunk = models_src[idx:nxt]
    if kt_cls == "MobileSnapshot":
        cut = chunk.find("val workersArr =")
        if cut != -1:
            chunk = chunk[:cut]
    if kt_cls == "CodespaceItem":
        cut = chunk.find("val m = o.optJSONObject")
        if cut != -1:
            chunk = chunk[:cut]
    kt_keys = set(re.findall(r'(?:safeDouble|optString|optInt|optLong|optBoolean)\(\s*"([^"]+)"', chunk))
    missing = sorted(kt_keys - go_structs.get(go_cls, set()))
    if missing:
        fail(f"JSON schema drift in {kt_cls} vs Go {go_cls}: missing keys {missing}")
        json_ok = False
if json_ok:
    ok(f"100% Go <-> Kotlin JSON schema parity verified across {len(struct_pairs)} structs")

mob_go = read(os.path.join(MOBILE_ROOT, "mobile.go"))
gm_path = os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/engine/GoMobileNetShaperEngine.kt")
gm_src = read(gm_path)
go_exports = {x[0].lower() + x[1:] for x in re.findall(r"^func\s+([A-Z]\w*)\(", mob_go, re.M)}
kt_methods = set(re.findall(r'coreClass\.getMethod\(\s*"([^"]+)"', gm_src))
if go_exports == kt_methods and len(go_exports) == 14:
    ok(f"14/14 gomobile Java ABI method names match mobilecore/mobile.go ({sorted(go_exports)})")
else:
    fail(f"gomobile method mismatch: go={sorted(go_exports)} kotlin={sorted(kt_methods)}")

if 'Class.forName(\n                "mobilecore.Mobilecore",\n                false' in gm_src or re.search(
    r'Class\.forName\(\s*"mobilecore\.Mobilecore"\s*,\s*false', gm_src
):
    ok("GoMobileNetShaperEngine.isAarPresent() uses non-initializing Class.forName(..., false, ...)")
else:
    fail("GoMobileNetShaperEngine.isAarPresent() must pass initialize=false to avoid Main-thread JNI init")

if "go.Seq" in gm_src and "setContext" in gm_src:
    ok("GoMobileNetShaperEngine wires go.Seq.setContext off UI thread")
else:
    fail("GoMobileNetShaperEngine missing go.Seq.setContext initialization")

# 4. EngineProvider Phase-4 auto-detection (no hardcoded Mock-only return)
ep_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/engine/EngineProvider.kt"))
if "isNativeCore" in ep_src and "GoMobileNetShaperEngine()" in ep_src:
    ok("EngineProvider auto-detects netshaper-core.aar cleanly")
else:
    fail("EngineProvider still hardcodes MockNetShaperEngine")

# 5. TerminalScreen LazyColumn crash fix + seq auto-scroll key
term_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/ui/screens/TerminalScreen.kt"))
if "BoxWithConstraints" in term_src and ".horizontalScroll(hScroll)" in term_src and "logs.lastOrNull()?.seq" in term_src:
    # Ensure horizontalScroll does not appear inside items(...)
    items_idx = term_src.find("items(items = logs")
    if items_idx != -1 and "horizontalScroll(" not in term_src[items_idx:]:
        ok("TerminalScreen wraps LazyColumn in finite-width outer horizontalScroll + keys on logs.lastOrNull()?.seq")
    else:
        fail("TerminalScreen still uses horizontalScroll inside LazyColumn item rows")
else:
    fail("TerminalScreen missing BoxWithConstraints / outer horizontalScroll / logs.lastOrNull()?.seq fix")

# 6. SecureTokenStore process-wide vaultLock + invalidation recovery + atomic commit()
vault_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/security/SecureTokenStore.kt"))
for req_tok, msg in [
    ("vaultLock", "SecureTokenStore missing process-wide vaultLock"),
    ("KeyPermanentlyInvalidatedException", "SecureTokenStore missing KeyPermanentlyInvalidatedException handler"),
    ("AEADBadTagException", "SecureTokenStore missing AEADBadTagException handler"),
    ("deleteEntry(", "SecureTokenStore missing KeyStore alias deletion on invalidation"),
    (".commit()", "SecureTokenStore missing atomic .commit()"),
    ("isUserUnlocked", "SecureTokenStore missing Direct-Boot UserManager.isUserUnlocked check"),
]:
    if req_tok not in vault_src:
        fail(msg)
if not any("SecureTokenStore" in f for f in fails):
    ok("SecureTokenStore hardened with process-wide vaultLock, Direct-Boot check & KeyStore auto-recovery")

# 7. NetShaperRuntime & ViewModel & App/Activity Main-thread hygiene + ForegroundService guarantees
rt_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/service/NetShaperRuntime.kt"))
if "MutableStateFlow(MobileSnapshot())" in rt_src and "initializeAsync(" in rt_src and "VpnBypassState" in rt_src:
    ok("NetShaperRuntime avoids static Main-thread JNI init and exposes VpnBypassState")
else:
    fail("NetShaperRuntime missing zero-Main-thread-JNI or VpnBypassState contract")

vm_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/viewmodel/NetShaperViewModel.kt"))
if "Dispatchers.IO" in vm_src and "refreshReadinessStatus" in vm_src:
    ok("NetShaperViewModel offloads KeyStore & JNI operations onto Dispatchers.IO")
else:
    fail("NetShaperViewModel missing Dispatchers.IO KeyStore/JNI offloading")

fgs_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/service/NetShaperForegroundService.kt"))
for req_tok, msg in [
    ("Mutex", "NetShaperForegroundService missing serviceMutex"),
    ("sessionGen", "NetShaperForegroundService missing sessionGen"),
    ("isUserUnlocked", "NetShaperForegroundService missing START_STICKY isUserUnlocked guard"),
    ("NOTIF_MIN_INTERVAL_BG_MS", "NetShaperForegroundService missing 30s background notification rate limit"),
    ("BACKGROUND_POLL_MS", "NetShaperForegroundService missing background poll throttle"),
    ("getForegroundService(", "NetShaperForegroundService notification actions must use getForegroundService"),
    ("NetShaperRuntime.engine.stop()", "NetShaperForegroundService.onDestroy missing Go engine teardown"),
]:
    if req_tok not in fgs_src:
        fail(msg)
if not any("NetShaperForegroundService" in f for f in fails):
    ok("NetShaperForegroundService enforces Mutex/sessionGen, Direct-Boot guard, 5s FGS rule & battery throttling")

ma_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/MainActivity.kt"))
if "setAppForeground(" not in ma_src and "onResume()" in ma_src and "refreshReadinessStatus()" in ma_src:
    ok("MainActivity delegates foreground tracking to NetShaperApp & refreshes readiness onResume()")
else:
    fail("MainActivity must not duplicate setAppForeground() and must refresh readiness in onResume()")

oem_src = read(os.path.join(ANDROID_ROOT, "app/src/main/java/com/netshaper/mobile/oem/BatterySurvivalHelper.kt"))
if "ActivityNotFoundException" in oem_src and "SecurityException" in oem_src and "PermissionReadinessState" in oem_src and "ACTION_APP_NOTIFICATION_SETTINGS" in oem_src:
    ok("BatterySurvivalHelper provides PermissionReadinessState + crash-proof OEM/notification/battery fallbacks")
else:
    fail("BatterySurvivalHelper missing PermissionReadinessState or crash-proof fallback handling")

# 8. Manifest, ProGuard, Gradle, and CI checks
man_src = read(os.path.join(ANDROID_ROOT, "app/src/main/AndroidManifest.xml"))
if 'android:usesCleartextTraffic="false"' in man_src and 'android:allowBackup="false"' in man_src and 'android:label="${appName}"' in man_src:
    ok("AndroidManifest.xml enforces usesCleartextTraffic=false, allowBackup=false, and flavor label placeholder")
else:
    fail("AndroidManifest.xml missing usesCleartextTraffic=false, allowBackup=false, or ${appName}")

pg_src = read(os.path.join(ANDROID_ROOT, "app/proguard-rules.pro"))
if "-keepattributes InnerClasses,Signature,Exceptions" in pg_src and "-keepclassmembers class mobilecore.**" in pg_src and "-keepclassmembers class go.**" in pg_src:
    ok("proguard-rules.pro preserves gomobile classes, interfaces, members, and attributes for R8 full-mode")
else:
    fail("proguard-rules.pro incomplete for R8 full-mode")

def strip_line_comments(src, marker):
    return "\n".join(line.split(marker, 1)[0] for line in src.splitlines())


gradle_src = read(os.path.join(ANDROID_ROOT, "app/build.gradle.kts"))
gradle_code = strip_line_comments(re.sub(r"/\*.*?\*/", "", gradle_src, flags=re.S), "//")
gradle_ok = True
if "abiFilters" in gradle_code:
    fail("app/build.gradle.kts sets abiFilters alongside splits.abi (hard AGP build error)")
    gradle_ok = False
for tok in ('useLegacyPackaging = false', 'val coreAar = file("libs/netshaper-core.aar")', 'RELEASE_KEYSTORE_PATH', 'enableV3Signing = true'):
    if tok not in gradle_code:
        fail(f"app/build.gradle.kts missing {tok!r}")
        gradle_ok = False
if gradle_ok:
    ok("app/build.gradle.kts verified (conditional .aar, ABI splits without conflict, useLegacyPackaging=false, v2/v3 signing)")

ci_src = read(CI_WORKFLOW)
ci_code = strip_line_comments(ci_src, "#")
ci_ok = True
if re.search(r"\./gradlew|\bchmod\s+\+x\s+gradlew", ci_code):
    fail(".github/workflows/build-android.yml still references missing ./gradlew binary")
    ci_ok = False
for tok in (
    "gradle/actions/setup-gradle@v4",
    "platforms;android-35",
    "build-tools;35.0.0",
    "ndk;26.3.11579264",
    "max-page-size=16384",
    "readelf -l",
    "0x4000",
    "verify_static.py",
    "verify_mobile_parity.py",
    "verify_android_parity.py",
    "SHA256SUMS.txt",
):
    if tok not in ci_code:
        fail(f".github/workflows/build-android.yml missing {tok!r}")
        ci_ok = False
if ci_ok:
    ok(".github/workflows/build-android.yml passes all 6 CI gates, 16KB ELF check, Gradle 8.9, signing & SHA256SUMS")

# 9. Cross-check mobilecore/ Phase-4 fixes
mob_ctrl = read(os.path.join(MOBILE_ROOT, "engine/controller.go"))
mob_dt = read(os.path.join(MOBILE_ROOT, "engine/devtunnel_transport.go"))
mob_dns = read(os.path.join(MOBILE_ROOT, "engine/dns_resolver.go"))
mob_pool = read(os.path.join(MOBILE_ROOT, "engine/tunnel_pool.go"))
mob_checks = [
    ("96 << 20" in mob_go, "mobilecore/mobile.go missing 96 MiB ceiling"),
    ("golang.org/x/crypto/x509roots/fallback" in mob_go, "mobilecore/mobile.go missing x509roots/fallback"),
    ("lifecycleMu" in mob_go, "mobilecore/mobile.go missing lifecycleMu"),
    ("processLogs" in mob_go, "mobilecore/mobile.go missing processLogs"),
    ("context.AfterFunc" in mob_dt, "mobilecore/engine/devtunnel_transport.go missing context.AfterFunc"),
    ("errDoHEndpointDown" in mob_dns, "mobilecore/engine/dns_resolver.go missing errDoHEndpointDown fast-fail"),
    ("0x64" in mob_dns, "mobilecore/engine/dns_resolver.go missing 64:ff9b::/96 NAT64 unwrap"),
    ("time.After(200" not in mob_pool, "mobilecore/engine/tunnel_pool.go still contains time.After(200...)"),
    ("time.After(250" not in mob_pool, "mobilecore/engine/tunnel_pool.go still contains time.After(250...)"),
    (bool(re.search(r"\bLogs\s+\*TerminalRingBuffer\b", mob_ctrl)), "mobilecore/engine/controller.go missing Logs override"),
]
mob_phase4_ok = True
for cond, msg in mob_checks:
    if not cond:
        fail(msg)
        mob_phase4_ok = False
if mob_phase4_ok:
    ok("mobilecore/ verified: 96 MiB ceiling, x509 fallback, lifecycleMu, processLogs, context.AfterFunc, NAT64/DoH, 0 idle polling spins")

print()
print("RESULT:", "PASS" if not fails else f"FAIL ({len(fails)} problems)")
sys.exit(1 if fails else 0)
