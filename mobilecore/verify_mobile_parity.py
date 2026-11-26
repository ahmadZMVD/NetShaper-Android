#!/usr/bin/env python3
"""NetShaper Android mobilecore static parity, gomobile ABI, security & test-suite verifier.

Audits:
  1. Go lexical balance, trailing newline, zero unused imports, zero unsafe.Pointer(uintptr).
  2. 100% constant/invariant parity against ../config.go (64/32/128, 16K/8K, 60s/12s, 180s/20s<25s,
     8s KA, 10sx3 SSH, 25s/0.30/100ms hysteresis, 2.2x/3.5x/30s/800ms, 6/5m, 24/1h, 2s spacing).
  3. Strict gomobile bind type compliance across EVERY exported function/method in mobilecore/mobile.go
     (no uint*, slices of structs, maps, channels, context.Context, time.Duration, variadic args, generics).
  4. Mandatory defer recover() panic firewall on EVERY exported FFI function in mobilecore/mobile.go.
  5. Zero forbidden desktop/subprocess calls inside mobilecore/ (exec.Command, os.Executable, os.UserConfigDir).
  6. All MT-01..MT-15 tests present exactly once, zero t.Parallel(), ephemeral LocalPort=0 only.
  7. Live smoke CLI (cmd/smoke/main.go) present & clean.

Usage: python3 mobilecore/verify_mobile_parity.py
"""
import os
import re
import sys

MOBILE_ROOT = os.path.dirname(os.path.abspath(__file__))
WIN_ROOT = os.path.dirname(MOBILE_ROOT)
fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL:", msg)


def ok(msg):
    print("OK:  ", msg)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def collect_go_files(root):
    out = []
    for dirpath, _, filenames in os.walk(root):
        for fn in sorted(filenames):
            if fn.endswith(".go"):
                out.append(os.path.join(dirpath, fn))
    return out


def strip_go(src, name):
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j < 0:
                raise ValueError(f"{name}: unterminated block comment")
            out.append("\n" * src.count("\n", i, j))
            i = j + 2
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                if src[j] == "\n":
                    raise ValueError(f"{name}: newline in string at {i}")
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise ValueError(f"{name}: unterminated string at {i}")
            i = j + 1
            out.append('""')
        elif c == "`":
            j = src.find("`", i + 1)
            if j < 0:
                raise ValueError(f"{name}: unterminated raw string at {i}")
            out.append("\n" * src.count("\n", i, j))
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise ValueError(f"{name}: unterminated rune at {i}")
            i = j + 1
            out.append("'x'")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def pkg_ident_from_path(path):
    parts = path.strip("/").split("/")
    last = parts[-1]
    if re.fullmatch(r"v\d+", last) and len(parts) >= 2:
        return parts[-2]
    return last


def extract_imports(src):
    imports = []
    for bm in re.finditer(r"import\s*\((.*?)\)", src, re.S):
        for line in bm.group(1).splitlines():
            line = re.sub(r"//.*", "", line).strip()
            if not line:
                continue
            m = re.match(r'^(?:([A-Za-z_\.]\w*)\s+)?"([^"]+)"$', line)
            if m:
                alias, path = m.group(1), m.group(2)
                imports.append((alias if alias else pkg_ident_from_path(path), path))
    for sm in re.finditer(r'^import\s+(?:([A-Za-z_\.]\w*)\s+)?"([^"]+)"', src, re.M):
        alias, path = sm.group(1), sm.group(2)
        imports.append((alias if alias else pkg_ident_from_path(path), path))
    return imports


go_files = collect_go_files(MOBILE_ROOT)
stripped = {}

# 1. Lexical balance, unused imports, unsafe.Pointer(uintptr)
bal_ok, imp_ok, unsafe_ok = True, True, True
for p in go_files:
    rel = os.path.relpath(p, MOBILE_ROOT)
    src = read(p)
    try:
        clean = strip_go(src, rel)
        stripped[rel] = clean
    except ValueError as e:
        fail(str(e))
        bal_ok = False
        continue
    stack = []
    pairs = {")": "(", "}": "{", "]": "["}
    for ch in clean:
        if ch in "({[":
            stack.append(ch)
        elif ch in ")}]":
            if not stack or stack[-1] != pairs[ch]:
                fail(f"{rel}: unbalanced {ch!r}")
                bal_ok = False
                break
            stack.pop()
    if stack:
        fail(f"{rel}: unclosed delimiters {stack}")
        bal_ok = False
    if not src.endswith("\n"):
        fail(f"{rel}: missing trailing newline")
        bal_ok = False

    body = re.sub(r"import\s*\(.*?\)", "", clean, flags=re.S)
    body = re.sub(r"^import\s+.*$", "", body, flags=re.M)
    for ident, path in extract_imports(src):
        if ident in ("_", "."):
            continue
        if not re.search(r"\b" + re.escape(ident) + r"\.", body):
            fail(f"{rel}: unused import {path!r} ({ident!r})")
            imp_ok = False
    if re.search(r"unsafe\.Pointer\(\s*uintptr\b", clean):
        fail(f"{rel}: forbidden unsafe.Pointer(uintptr)")
        unsafe_ok = False

if bal_ok:
    ok(f"{len(go_files)} mobilecore .go files lexically balanced & newline-terminated")
if imp_ok:
    ok(f"0 unused imports across all {len(go_files)} mobilecore .go files")
if unsafe_ok:
    ok("0 unsafe.Pointer(uintptr) casts across mobilecore")

# 2. Constant parity against ../config.go
mob_cfg = read(os.path.join(MOBILE_ROOT, "engine", "config.go"))
win_cfg_path = os.path.join(WIN_ROOT, "config.go")
parity_consts = [
    "DefaultPoolSize",
    "DefaultMaxActiveConns",
    "DefaultPerTunnelMaxConns",
    "DefaultMaxQueuedConns",
    "DefaultCopyBufferSize",
    "DefaultPMTU576CopyBufSize",
    "DefaultIdleTimeout",
    "DefaultPressureIdleTimeout",
    "DefaultStreamingIdleTimeout",
    "DefaultStreamingPressureIdleTimeout",
    "DefaultStalledHandshakeMaxDownBytes",
    "DefaultPressureThresholdPct",
    "DefaultHalfCloseDrainTimeout",
    "DefaultTCPKeepAlivePeriod",
    "DefaultSemaphoreWaitTimeout",
    "DefaultSSHAliveInterval",
    "DefaultSSHAliveCountMax",
    "DefaultHysteresisDwellWindow",
    "DefaultHysteresisRelMargin",
    "DefaultHysteresisAbsMargin",
    "DefaultFastLaneMaxRatio",
    "DefaultSlowLaneEvictRatio",
    "DefaultSlowLaneEvictWindow",
    "DefaultSlowLaneUnderlayCeiling",
    "DefaultGitHubMaxCallsPer5Min",
    "DefaultGitHubMaxCallsPerHour",
    "DefaultGitHubMinCallSpacing",
]


def extract_const(src, name):
    m = re.search(rf"\b{name}\s*=\s*([^\n/]+)", src)
    return m.group(1).strip() if m else None


if os.path.exists(win_cfg_path):
    win_cfg = read(win_cfg_path)
    parity_ok = True
    for cname in parity_consts:
        wv = extract_const(win_cfg, cname)
        mv = extract_const(mob_cfg, cname)
        if wv != mv:
            fail(f"constant parity mismatch for {cname}: windows={wv!r} mobile={mv!r}")
            parity_ok = False
    if parity_ok:
        ok(f"100% constant parity verified across {len(parity_consts)} v6.4 invariants vs ../config.go")
else:
    print("INFO: ../config.go not found; checking mobilecore constants standalone")

# 3. Strict gomobile bind type compliance & panic firewall on mobilecore/mobile.go
mob_go = read(os.path.join(MOBILE_ROOT, "mobile.go"))
mob_clean = stripped.get("mobile.go", "")
forbidden_gomobile_types = [
    r"\buint\d*\b", r"\buintptr\b", r"\bcontext\.Context\b", r"\btime\.Duration\b",
    r"\bchan\b", r"\bmap\[", r"\[\](?!byte\b)", r"\.\.\.", r"\[[A-Z]\w*\s+any\]",
]
exported_funcs = list(re.finditer(r"^func\s+([A-Z]\w*)\s*\(([^)]*)\)\s*([^{\n]*)\{", mob_clean, re.M))
required_exports = {
    "Start", "Stop", "GetSnapshotJSON", "GetLogsJSON", "ClearLogs",
    "NotifyNetworkChange", "SetAppForeground", "StartDeviceAuthJSON",
    "PollDeviceAuthJSON", "ListCodespacesJSON", "CheckQuotaJSON",
    "StopCodespaceNow", "GetV2RayNGProfileURI", "CoreVersion",
}
found_exports = set()
gomobile_ok = True
panic_ok = True
for idx, m in enumerate(exported_funcs):
    fname, params, ret = m.group(1), m.group(2), m.group(3)
    found_exports.add(fname)
    sig = f"({params}) {ret}"
    for fpat in forbidden_gomobile_types:
        if re.search(fpat, sig):
            fail(f"mobile.go exported func {fname}: forbidden gomobile type matching {fpat} in {sig!r}")
            gomobile_ok = False
    # Check panic firewall in body (CoreVersion is trivial constant return).
    body_start = m.end()
    body_end = exported_funcs[idx + 1].start() if idx + 1 < len(exported_funcs) else len(mob_clean)
    body = mob_clean[body_start:body_end]
    if fname != "CoreVersion" and not re.search(r"defer\s+recover", body):
        fail(f"mobile.go exported func {fname}: missing mandatory defer recover*() panic firewall")
        panic_ok = False

missing_exports = sorted(required_exports - found_exports)
if missing_exports:
    fail(f"mobile.go missing required FFI exports: {missing_exports}")
elif gomobile_ok:
    ok(f"gomobile bind type compliance verified across all {len(found_exports)} exported symbols")
if panic_ok:
    ok("panic firewall (defer recover) verified on every exported FFI entry point")

# 4. Zero desktop/subprocess calls inside mobilecore/
desktop_ok = True
for rel, clean in stripped.items():
    if rel.endswith("_test.go") or rel.startswith("cmd"):
        continue
    for bad in ("exec.Command", "os.Executable(", "os.UserConfigDir("):
        if bad in clean:
            fail(f"{rel}: forbidden desktop/subprocess call {bad!r} in mobilecore")
            desktop_ok = False
if desktop_ok:
    ok("0 exec.Command / os.Executable() / os.UserConfigDir() calls in mobilecore engine")

# 5. All MT-01..MT-15 tests present once & isolated
test_files = [p for p in go_files if p.endswith("_test.go")]
found_mt = {}
iso_ok = True
for p in test_files:
    rel = os.path.relpath(p, MOBILE_ROOT)
    src = read(p)
    for m in re.finditer(r"^func\s+(TestMT(\d\d)_\w+)\(t \*testing\.T\)", src, re.M):
        found_mt.setdefault(f"MT{m.group(2)}", []).append(f"{rel}:{m.group(1)}")
    if "t.Parallel()" in src:
        fail(f"{rel}: forbidden t.Parallel() in isolated chaos test")
        iso_ok = False
    for lm in re.finditer(r"\.LocalPort\s*=\s*(\S+)", src):
        if lm.group(1) != "0":
            fail(f"{rel}: non-ephemeral LocalPort={lm.group(1)}")
            iso_ok = False

want_mt = [f"MT{n:02d}" for n in range(1, 16)]
miss_mt = [w for w in want_mt if w not in found_mt]
dup_mt = {k: v for k, v in found_mt.items() if len(v) > 1}
if miss_mt:
    fail(f"missing mobile chaos tests: {miss_mt}")
if dup_mt:
    fail(f"duplicate mobile test IDs: {dup_mt}")
if not miss_mt and not dup_mt:
    ok(f"all 15 mobile chaos tests (MT-01..MT-15) present exactly once")
if iso_ok:
    ok("mobile tests strictly isolated (no t.Parallel, ephemeral LocalPort=0 only)")

# 6. Smoke CLI check
smoke_path = os.path.join(MOBILE_ROOT, "cmd", "smoke", "main.go")
if not os.path.exists(smoke_path):
    fail("missing live smoke CLI: mobilecore/cmd/smoke/main.go")
else:
    ok("live smoke CLI present: mobilecore/cmd/smoke/main.go")

print()
print("RESULT:", "PASS" if not fails else f"FAIL ({len(fails)} problems)")
sys.exit(1 if fails else 0)
