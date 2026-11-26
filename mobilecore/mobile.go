package mobilecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "golang.org/x/crypto/x509roots/fallback"

	"netshaper/mobilecore/engine"
)

func init() {
	// Mobile RAM ceiling calibrated for 64 concurrent SSH channels without GC thrash while staying safely below Android LMKD.
	debug.SetMemoryLimit(96 << 20) // 96 MiB soft memory limit
	debug.SetGCPercent(75)
}

// MobileCallback is implemented by Kotlin across the gomobile JNI boundary.
// All parameter types are strictly gomobile-safe primitives/strings.
type MobileCallback interface {
	OnStateChange(state string, detail string)
	OnLogLine(seq int64, level string, text string)
	OnError(code string, message string)
}

type cbEvent struct {
	kind  int // 1=state, 2=log, 3=error
	a     string
	b     string
	seq   int64
	level string
}

// callbackDispatcher guarantees Kotlin callbacks NEVER execute on data-plane goroutines,
// NEVER block Go when the UI thread stalls, and NEVER crash Go if Kotlin throws.
type callbackDispatcher struct {
	cb        MobileCallback
	ch        chan cbEvent
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newCallbackDispatcher(cb MobileCallback) *callbackDispatcher {
	if cb == nil {
		return nil
	}
	d := &callbackDispatcher{
		cb:   cb,
		ch:   make(chan cbEvent, 256),
		quit: make(chan struct{}),
		done: make(chan struct{}),
	}
	go d.loop()
	return d
}

func (d *callbackDispatcher) loop() {
	defer close(d.done)
	for {
		select {
		case ev := <-d.ch:
			d.invokeSafe(ev)
		case <-d.quit:
			return
		}
	}
}

func (d *callbackDispatcher) invokeSafe(ev cbEvent) {
	defer func() {
		_ = recover()
	}()
	switch ev.kind {
	case 1:
		d.cb.OnStateChange(ev.a, ev.b)
	case 2:
		d.cb.OnLogLine(ev.seq, ev.level, ev.a)
	case 3:
		d.cb.OnError(ev.a, ev.b)
	}
}

func (d *callbackDispatcher) enqueue(ev cbEvent) {
	if d == nil {
		return
	}
	select {
	case <-d.quit:
		return
	default:
	}
	select {
	case d.ch <- ev:
	default:
		// Drop newest on severe UI backpressure so Go data plane never stalls.
	}
}

func (d *callbackDispatcher) close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		close(d.quit)
		<-d.done
	})
}

var (
	lifecycleMu    sync.Mutex // Serializes Start/Stop transitions cleanly without holding runtimeMu across StopAndWait.
	runtimeMu      sync.Mutex
	activeCtrl     *engine.SessionController
	activeDisp     *callbackDispatcher
	sharedGuard    *engine.GitHubGuard
	sharedResolver *engine.AntiPoisonResolver
	processLogs    *engine.TerminalRingBuffer
	lastLocalURI   atomic.Value

	// Internal test hooks (unexported — invisible to gomobile bind).
	testOverridesMu sync.RWMutex
	testOverrides   engine.ControllerOverrides
	testPanicHook   func()
)

func getTestOverrides() engine.ControllerOverrides {
	testOverridesMu.RLock()
	ov := testOverrides
	testOverridesMu.RUnlock()
	return ov
}

func ensureSharedInfraLocked(cfg engine.Config) (*engine.GitHubGuard, *engine.AntiPoisonResolver, *engine.TerminalRingBuffer) {
	if sharedGuard == nil {
		sharedGuard = engine.NewGitHubGuard(cfg, nil, nil)
	}
	if sharedResolver == nil {
		sharedResolver = engine.NewAntiPoisonResolver(nil, nil)
	}
	if processLogs == nil {
		processLogs = engine.NewTerminalRingBuffer()
	}
	return sharedGuard, sharedResolver, processLogs
}

func newSharedAPIClient(apiBaseURL, oauthBaseURL string) *engine.GitHubAPIClient {
	ov := getTestOverrides()
	if ov.APIClient != nil {
		return ov.APIClient
	}
	runtimeMu.Lock()
	guard, resolver, _ := ensureSharedInfraLocked(engine.DefaultConfig())
	runtimeMu.Unlock()
	if ov.Guard != nil {
		guard = ov.Guard
	}
	if ov.Resolver != nil {
		resolver = ov.Resolver
	}
	return engine.NewGitHubAPIClient(apiBaseURL, oauthBaseURL, resolver, guard)
}

func recoverToErr(errPtr *error) {
	if r := recover(); r != nil {
		*errPtr = fmt.Errorf("mobilecore panic recovered: %v", r)
	}
}

func recoverToString(outPtr *string, fallback string) {
	if r := recover(); r != nil {
		*outPtr = fallback
	}
}

func recoverVoid() {
	_ = recover()
}

// Start parses configJSON and boots the in-process pure-Go NetShaper engine asynchronously.
func Start(configJSON string, callback MobileCallback) (retErr error) {
	defer recoverToErr(&retErr)
	testOverridesMu.RLock()
	ph := testPanicHook
	testOverridesMu.RUnlock()
	if ph != nil {
		ph()
	}
	cfg, err := engine.ParseMobileConfigJSON(configJSON)
	if err != nil {
		return err
	}
	if cfg.GitHubToken == "" && getTestOverrides().TransportFactory == nil {
		return errors.New("github_token must not be empty")
	}

	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	runtimeMu.Lock()
	prev := activeCtrl
	prevDisp := activeDisp
	activeCtrl = nil
	activeDisp = nil
	runtimeMu.Unlock()

	if prev != nil {
		prev.StopAndWait(10 * time.Second)
		prevDisp.close()
	}

	disp := newCallbackDispatcher(callback)
	cb := engine.ControllerCallbacks{
		OnStateChange: func(state, detail string) {
			disp.enqueue(cbEvent{kind: 1, a: state, b: detail})
		},
		OnLogLine: func(seq int64, level, text string) {
			disp.enqueue(cbEvent{kind: 2, seq: seq, level: level, a: text})
		},
		OnError: func(code, message string) {
			disp.enqueue(cbEvent{kind: 3, a: code, b: message})
		},
	}

	ov := getTestOverrides()
	runtimeMu.Lock()
	guard, resolver, logs := ensureSharedInfraLocked(cfg)
	if ov.Guard == nil {
		ov.Guard = guard
	}
	if ov.Resolver == nil {
		ov.Resolver = resolver
	}
	if ov.Logs == nil {
		ov.Logs = logs
	}
	ctrl := engine.NewSessionController(cfg, cb, ov)
	activeCtrl = ctrl
	activeDisp = disp
	lastLocalURI.Store(engine.BuildV2RayNGProfileURI(cfg.LocalHost, cfg.LocalPort))
	runtimeMu.Unlock()

	ctrl.Start()
	return nil
}

// Stop gracefully stops the active NetShaper session and waits for clean teardown (0 leaked goroutines).
func Stop() (retErr error) {
	defer recoverToErr(&retErr)
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	runtimeMu.Lock()
	ctrl := activeCtrl
	disp := activeDisp
	res := sharedResolver
	activeCtrl = nil
	activeDisp = nil
	lastLocalURI.Store("")
	runtimeMu.Unlock()

	if ctrl != nil {
		ctrl.StopAndWait(14 * time.Second)
	}
	if disp != nil {
		disp.close()
	}
	if res != nil {
		res.CloseIdleConnections()
	}
	return nil
}

// GetSnapshotJSON returns the latest immutable engine telemetry snapshot via wait-free atomic load.
func GetSnapshotJSON() (out string) {
	defer recoverToString(&out, `{"state":"STOPPED"}`)
	runtimeMu.Lock()
	ctrl := activeCtrl
	guard := sharedGuard
	runtimeMu.Unlock()
	if ctrl == nil {
		def := engine.DefaultConfig()
		snap := engine.MobileSnapshot{
			CoreVersion:    engine.CoreVersionString,
			State:          engine.CtrlStopped,
			PowerState:     engine.PowerActive,
			LocalHost:      def.LocalHost,
			LocalPort:      int(def.LocalPort),
			LocalAddr:      def.LocalAddr(),
			V2RayNGURI:     engine.BuildV2RayNGProfileURI(def.LocalHost, def.LocalPort),
			PoolSize:       def.PoolSize,
			MaxActiveConns: def.MaxActiveConns,
			GuardMax5Min:   def.GitHubMaxCallsPer5Min,
			GuardMaxHour:   def.GitHubMaxCallsPerHour,
			Workers:        []engine.TunnelSnapshot{},
		}
		if guard != nil {
			gs := guard.CachedSnapshot()
			snap.GuardCalls5Min = gs.CallsLast5Min
			if gs.MaxCallsPer5Min > 0 {
				snap.GuardMax5Min = gs.MaxCallsPer5Min
			}
			snap.GuardCallsHour = gs.CallsLastHour
			if gs.MaxCallsPerHour > 0 {
				snap.GuardMaxHour = gs.MaxCallsPerHour
			}
			snap.GuardCooldownMS = gs.CooldownRemainingMS
			snap.GuardBudgetWaitMS = gs.BudgetWaitMS
			snap.GuardThrottleWaitMS = gs.ThrottleWaitMS
			snap.GuardThrottleReason = gs.ThrottleReason
			snap.GuardRateLimits = gs.RateLimitHits
		}
		b, _ := json.Marshal(snap)
		return string(b)
	}
	snap := ctrl.Snapshot()
	if snap.V2RayNGURI != "" {
		lastLocalURI.Store(snap.V2RayNGURI)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return `{"state":"STOPPED"}`
	}
	return string(b)
}

// GetLogsJSON returns buffered TerminalRingBuffer lines with seq > sinceSeq as a JSON array.
func GetLogsJSON(sinceSeq int64) (out string) {
	defer recoverToString(&out, "[]")
	runtimeMu.Lock()
	ctrl := activeCtrl
	logs := processLogs
	runtimeMu.Unlock()
	if ctrl != nil {
		return ctrl.LogsJSON(sinceSeq)
	}
	if logs == nil {
		return "[]"
	}
	lines := logs.Since(sinceSeq)
	if lines == nil {
		lines = []engine.TerminalLine{}
	}
	b, err := json.Marshal(lines)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ClearLogs empties the bounded TerminalRingBuffer while keeping seq monotonic across restarts.
func ClearLogs() {
	defer recoverVoid()
	runtimeMu.Lock()
	ctrl := activeCtrl
	logs := processLogs
	runtimeMu.Unlock()
	if ctrl != nil && ctrl.Logs() != nil {
		ctrl.Logs().Clear()
		return
	}
	if logs != nil {
		logs.Clear()
	}
}

// NotifyNetworkChange feeds Android ConnectivityManager network transitions into the 1500ms debouncer.
func NotifyNetworkChange(networkType string, isMetered bool) {
	defer recoverVoid()
	runtimeMu.Lock()
	ctrl := activeCtrl
	runtimeMu.Unlock()
	if ctrl != nil {
		ctrl.NotifyNetworkChange(networkType, isMetered)
	}
}

// SetAppForeground throttles background telemetry/log JNI callbacks when the Android Activity is backgrounded.
func SetAppForeground(inForeground bool) {
	defer recoverVoid()
	runtimeMu.Lock()
	ctrl := activeCtrl
	runtimeMu.Unlock()
	if ctrl != nil {
		ctrl.SetAppForeground(inForeground)
	}
}

// StartDeviceAuthJSON starts GitHub OAuth Device Flow (`codespace` scope) with zero GMS dependency.
func StartDeviceAuthJSON(clientID string) (out string, retErr error) {
	defer recoverToErr(&retErr)
	api := newSharedAPIClient("", "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := api.StartDeviceAuth(ctx, clientID)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PollDeviceAuthJSON performs one poll of GitHub OAuth Device Flow.
func PollDeviceAuthJSON(clientID string, deviceCode string) (out string, retErr error) {
	defer recoverToErr(&retErr)
	api := newSharedAPIClient("", "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := api.PollDeviceAuth(ctx, clientID, deviceCode)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ListCodespacesJSON fetches the user's Codespaces list via GitHub REST API (never writes token to disk).
func ListCodespacesJSON(token string) (out string, retErr error) {
	defer recoverToErr(&retErr)
	if strings.TrimSpace(token) == "" {
		return "", errors.New("token must not be empty")
	}
	api := newSharedAPIClient("", "")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	list, err := api.ListCodespaces(ctx, token)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckQuotaJSON runs an on-demand Codespaces machine tier + billing check (isolating HTTP 403 scope errors).
func CheckQuotaJSON(token string, codespaceName string) (out string, retErr error) {
	defer recoverToErr(&retErr)
	if strings.TrimSpace(token) == "" {
		return "", errors.New("token must not be empty")
	}
	api := newSharedAPIClient("", "")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := api.CheckQuota(ctx, token, codespaceName)
	b, mErr := json.Marshal(res)
	if mErr != nil {
		return "", mErr
	}
	if err != nil {
		return string(b), err
	}
	return string(b), nil
}

// StopCodespaceNow issues a bounded POST /user/codespaces/{name}/stop immediately.
func StopCodespaceNow(token string, codespaceName string) (retErr error) {
	defer recoverToErr(&retErr)
	if strings.TrimSpace(token) == "" {
		return errors.New("token must not be empty")
	}
	if err := engine.ValidateCodespaceName(codespaceName); err != nil {
		return err
	}
	api := newSharedAPIClient("", "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return api.StopCodespace(ctx, token, codespaceName)
}

// GetV2RayNGProfileURI returns a v2rayNG SocksFmt-compatible profile URI (e.g. socks://127.0.0.1:1080#NetShaper).
func GetV2RayNGProfileURI() (out string) {
	defer recoverToString(&out, engine.BuildV2RayNGProfileURI(engine.DefaultLocalHost, engine.DefaultLocalPort))
	runtimeMu.Lock()
	ctrl := activeCtrl
	runtimeMu.Unlock()
	if ctrl != nil {
		if uri := ctrl.Snapshot().V2RayNGURI; uri != "" {
			return uri
		}
	}
	if v, ok := lastLocalURI.Load().(string); ok && v != "" {
		return v
	}
	return engine.BuildV2RayNGProfileURI(engine.DefaultLocalHost, engine.DefaultLocalPort)
}

// CoreVersion returns the semantic core version string.
func CoreVersion() string {
	return engine.CoreVersionString
}
