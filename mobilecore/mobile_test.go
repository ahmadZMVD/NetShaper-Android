package mobilecore

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"netshaper/mobilecore/engine"
)

type stubTransport struct{}

func (stubTransport) Connect(_ context.Context, _ string) (engine.WorkerSession, error) {
	return newStubSession(), nil
}

type stubSession struct {
	done chan error
	once sync.Once
}

func newStubSession() *stubSession { return &stubSession{done: make(chan error, 1)} }

func (s *stubSession) DialTarget(ctx context.Context, _ string, _ uint16) (net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		defer ln.Close()
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", ln.Addr().String())
}
func (s *stubSession) SendKeepalive(_ context.Context) error { return nil }
func (s *stubSession) WANRemote() string                     { return "20.93.53.155:443" }
func (s *stubSession) PMTU576Active() bool                   { return false }
func (s *stubSession) Done() <-chan error                    { return s.done }
func (s *stubSession) Close() error {
	s.once.Do(func() {
		s.done <- net.ErrClosed
		close(s.done)
	})
	return nil
}

func installStubOverrides(t *testing.T) {
	t.Helper()
	testOverridesMu.Lock()
	testOverrides = engine.ControllerOverrides{
		TransportFactory: func(_ engine.Config, _ *engine.CredentialManager, _ *engine.AntiPoisonResolver, _ *engine.HeartbeatCoordinator, _ *engine.EventLogger) engine.WorkerTransport {
			return stubTransport{}
		},
		StopCodespace: func(_ context.Context, _ engine.Config) error { return nil },
		PoolHooks: engine.PoolHooks{
			ProbeFunc: func(_ context.Context, _ engine.WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 80 * time.Millisecond, nil
			},
			MicroPayloadProbeFunc: func(_ context.Context, _ engine.WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 80 * time.Millisecond, nil
			},
			SampleDelay: 5 * time.Millisecond,
			RetryDelay:  10 * time.Millisecond,
		},
		SnapshotInterval: 50 * time.Millisecond,
	}
	testOverridesMu.Unlock()
	t.Cleanup(func() {
		_ = Stop()
		testOverridesMu.Lock()
		testOverrides = engine.ControllerOverrides{}
		testOverridesMu.Unlock()
	})
}

type recordingCallback struct {
	mu           sync.Mutex
	states       []string
	logCount     atomic.Int64
	blockOnLogCh chan struct{}
}

func (r *recordingCallback) OnStateChange(state, _ string) {
	r.mu.Lock()
	r.states = append(r.states, state)
	r.mu.Unlock()
}

func (r *recordingCallback) OnLogLine(_ int64, _, _ string) {
	r.logCount.Add(1)
	if r.blockOnLogCh != nil {
		<-r.blockOnLogCh
	}
}

func (r *recordingCallback) OnError(_, _ string) {}

// =============================================================================
// MT-07: 50x Rapid Start() -> Stop() In-Process Lifecycle Soak (0 Goroutine/Socket Leaks)
// =============================================================================
func TestMT07_Lifecycle50xStartStopSoakZeroLeaks(t *testing.T) {
	installStubOverrides(t)
	// Warm up 1 cycle so one-time runtime goroutines stabilize.
	cfgJSON := fmt.Sprintf(`{"github_token":"gho_soak","codespace_name":"mt07-soak","local_port":0,"data_dir":%q,"pool_size":2,"stop_on_exit":false}`, t.TempDir())
	if err := Start(cfgJSON, nil); err != nil {
		t.Fatalf("MT-07 warmup Start: %v", err)
	}
	_ = Stop()
	runtime.GC()
	baseG := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		if err := Start(cfgJSON, nil); err != nil {
			t.Fatalf("MT-07 cycle %d Start: %v", i+1, err)
		}
		deadline := time.Now().Add(3 * time.Second)
		running := false
		for time.Now().Before(deadline) {
			var snap engine.MobileSnapshot
			_ = json.Unmarshal([]byte(GetSnapshotJSON()), &snap)
			if snap.State == engine.CtrlRunning && snap.HealthyWorkers >= 1 {
				running = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !running {
			_ = Stop()
			t.Fatalf("MT-07 cycle %d did not reach RUNNING", i+1)
		}
		if err := Stop(); err != nil {
			t.Fatalf("MT-07 cycle %d Stop: %v", i+1, err)
		}
	}

	dl := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(dl) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseG+6 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("MT-07 goroutine leak after 50x Start/Stop soak: baseline=%d current=%d", baseG, runtime.NumGoroutine())
}

// =============================================================================
// MT-08: FFI Panic-Recovery Firewall & Non-Blocking Stalled Kotlin Callback
// =============================================================================
func TestMT08_FFIPanicFirewallAndNonBlockingCallback(t *testing.T) {
	installStubOverrides(t)

	// 1. Deliberate panic inside Start() MUST be caught and returned as Go error (never SIGABRT JVM!).
	testOverridesMu.Lock()
	testPanicHook = func() { panic("simulated_native_fault") }
	testOverridesMu.Unlock()
	err := Start(`{"codespace_name":"mt08-space"}`, nil)
	testOverridesMu.Lock()
	testPanicHook = nil
	testOverridesMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "panic recovered") {
		t.Fatalf("MT-08 expected recovered panic error, got: %v", err)
	}

	// 2. Stalled/blocking Kotlin callback MUST NEVER block Start(), GetSnapshotJSON(), or Stop()!
	unblock := make(chan struct{})
	cb := &recordingCallback{blockOnLogCh: unblock}
	cfgJSON := fmt.Sprintf(`{"github_token":"gho_mt08","codespace_name":"mt08-space","local_port":0,"data_dir":%q,"pool_size":2,"stop_on_exit":false}`, t.TempDir())
	if err := Start(cfgJSON, cb); err != nil {
		t.Fatalf("MT-08 Start with stalled callback: %v", err)
	}

	dl := time.Now().Add(3 * time.Second)
	for time.Now().Before(dl) {
		var snap engine.MobileSnapshot
		_ = json.Unmarshal([]byte(GetSnapshotJSON()), &snap)
		if snap.State == engine.CtrlRunning {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	close(unblock)
	if err := Stop(); err != nil {
		t.Fatalf("MT-08 Stop failed: %v", err)
	}
}

// =============================================================================
// MT-15: v2rayNG Profile URI, Snapshot JSON Schema & Incremental Logs Contract
// =============================================================================
func TestMT15_V2RayNGProfileURIAndSnapshotJSONContract(t *testing.T) {
	installStubOverrides(t)

	if CoreVersion() == "" {
		t.Fatal("MT-15 CoreVersion() must not be empty")
	}

	// Check stopped default snapshot & URI.
	defURI := GetV2RayNGProfileURI()
	if defURI != "socks://127.0.0.1:1080#NetShaper" {
		t.Fatalf("MT-15 unexpected default v2rayNG URI: %q", defURI)
	}

	cfgJSON := fmt.Sprintf(`{"github_token":"gho_mt15","codespace_name":"mt15-space","local_port":0,"data_dir":%q,"pool_size":2,"stop_on_exit":false}`, t.TempDir())
	if err := Start(cfgJSON, nil); err != nil {
		t.Fatalf("MT-15 Start: %v", err)
	}
	defer Stop()

	var snap engine.MobileSnapshot
	dl := time.Now().Add(4 * time.Second)
	for time.Now().Before(dl) {
		_ = json.Unmarshal([]byte(GetSnapshotJSON()), &snap)
		if snap.State == engine.CtrlRunning && snap.LocalPort > 0 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if snap.State != engine.CtrlRunning || snap.LocalHost != "127.0.0.1" || snap.LocalPort <= 0 {
		t.Fatalf("MT-15 snapshot missing host/port fields: %+v", snap)
	}
	wantURI := fmt.Sprintf("socks://127.0.0.1:%d#NetShaper", snap.LocalPort)
	if snap.V2RayNGURI != wantURI || GetV2RayNGProfileURI() != wantURI {
		t.Fatalf("MT-15 URI mismatch: snap=%q fn=%q want=%q", snap.V2RayNGURI, GetV2RayNGProfileURI(), wantURI)
	}

	// Verify incremental GetLogsJSON(sinceSeq) & ClearLogs().
	var logs1 []engine.TerminalLine
	if err := json.Unmarshal([]byte(GetLogsJSON(0)), &logs1); err != nil || len(logs1) == 0 {
		t.Fatalf("MT-15 expected non-empty GetLogsJSON(0), got len=%d err=%v", len(logs1), err)
	}
	lastSeq := logs1[len(logs1)-1].Seq
	var logs2 []engine.TerminalLine
	_ = json.Unmarshal([]byte(GetLogsJSON(lastSeq)), &logs2)
	for _, ln := range logs2 {
		if ln.Seq <= lastSeq {
			t.Fatalf("MT-15 GetLogsJSON(%d) returned stale seq %d", lastSeq, ln.Seq)
		}
	}
	ClearLogs()
	if GetLogsJSON(0) != "[]" {
		t.Fatalf("MT-15 expected empty [] after ClearLogs(), got %s", GetLogsJSON(0))
	}
}

// =============================================================================
// MT-16: Process-Lifetime Monotonic Log Seq, Concurrent Start() Serialization & Stopped Guard Visibility
// =============================================================================
func TestMT16_MonotonicLogsAcrossRestartsAndStoppedGuardTelemetry(t *testing.T) {
	installStubOverrides(t)
	dataDir := t.TempDir()
	t.Cleanup(func() { _ = Stop() })
	cfgJSON := fmt.Sprintf(`{"github_token":"gho_mt16","codespace_name":"mt16-space","local_port":0,"data_dir":%q,"pool_size":2,"stop_on_exit":false}`, dataDir)

	// Session 1
	if err := Start(cfgJSON, nil); err != nil {
		t.Fatalf("MT-16 Start 1: %v", err)
	}
	dl1 := time.Now().Add(3 * time.Second)
	for time.Now().Before(dl1) {
		var snap engine.MobileSnapshot
		_ = json.Unmarshal([]byte(GetSnapshotJSON()), &snap)
		if snap.State == engine.CtrlRunning {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	var s1Logs []engine.TerminalLine
	_ = json.Unmarshal([]byte(GetLogsJSON(0)), &s1Logs)
	if len(s1Logs) == 0 {
		t.Fatal("MT-16 expected non-empty logs in session 1")
	}
	lastSeqBeforeStop := s1Logs[len(s1Logs)-1].Seq

	// Record one API guard budget call on process-lifetime sharedGuard while active.
	runtimeMu.Lock()
	g := sharedGuard
	runtimeMu.Unlock()
	if g == nil {
		t.Fatal("MT-16 expected sharedGuard initialized")
	}
	beforeCalls := g.CachedSnapshot().CallsLast5Min
	if err := g.Allow(context.Background(), "wake_codespace"); err != nil {
		t.Fatalf("MT-16 sharedGuard.Allow: %v", err)
	}

	if err := Stop(); err != nil {
		t.Fatalf("MT-16 Stop 1: %v", err)
	}

	// Stopped-state snapshot MUST still preserve live sharedGuard counters (BUG-G08).
	var stoppedSnap engine.MobileSnapshot
	if err := json.Unmarshal([]byte(GetSnapshotJSON()), &stoppedSnap); err != nil {
		t.Fatalf("MT-16 unmarshal stopped snapshot: %v", err)
	}
	if stoppedSnap.State != engine.CtrlStopped {
		t.Fatalf("MT-16 expected STOPPED state, got %s", stoppedSnap.State)
	}
	if stoppedSnap.GuardCalls5Min < beforeCalls+1 {
		t.Fatalf("MT-16 expected stopped snapshot GuardCalls5Min >= %d, got %d", beforeCalls+1, stoppedSnap.GuardCalls5Min)
	}

	// Logs MUST still be readable while STOPPED (BUG-G06).
	var stoppedLogs []engine.TerminalLine
	_ = json.Unmarshal([]byte(GetLogsJSON(0)), &stoppedLogs)
	if len(stoppedLogs) == 0 {
		t.Fatal("MT-16 expected GetLogsJSON(0) preserved while STOPPED")
	}

	// Concurrent Start() calls serialized cleanly via lifecycleMu (BUG-G04) + monotonic seq across Stop()->Start().
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = Start(cfgJSON, nil)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("MT-16 concurrent Start[%d] failed: %v", i, e)
		}
	}

	dl2 := time.Now().Add(3 * time.Second)
	for time.Now().Before(dl2) {
		var snap engine.MobileSnapshot
		_ = json.Unmarshal([]byte(GetSnapshotJSON()), &snap)
		if snap.State == engine.CtrlRunning {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	var deltaLogs []engine.TerminalLine
	_ = json.Unmarshal([]byte(GetLogsJSON(lastSeqBeforeStop)), &deltaLogs)
	if len(deltaLogs) == 0 || deltaLogs[0].Seq <= lastSeqBeforeStop {
		t.Fatalf("MT-16 expected strictly monotonic seq > %d after restart, got %+v", lastSeqBeforeStop, deltaLogs)
	}
}

// =============================================================================
// MT-17: Uninterruptible Boot-Time SSH Hang Cancellation via context.AfterFunc (BUG-G07)
// =============================================================================
func TestMT17_DevTunnelBootCancelInterruptsHungSSH(t *testing.T) {
	wsHeld := make(chan struct{})
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/user/codespaces/mt17-hang"):
			hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
			pay := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(1*time.Hour).Unix())))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":  "mt17-hang",
				"state": "Available",
				"connection": map[string]any{
					"tunnelProperties": map[string]any{
						"connectAccessToken":     hdr + "." + pay + ".sig",
						"managePortsAccessToken": "mgt",
						"serviceUri":             srv.URL,
						"tunnelId":               "t-mt17",
						"clusterId":              "c-mt17",
						"domain":                 "devtunnels.ms",
					},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/tunnels/t-mt17"):
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tunnelId":  "t-mt17",
				"clusterId": "c-mt17",
				"endpoints": []map[string]any{{
					"id":             "ep1",
					"connectionMode": "Relay",
					"clientRelayUri": wsURL,
				}},
			})
		case r.URL.Path == "/relay":
			wc, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return
			}
			defer wc.CloseNow()
			// Hold WebSocket silent indefinitely to simulate 15s CG-NAT SSH handshake stall.
			select {
			case <-wsHeld:
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer func() {
		close(wsHeld)
		srv.Close()
	}()

	cfg := engine.DefaultConfig()
	cfg.CodespaceName = "mt17-hang"
	cfg.GitHubToken = "gho_mt17"
	cfg.GitHubAPIBaseURL = srv.URL
	cfg.GitHubMinCallSpacing = 0

	res := engine.NewAntiPoisonResolver(nil, nil)
	guard := engine.NewGitHubGuard(cfg, nil, nil)
	api := engine.NewGitHubAPIClient(srv.URL, srv.URL, res, guard)
	creds := engine.NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	tr := engine.NewDevTunnelSSHTransport(cfg, creds, res, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	t0 := time.Now()
	sess, err := tr.Connect(ctx, "tunnel-1")
	elapsed := time.Since(t0)
	if err == nil {
		_ = sess.Close()
		t.Fatal("MT-17 expected Connect to abort on hung SSH handshake when boot ctx cancels")
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("MT-17 Connect took %v (>1.2s) instead of aborting promptly when boot ctx canceled", elapsed)
	}
}

// =============================================================================
// MT-18: Dead DoH Fast-Fail Skips Redundant AAAA & NAT64/FakeDNS Rejection (BUG-G08, BUG-G05)
// =============================================================================
func TestMT18_DeadDoHSkipsAAAARedundancyAndRejectsNAT64FakeDNS(t *testing.T) {
	var deadHits atomic.Int32
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		deadHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer deadSrv.Close()

	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		if len(q) < 12 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := append([]byte(nil), q...)
		resp[2] = 0x81
		resp[3] = 0x80
		binary.BigEndian.PutUint16(resp[6:8], 1)
		resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 140, 82, 121, 4)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer healthySrv.Close()

	poisonedSys := func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("64:ff9b::0a0a:2223")}, nil
	}
	res := engine.NewAntiPoisonResolver([]string{deadSrv.URL, healthySrv.URL}, poisonedSys)
	ips, usedDoH, err := res.ResolveHost(context.Background(), "api.github.com")
	if err != nil || !usedDoH || len(ips) == 0 || ips[0].String() != "140.82.121.4" {
		t.Fatalf("MT-18 failover failed: ips=%v usedDoH=%v err=%v", ips, usedDoH, err)
	}
	if deadHits.Load() != 1 {
		t.Fatalf("MT-18 expected exactly 1 DoH request (skipping redundant AAAA on dead HTTP 503 endpoint), got %d", deadHits.Load())
	}

	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"10.10.34.34", true},
		{"64:ff9b::0a0a:2222", true},
		{"64:ff9b::0a0a:2223", true},
		{"198.18.0.1", true},
		{"198.19.255.254", true},
		{"192.0.2.1", true},
		{"64:ff9b::1478:380b", false},
		{"140.82.121.4", false},
	} {
		if got := engine.IsPoisonedPublicIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Fatalf("MT-18 IsPoisonedPublicIP(%q)=%v, want %v", tc.ip, got, tc.want)
		}
	}
}
