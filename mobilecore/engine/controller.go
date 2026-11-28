package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ControllerState string

const (
	CtrlStopped       ControllerState = "STOPPED"
	CtrlStarting      ControllerState = "STARTING"
	CtrlRunning       ControllerState = "RUNNING"
	CtrlDegraded      ControllerState = "DEGRADED"
	CtrlPausedOffline ControllerState = "PAUSED_OFFLINE"
	CtrlStopping      ControllerState = "STOPPING"
)

var codespaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$`)

func ValidateCodespaceName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("codespace name cannot be empty")
	}
	if trimmed != name {
		return errors.New("codespace name must not have leading or trailing whitespace")
	}
	if strings.HasPrefix(trimmed, "-") {
		return errors.New("codespace name must not start with '-'")
	}
	if !codespaceNameRe.MatchString(trimmed) {
		return errors.New("codespace name must be 2..128 alphanumeric/._- characters")
	}
	return nil
}

// MobileSnapshot is the immutable JSON contract returned wait-free by mobilecore.GetSnapshotJSON().
type MobileSnapshot struct {
	CoreVersion         string           `json:"core_version"`
	State               ControllerState  `json:"state"`
	SupervisorState     SupervisorState  `json:"supervisor_state"`
	PowerState          PowerState       `json:"power_state"`
	CodespaceName       string           `json:"codespace_name"`
	LocalHost           string           `json:"local_host"`
	LocalPort           int              `json:"local_port"`
	LocalAddr           string           `json:"local_addr"`
	V2RayNGURI          string           `json:"v2rayng_uri"`
	NetworkType         string           `json:"network_type"`
	IsMetered           bool             `json:"is_metered"`
	AppInForeground     bool             `json:"app_in_foreground"`
	PoolSize            int              `json:"pool_size"`
	HealthyWorkers      int              `json:"healthy_workers"`
	DegradedWorkers     int              `json:"degraded_workers"`
	ParkedWorkers       int              `json:"parked_workers"`
	RoutingMode         string           `json:"routing_mode"`
	PrimaryTunnelID     string           `json:"primary_tunnel_id"`
	LatencyP50MS        float64          `json:"latency_p50_ms"`
	UnderlayMS          float64          `json:"underlay_ms"`
	ActiveConns         int64            `json:"active_conns"`
	PeakConns           int64            `json:"peak_conns"`
	MaxActiveConns      int              `json:"max_active_conns"`
	QueuedConns         int64            `json:"queued_conns"`
	SemaphoreRejects    uint64           `json:"semaphore_rejects"`
	BytesUp             uint64           `json:"bytes_up"`
	BytesDown           uint64           `json:"bytes_down"`
	UptimeSec           int64            `json:"uptime_sec"`
	GuardCalls5Min      int              `json:"guard_calls_5m"`
	GuardMax5Min        int              `json:"guard_max_5m"`
	GuardCallsHour      int              `json:"guard_calls_hour"`
	GuardMaxHour        int              `json:"guard_max_hour"`
	GuardCooldownMS     int64            `json:"guard_cooldown_ms"`
	GuardBudgetWaitMS   int64            `json:"guard_budget_wait_ms"`
	GuardThrottleWaitMS int64            `json:"guard_throttle_wait_ms"`
	GuardThrottleReason string           `json:"guard_throttle_reason,omitempty"`
	GuardRateLimits     int64            `json:"guard_rate_limits"`
	Workers             []TunnelSnapshot `json:"workers"`
	LastError           string           `json:"last_error,omitempty"`
}

// BuildV2RayNGProfileURI formats a standard no-auth SOCKS5 profile URI compatible with v2rayNG SocksFmt.
func BuildV2RayNGProfileURI(host string, port uint16) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = DefaultLocalHost
	}
	if port == 0 {
		port = DefaultLocalPort
	}
	return fmt.Sprintf("socks://%s#NetShaper", net.JoinHostPort(host, strconv.Itoa(int(port))))
}

type ControllerCallbacks struct {
	OnStateChange func(state, detail string)
	OnLogLine     func(seq int64, level, text string)
	OnError       func(code, message string)
}

type ControllerOverrides struct {
	TransportFactory func(cfg Config, creds *CredentialManager, resolver *AntiPoisonResolver, hb *HeartbeatCoordinator, logger *EventLogger) WorkerTransport
	StopCodespace    func(ctx context.Context, cfg Config) error
	PoolHooks        PoolHooks
	Resolver         *AntiPoisonResolver
	APIClient        *GitHubAPIClient
	Guard            *GitHubGuard
	Logs             *TerminalRingBuffer
	SnapshotInterval time.Duration
}

// SessionController owns the serialized mobile engine lifecycle, wait-free atomic snapshots,
// trailing-edge network handover debouncing (1500ms), and foreground/background telemetry throttling.
type SessionController struct {
	cfg       Config
	callbacks ControllerCallbacks
	overrides ControllerOverrides
	guard     *GitHubGuard
	resolver  *AntiPoisonResolver
	apiClient *GitHubAPIClient
	logs      *TerminalRingBuffer

	mu              sync.RWMutex
	ctrlState       ControllerState
	lastErr         string
	sessionAt       time.Time
	networkType     string
	isMetered       bool
	appInForeground atomic.Bool

	runMu           sync.Mutex
	activeSupRef    *Supervisor
	activeRunCancel context.CancelFunc
	activeHB        *HeartbeatCoordinator

	// Trailing-edge network handover debouncer.
	netMu                       sync.Mutex
	netDebounceTimer            *time.Timer
	netPendingType              string
	netPendingMeter             bool
	netLastApplied              string
	netHasApplied               bool
	netSawOfflineDuringDebounce bool
	netSameTypeRefreshPending   bool

	activeSup   atomic.Pointer[Supervisor]
	latestSnap  atomic.Pointer[MobileSnapshot]
	shuttingDwn atomic.Bool
	runDoneCh   chan struct{}

	stopCtx    context.Context
	stopCancel context.CancelFunc
	wg         sync.WaitGroup
	startOnce  sync.Once
	stopOnce   sync.Once
}

func NewSessionController(cfg Config, cb ControllerCallbacks, overrides ControllerOverrides) *SessionController {
	resolver := overrides.Resolver
	if resolver == nil {
		resolver = NewAntiPoisonResolver(nil, nil)
	}
	guard := overrides.Guard
	if guard == nil {
		guard = NewGitHubGuard(cfg, nil, nil)
	}
	apiClient := overrides.APIClient
	if apiClient == nil {
		apiClient = NewGitHubAPIClient(cfg.GitHubAPIBaseURL, cfg.GitHubOAuthBaseURL, resolver, guard)
	}
	logs := overrides.Logs
	if logs == nil {
		logs = NewTerminalRingBuffer()
	}
	if overrides.SnapshotInterval <= 0 {
		overrides.SnapshotInterval = 1 * time.Second
	}
	stopCtx, stopCancel := context.WithCancel(context.Background())
	c := &SessionController{
		cfg:         cfg,
		callbacks:   cb,
		overrides:   overrides,
		guard:       guard,
		resolver:    resolver,
		apiClient:   apiClient,
		logs:        logs,
		ctrlState:   CtrlStopped,
		networkType: "unknown",
		runDoneCh:   make(chan struct{}),
		stopCtx:     stopCtx,
		stopCancel:  stopCancel,
	}
	c.appInForeground.Store(true)
	c.logs.SetListener(func(ln TerminalLine) {
		if c.appInForeground.Load() && c.callbacks.OnLogLine != nil {
			c.callbacks.OnLogLine(ln.Seq, ln.Level, ln.Text)
		}
	})
	c.publishSnapshotNow()
	return c
}

func (c *SessionController) Guard() *GitHubGuard       { return c.guard }
func (c *SessionController) Logs() *TerminalRingBuffer { return c.logs }

func (c *SessionController) Snapshot() MobileSnapshot {
	if p := c.latestSnap.Load(); p != nil {
		return *p
	}
	return MobileSnapshot{
		CoreVersion: CoreVersionString,
		State:       CtrlStopped,
		LocalHost:   c.cfg.LocalHost,
		LocalPort:   int(c.cfg.LocalPort),
		LocalAddr:   c.cfg.LocalAddr(),
		V2RayNGURI:  BuildV2RayNGProfileURI(c.cfg.LocalHost, c.cfg.LocalPort),
	}
}

func (c *SessionController) SnapshotJSON() string {
	b, err := json.Marshal(c.Snapshot())
	if err != nil {
		return `{"state":"ERROR"}`
	}
	return string(b)
}

func (c *SessionController) LogsJSON(sinceSeq int64) string {
	lines := c.logs.Since(sinceSeq)
	if lines == nil {
		lines = []TerminalLine{}
	}
	b, err := json.Marshal(lines)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func (c *SessionController) SetAppForeground(inForeground bool) {
	c.appInForeground.Store(inForeground)
	c.publishSnapshotNow()
}

// NotifyNetworkChange debounces Android ConnectivityManager flaps (1500ms trailing-edge default).
func (c *SessionController) NotifyNetworkChange(networkType string, isMetered bool) {
	if c.shuttingDwn.Load() {
		return
	}
	nt := strings.ToLower(strings.TrimSpace(networkType))
	if nt == "" {
		nt = "unknown"
	}
	debounce := c.cfg.NetworkDebounceInterval
	if debounce <= 0 {
		debounce = DefaultNetworkDebounceInterval
	}

	c.netMu.Lock()
	c.netPendingType = nt
	c.netPendingMeter = isMetered
	if nt == "none" {
		c.netSawOfflineDuringDebounce = true
		c.netSameTypeRefreshPending = false
	} else if c.netHasApplied && c.netLastApplied == nt {
		c.netSameTypeRefreshPending = true
	}
	if c.netDebounceTimer != nil {
		c.netDebounceTimer.Stop()
	}
	c.netDebounceTimer = time.AfterFunc(debounce, func() {
		c.applyDebouncedNetworkChange()
	})
	c.netMu.Unlock()
}

func (c *SessionController) applyDebouncedNetworkChange() {
	if c.shuttingDwn.Load() {
		return
	}
	c.netMu.Lock()
	if c.shuttingDwn.Load() {
		c.netMu.Unlock()
		return
	}
	nt := c.netPendingType
	metered := c.netPendingMeter
	prev := c.netLastApplied
	wasApplied := c.netHasApplied
	sawOffline := c.netSawOfflineDuringDebounce
	sameTypeRefresh := c.netSameTypeRefreshPending
	c.netLastApplied = nt
	c.netHasApplied = true
	c.netSawOfflineDuringDebounce = false
	c.netSameTypeRefreshPending = false
	c.netMu.Unlock()

	c.mu.Lock()
	c.networkType = nt
	c.isMetered = metered
	c.mu.Unlock()

	c.resolver.FlushCache()
	sup := c.activeSup.Load()
	if sup != nil {
		sup.SetNetworkInfo(nt, metered)
	}

	if nt == "none" {
		if !wasApplied || prev != "none" {
			c.logs.Append(LogWarn, "[Net] Connectivity lost — entering PAUSED_OFFLINE (0 API calls)")
		}
		if sup != nil {
			sup.SetPausedOffline(true)
		}
		c.setCtrlState(CtrlPausedOffline, "network_offline")
		return
	}

	needHandover := false
	switch {
	case prev == "none":
		c.logs.Append(LogSuccess, fmt.Sprintf("[Net] Connectivity restored (%s) — resuming tunnels", nt))
		needHandover = true
	case sawOffline:
		c.logs.Append(LogInfo, fmt.Sprintf("[Net] Brief connectivity dropout recovered (%s) — refreshing sockets & underlay", nt))
		needHandover = true
	case prev != "" && prev != nt:
		c.logs.Append(LogInfo, fmt.Sprintf("[Net] Handover %s -> %s — resetting underlay & refreshing sockets", prev, nt))
		needHandover = true
	case sameTypeRefresh:
		c.logs.Append(LogInfo, fmt.Sprintf("[Net] Interface refreshed (%s) — resetting underlay & refreshing sockets", nt))
		needHandover = true
	}

	if needHandover {
		c.apiClient.CloseIdleConnections()
		c.resolver.CloseIdleConnections()
		if sup != nil {
			sup.NotifyHandover()
		}
		c.mu.RLock()
		stillPaused := c.ctrlState == CtrlPausedOffline
		c.mu.RUnlock()
		if stillPaused {
			c.setCtrlState(CtrlStarting, "network_restored")
		}
		c.publishSnapshotNow()
	}
}

func (c *SessionController) setCtrlState(st ControllerState, detail string) {
	c.mu.Lock()
	changed := c.ctrlState != st
	c.ctrlState = st
	c.mu.Unlock()
	c.publishSnapshotNow()
	if changed && c.callbacks.OnStateChange != nil {
		c.callbacks.OnStateChange(string(st), detail)
	}
}

// Start launches the supervised mobile engine asynchronously and begins 1Hz wait-free snapshot publishing.
func (c *SessionController) Start() {
	c.startOnce.Do(func() {
		c.wg.Add(2)
		safeGo(nil, "ctrl_lifecycle", c.runSession)
		safeGo(nil, "ctrl_snapshot_pub", c.snapshotPublisher)
	})
}

func (c *SessionController) runSession() {
	defer c.wg.Done()
	defer close(c.runDoneCh)

	c.setCtrlState(CtrlStarting, "booting")
	c.guard.ClearSessionStopped()

	logPath := ""
	metricsPath := ""
	if strings.TrimSpace(c.cfg.DataDir) != "" {
		logPath = filepath.Join(c.cfg.DataDir, DefaultLogFileName)
		if c.cfg.EnableMetricsLog {
			metricsPath = filepath.Join(c.cfg.DataDir, DefaultMetricsFileName)
		}
	}
	eventLogger, err := NewEventLoggerWithArchive(logPath, c.cfg.MaxLogFileBytes, c.cfg.MaxArchiveTotalBytes, c.cfg.LogClusterWindow)
	if err != nil {
		// Fall back cleanly to observer-only in-memory logging rather than failing start.
		eventLogger, _ = NewEventLoggerWithArchive("", c.cfg.MaxLogFileBytes, c.cfg.MaxArchiveTotalBytes, c.cfg.LogClusterWindow)
	}
	eventLogger.SetObserver(func(rec LogRecord) {
		sev, line := FormatLogRecord(rec)
		ts := time.Now()
		if rec.UnixMS > 0 {
			ts = time.UnixMilli(rec.UnixMS)
		}
		c.logs.AppendAt(ts, sev, line)
	})

	var metricsEmitter *MetricsEmitter
	if metricsPath != "" {
		if m, merr := NewMetricsEmitter(metricsPath, eventLogger.SessionID()); merr == nil {
			metricsEmitter = m
		}
	}
	c.guard.SetSinks(eventLogger, metricsEmitter)
	defer c.guard.SetSinks(nil, nil)

	hb := NewHeartbeatCoordinator(time.Duration(c.cfg.SSHServerAliveInterval) * time.Second)
	creds := NewCredentialManager(c.apiClient, c.cfg.GitHubToken, c.cfg.CodespaceName)
	creds.SetLogger(eventLogger)

	var transport WorkerTransport
	if c.overrides.TransportFactory != nil {
		transport = c.overrides.TransportFactory(c.cfg, creds, c.resolver, hb, eventLogger)
	} else {
		transport = NewDevTunnelSSHTransport(c.cfg, creds, c.resolver, hb, eventLogger)
	}

	stopFn := c.overrides.StopCodespace
	if stopFn == nil {
		stopFn = func(sctx context.Context, cfg Config) error {
			return c.apiClient.StopCodespace(sctx, cfg.GitHubToken, cfg.CodespaceName)
		}
	}

	hooks := c.overrides.PoolHooks
	if hooks.UnderlayProbeFunc == nil && c.overrides.TransportFactory == nil {
		hooks.UnderlayProbeFunc = MeasureUnderlayBaseline
	}

	sup := NewSupervisor(c.cfg, eventLogger, SupervisorDeps{
		Transport:     transport,
		StopCodespace: stopFn,
		PoolHooks:     hooks,
		Metrics:       metricsEmitter,
		GitHubGuard:   c.guard,
		OnStateChange: func(_, to SupervisorState) {
			switch to {
			case StateHealthy:
				c.mu.Lock()
				if c.sessionAt.IsZero() {
					c.sessionAt = time.Now()
				}
				c.mu.Unlock()
				c.setCtrlState(CtrlRunning, "healthy")
			case StateDegraded:
				c.setCtrlState(CtrlDegraded, "degraded")
			case StatePausedOffline:
				c.setCtrlState(CtrlPausedOffline, "offline")
			case StateShutdown:
				c.setCtrlState(CtrlStopping, "shutdown")
			default:
				if !c.shuttingDwn.Load() {
					c.setCtrlState(CtrlStarting, string(to))
				}
			}
		},
	})
	c.mu.RLock()
	initNT, initMetered := c.networkType, c.isMetered
	c.mu.RUnlock()
	if initNT == "" || initNT == "unknown" {
		c.netMu.Lock()
		if c.netPendingType != "" {
			initNT = c.netPendingType
			initMetered = c.netPendingMeter
		}
		c.netMu.Unlock()
	}
	sup.SetNetworkInfo(initNT, initMetered)

	runCtx, runCancel := context.WithCancel(context.Background())
	c.runMu.Lock()
	c.activeSupRef = sup
	c.activeRunCancel = runCancel
	c.activeHB = hb
	c.runMu.Unlock()
	c.activeSup.Store(sup)

	if c.shuttingDwn.Load() {
		sup.RequestShutdown("stop_before_run")
		runCancel()
	}

	runErr := sup.Run(runCtx)
	runCancel()
	hb.Close()

	c.runMu.Lock()
	c.activeSupRef = nil
	c.activeRunCancel = nil
	c.activeHB = nil
	c.runMu.Unlock()
	c.activeSup.Store(nil)

	if runErr != nil && !c.shuttingDwn.Load() {
		c.mu.Lock()
		c.lastErr = RedactSecrets(runErr.Error())
		c.mu.Unlock()
		code := "runtime_error"
		var fe *FatalBootError
		if errors.As(runErr, &fe) {
			code = fe.Code
		}
		if c.callbacks.OnError != nil {
			c.callbacks.OnError(code, RedactSecrets(runErr.Error()))
		}
	}

	c.mu.Lock()
	c.sessionAt = time.Time{}
	c.mu.Unlock()
	c.setCtrlState(CtrlStopped, "stopped")
}

func (c *SessionController) snapshotPublisher() {
	defer c.wg.Done()
	nextSnapInterval := func() time.Duration {
		interval := c.overrides.SnapshotInterval
		if !c.appInForeground.Load() && interval < 15*time.Second {
			// Background screen-off telemetry throttle to hit 240 wakeups/hr (event callbacks fire immediately on transition).
			interval = 15 * time.Second
		}
		return interval
	}
	tm := time.NewTimer(nextSnapInterval())
	defer tm.Stop()
	for {
		select {
		case <-c.stopCtx.Done():
			return
		case <-tm.C:
			c.publishSnapshotNow()
			tm.Reset(nextSnapInterval())
		}
	}
}

func (c *SessionController) publishSnapshotNow() {
	c.mu.RLock()
	st := c.ctrlState
	lastErr := c.lastErr
	sessAt := c.sessionAt
	nt := c.networkType
	metered := c.isMetered
	c.mu.RUnlock()

	var uptimeSec int64
	if !sessAt.IsZero() && (st == CtrlRunning || st == CtrlDegraded) {
		if d := time.Since(sessAt); d > 0 {
			uptimeSec = int64(d.Seconds())
		}
	}

	localHost := c.cfg.LocalHost
	localPort := c.cfg.LocalPort
	localAddr := c.cfg.LocalAddr()

	snap := MobileSnapshot{
		CoreVersion:     CoreVersionString,
		State:           st,
		SupervisorState: StateShutdown,
		PowerState:      PowerActive,
		CodespaceName:   c.cfg.CodespaceName,
		LocalHost:       localHost,
		LocalPort:       int(localPort),
		LocalAddr:       localAddr,
		V2RayNGURI:      BuildV2RayNGProfileURI(localHost, localPort),
		NetworkType:     nt,
		IsMetered:       metered,
		AppInForeground: c.appInForeground.Load(),
		PoolSize:        c.cfg.PoolSize,
		MaxActiveConns:  c.cfg.MaxActiveConns,
		UptimeSec:       uptimeSec,
		LastError:       lastErr,
		Workers:         []TunnelSnapshot{},
	}

	if c.guard != nil {
		gs := c.guard.CachedSnapshot()
		snap.GuardCalls5Min = gs.CallsLast5Min
		snap.GuardMax5Min = gs.MaxCallsPer5Min
		snap.GuardCallsHour = gs.CallsLastHour
		snap.GuardMaxHour = gs.MaxCallsPerHour
		snap.GuardCooldownMS = gs.CooldownRemainingMS
		snap.GuardBudgetWaitMS = gs.BudgetWaitMS
		snap.GuardThrottleWaitMS = gs.ThrottleWaitMS
		snap.GuardThrottleReason = gs.ThrottleReason
		snap.GuardRateLimits = gs.RateLimitHits
	}

	if sup := c.activeSup.Load(); sup != nil {
		snap.SupervisorState = sup.AtomicState()
		if ba := sup.AtomicBoundLocalAddr(); ba != "" {
			snap.LocalAddr = ba
			if h, p, err := splitHostPortUint16(ba); err == nil {
				snap.LocalHost = h
				snap.LocalPort = int(p)
				snap.V2RayNGURI = BuildV2RayNGProfileURI(h, p)
			}
		}
		pt := sup.AtomicProxyTelemetry()
		snap.ActiveConns = pt.ActiveConns
		snap.PeakConns = pt.PeakConns
		snap.QueuedConns = pt.QueuedConns
		snap.SemaphoreRejects = pt.SemaphoreRejects
		snap.BytesUp = pt.TotalBytesUp
		snap.BytesDown = pt.TotalBytesDown

		ps := sup.AtomicPoolSnapshot()
		if ps.PoolSize > 0 {
			snap.PoolSize = ps.PoolSize
		}
		snap.PowerState = ps.PowerState
		snap.HealthyWorkers = ps.HealthyWorkers
		snap.DegradedWorkers = ps.DegradedWorkers
		snap.ParkedWorkers = ps.ParkedWorkers
		snap.RoutingMode = ps.RoutingMode
		snap.PrimaryTunnelID = ps.PrimaryTunnelID
		snap.LatencyP50MS = ps.AggregateP50MS
		snap.UnderlayMS = ps.UnderlayBaselineMS
		if len(ps.Workers) > 0 {
			snap.Workers = make([]TunnelSnapshot, len(ps.Workers))
			copy(snap.Workers, ps.Workers)
		}
	}

	c.latestSnap.Store(&snap)
}

// StopAndWait performs an idempotent, bounded ordered shutdown with 0 leaked goroutines.
func (c *SessionController) StopAndWait(timeout time.Duration) {
	c.stopOnce.Do(func() {
		c.shuttingDwn.Store(true)
		c.netMu.Lock()
		if c.netDebounceTimer != nil {
			c.netDebounceTimer.Stop()
			c.netDebounceTimer = nil
		}
		c.netMu.Unlock()

		c.runMu.Lock()
		sup := c.activeSupRef
		cancel := c.activeRunCancel
		c.runMu.Unlock()
		if sup != nil {
			sup.RequestShutdown("mobile_stop")
		}
		if cancel != nil {
			cancel()
		}
		c.stopCancel()

		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()
		if timeout <= 0 {
			timeout = c.cfg.StopTimeout + 4*time.Second
		}
		select {
		case <-done:
		case <-time.After(timeout):
		}
		c.logs.SetListener(nil)
		c.apiClient.CloseIdleConnections()
		c.resolver.CloseIdleConnections()
		c.publishSnapshotNow()
	})
}
