package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type SupervisorState string

const (
	StateInit          SupervisorState = "INIT"
	StateStarting      SupervisorState = "STARTING_TUNNELS"
	StateProbing       SupervisorState = "PROBING_E2E"
	StateHealthy       SupervisorState = "HEALTHY"
	StateDegraded      SupervisorState = "DEGRADED"
	StatePausedOffline SupervisorState = "PAUSED_OFFLINE"
	StateReconnecting  SupervisorState = "RECONNECTING"
	StateShutdown      SupervisorState = "SHUTDOWN"
)

func ComputeBackoff(attempt int, minD, maxD time.Duration, rng *rand.Rand) time.Duration {
	if minD <= 0 {
		minD = 2 * time.Second
	}
	if maxD < minD {
		maxD = minD
	}
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 10 {
		shift = 10
	}
	base := float64(minD) * math.Pow(2, float64(shift))
	if base > float64(maxD) {
		base = float64(maxD)
	}
	var u float64
	if rng != nil {
		u = rng.Float64()
	} else {
		u = rand.Float64()
	}
	jittered := base * (0.8 + 0.4*u)
	if jittered < float64(minD) {
		jittered = float64(minD)
	}
	if jittered > float64(maxD) {
		jittered = float64(maxD)
	}
	return time.Duration(jittered)
}

type SupervisorDeps struct {
	Transport     WorkerTransport
	StopCodespace func(ctx context.Context, cfg Config) error
	PoolHooks     PoolHooks
	Metrics       *MetricsEmitter
	GitHubGuard   *GitHubGuard
	OnStateChange func(from, to SupervisorState)
}

type Supervisor struct {
	cfg     Config
	deps    SupervisorDeps
	logger  *EventLogger
	metrics *MetricsEmitter
	guard   *GitHubGuard

	stateMu        sync.RWMutex
	state          SupervisorState
	stateShadow    atomic.Pointer[SupervisorState]
	sessionStart   time.Time
	everHealthy    atomic.Bool
	vmWoken        atomic.Bool
	fatalBootAbort atomic.Bool
	pausedOffline  atomic.Bool

	poolMu        sync.Mutex
	activePool    *TunnelPool
	activePoolPtr atomic.Pointer[TunnelPool]

	proxyMu        sync.Mutex
	activeProxy    *ProxyServer
	boundAddr      string
	activeProxyPtr atomic.Pointer[ProxyServer]
	boundAddrPtr   atomic.Pointer[string]

	closedBytesUp   atomic.Uint64
	closedBytesDown atomic.Uint64
	networkTypePtr  atomic.Pointer[string]
	isMetered       atomic.Bool

	shutdownMu     sync.Mutex
	shutdownReason string
	shutdownOnce   sync.Once
	cancelMain     context.CancelFunc
}

func NewSupervisor(cfg Config, logger *EventLogger, deps SupervisorDeps) *Supervisor {
	guard := deps.GitHubGuard
	if guard == nil {
		guard = NewGitHubGuard(cfg, logger, deps.Metrics)
	}
	s := &Supervisor{
		cfg:          cfg,
		deps:         deps,
		logger:       logger,
		metrics:      deps.Metrics,
		guard:        guard,
		state:        StateInit,
		sessionStart: time.Now(),
	}
	initSt := StateInit
	s.stateShadow.Store(&initSt)
	return s
}

func (s *Supervisor) State() SupervisorState {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

func (s *Supervisor) AtomicState() SupervisorState {
	if s == nil {
		return StateShutdown
	}
	if p := s.stateShadow.Load(); p != nil {
		return *p
	}
	return StateInit
}

func (s *Supervisor) AtomicBoundLocalAddr() string {
	if s == nil {
		return ""
	}
	if p := s.boundAddrPtr.Load(); p != nil {
		return *p
	}
	return ""
}

func (s *Supervisor) AtomicProxyTelemetry() ProxyAtomicSnapshot {
	if s == nil {
		return ProxyAtomicSnapshot{}
	}
	if p := s.activeProxyPtr.Load(); p != nil {
		return p.AtomicTelemetry()
	}
	return ProxyAtomicSnapshot{}
}

func (s *Supervisor) AtomicPoolSnapshot() PoolSnapshot {
	if s == nil {
		return PoolSnapshot{}
	}
	if p := s.activePoolPtr.Load(); p != nil {
		return p.CachedSnapshot()
	}
	return PoolSnapshot{PoolSize: s.cfg.PoolSize, PowerState: PowerActive}
}

func (s *Supervisor) setState(next SupervisorState) {
	s.stateMu.Lock()
	prev := s.state
	if prev == next {
		s.stateMu.Unlock()
		return
	}
	s.state = next
	cp := next
	s.stateShadow.Store(&cp)
	if next == StateHealthy {
		s.everHealthy.Store(true)
	}
	s.stateMu.Unlock()

	if s.logger != nil {
		s.logger.Log("STATE_TRANSITION", map[string]any{
			"from": string(prev),
			"to":   string(next),
		})
	}
	if s.deps.OnStateChange != nil {
		s.deps.OnStateChange(prev, next)
	}
}

func (s *Supervisor) RequestShutdown(reason string) {
	s.shutdownMu.Lock()
	if s.shutdownReason == "" {
		s.shutdownReason = reason
	}
	cancel := s.cancelMain
	s.shutdownMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Supervisor) SetPausedOffline(offline bool) {
	s.pausedOffline.Store(offline)
	if pool := s.activePoolPtr.Load(); pool != nil {
		pool.SetPausedOffline(offline)
	}
	if offline {
		s.setState(StatePausedOffline)
	}
}

func (s *Supervisor) NotifyHandover() {
	s.pausedOffline.Store(false)
	if s.State() == StatePausedOffline {
		s.setState(StateProbing)
	}
	if pool := s.activePoolPtr.Load(); pool != nil {
		pool.SetPausedOffline(false)
		pool.ForceReconnectForHandover()
	}
}

func (s *Supervisor) SetNetworkInfo(networkType string, isMetered bool) {
	if s == nil {
		return
	}
	nt := networkType
	if nt == "" {
		nt = "unknown"
	}
	s.networkTypePtr.Store(&nt)
	s.isMetered.Store(isMetered)
}

func (s *Supervisor) emitPoolSummary(proxy *ProxyServer, pool *TunnelPool) {
	if s == nil || s.logger == nil {
		return
	}
	st := proxy.SnapshotWindow(true)
	ps := pool.PoolSnapshot()
	var gs GitHubGuardSnapshot
	if s.guard != nil {
		gs = s.guard.CachedSnapshot()
	}
	netType := "unknown"
	if ptr := s.networkTypePtr.Load(); ptr != nil && *ptr != "" {
		netType = *ptr
	}

	var healthyRTTs []float64
	for _, w := range ps.Workers {
		if w.State == TunnelHealthy && w.EWMARTTMS > 0 {
			healthyRTTs = append(healthyRTTs, w.EWMARTTMS)
		}
	}
	var p95MS, p99MS float64
	if len(healthyRTTs) > 0 {
		sort.Float64s(healthyRTTs)
		_, _, p95MS, p99MS = computeRTTStats(healthyRTTs)
	}

	fields := map[string]any{
		"state":                string(s.AtomicState()),
		"power_state":          string(ps.PowerState),
		"routing_mode":         ps.RoutingMode,
		"primary_tunnel":       ps.PrimaryTunnelID,
		"healthy_workers":      ps.HealthyWorkers,
		"parked_workers":       ps.ParkedWorkers,
		"pool_size":            ps.PoolSize,
		"active_conns":         st.ActiveConns,
		"peak_conns":           st.PeakConns,
		"queued_conns":         st.QueuedConns,
		"bytes_up_window":      st.BytesUpWindow,
		"bytes_down_window":    st.BytesDownWindow,
		"total_bytes_up":       s.closedBytesUp.Load() + st.TotalBytesUp,
		"total_bytes_down":     s.closedBytesDown.Load() + st.TotalBytesDown,
		"aggregate_p50_ms":     ps.AggregateP50MS,
		"rtt_p95_ms":           round2(p95MS),
		"rtt_p99_ms":           round2(p99MS),
		"underlay_baseline_ms": ps.UnderlayBaselineMS,
		"network_type":         netType,
		"is_metered":           s.isMetered.Load(),
		"primary_switches":     ps.PrimarySwitches,
		"slow_lane_evictions":  ps.SlowLaneEvictions,
		"total_failovers":      ps.TotalFailovers,
		"dial_ok_window":       st.DialOK,
		"dial_fail_window":     st.DialFail,
		"waf_5m":               gs.CallsLast5Min,
		"waf_max_5m":           gs.MaxCallsPer5Min,
		"waf_1h":               gs.CallsLastHour,
		"waf_max_1h":           gs.MaxCallsPerHour,
		"waf_cooldown_ms":      gs.CooldownRemainingMS,
		"goroutines":           runtime.NumGoroutine(),
	}
	for i, w := range ps.Workers {
		prefix := fmt.Sprintf("t%d_", i+1)
		fields[prefix+"state"] = string(w.State)
		fields[prefix+"rtt_ms"] = w.EWMARTTMS
		fields[prefix+"jitter_ms"] = w.EWMAJitterMS
		fields[prefix+"err_rate"] = w.StreamErrorRate
		fields[prefix+"rho"] = w.RelativeRho
		fields[prefix+"active"] = w.ActiveStreams
		fields[prefix+"pmtu576"] = w.PMTU576Active
		fields[prefix+"wan"] = RedactSecrets(w.WANRemote)
	}
	s.logger.Log("POOL_SUMMARY", fields)
}

func (s *Supervisor) Run(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	s.shutdownMu.Lock()
	s.cancelMain = cancel
	alreadyRequested := s.shutdownReason != ""
	s.shutdownMu.Unlock()
	if alreadyRequested {
		cancel()
	}
	defer cancel()

	s.setState(StateInit)
	if s.logger != nil {
		s.logger.Log("SESSION_START", map[string]any{
			"version":    CoreVersionString,
			"codespace":  s.cfg.CodespaceName,
			"local_addr": s.cfg.LocalAddr(),
			"pool_size":  s.cfg.PoolSize,
			"max_conns":  s.cfg.MaxActiveConns,
			"go_version": runtime.Version(),
		})
	}

	s.setState(StateStarting)
	pool := NewTunnelPool(s.cfg, s.deps.Transport, s.logger, s.metrics, s.guard, s.deps.PoolHooks)
	pool.SetOnVMWoken(func() { s.vmWoken.Store(true) })
	if s.pausedOffline.Load() {
		pool.SetPausedOffline(true)
	}
	s.poolMu.Lock()
	s.activePool = pool
	s.activePoolPtr.Store(pool)
	s.poolMu.Unlock()

	s.setState(StateProbing)
	if err := pool.Start(ctx); err != nil {
		var fatalErr *FatalBootError
		if errors.As(err, &fatalErr) {
			s.fatalBootAbort.Store(true)
		}
		if pool.HasWokenVM() {
			s.vmWoken.Store(true)
		}
		pool.Close()
		s.executeOrderedShutdown()
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	proxy := NewPooledProxyServer(s.cfg, pool, s.logger, s.metrics)
	boundAddr, listenErr := proxy.Start(ctx)
	if listenErr != nil {
		if s.logger != nil {
			s.logger.Log("LISTEN_BIND_ERROR", map[string]any{
				"local_addr": s.cfg.LocalAddr(),
				"error":      listenErr.Error(),
			})
		}
		pool.Close()
		s.executeOrderedShutdown()
		return listenErr
	}

	s.proxyMu.Lock()
	s.activeProxy = proxy
	s.boundAddr = boundAddr
	s.activeProxyPtr.Store(proxy)
	baCopy := boundAddr
	s.boundAddrPtr.Store(&baCopy)
	s.proxyMu.Unlock()

	snap := pool.PoolSnapshot()
	if s.logger != nil {
		s.logger.Log("BOOT_READY", map[string]any{
			"local_addr":           boundAddr,
			"pool_size":            snap.PoolSize,
			"healthy_workers":      snap.HealthyWorkers,
			"routing_mode":         snap.RoutingMode,
			"underlay_baseline_ms": snap.UnderlayBaselineMS,
		})
	}
	s.setState(StateHealthy)

	summaryInterval := s.cfg.SummaryLogInterval
	if summaryInterval <= 0 {
		summaryInterval = DefaultSummaryLogInterval
	}
	summaryTicker := time.NewTicker(summaryInterval)
	defer summaryTicker.Stop()

	nextHealthDelay := func() time.Duration {
		if s.pausedOffline.Load() {
			return 30 * time.Second
		}
		switch pool.PowerState() {
		case PowerIdleDeep:
			return 30 * time.Second
		case PowerIdleLight:
			return 10 * time.Second
		default:
			return 2 * time.Second
		}
	}
	healthTimer := time.NewTimer(nextHealthDelay())
	defer healthTimer.Stop()

	resetHealthTimer := func() {
		if !healthTimer.Stop() {
			select {
			case <-healthTimer.C:
			default:
			}
		}
		healthTimer.Reset(nextHealthDelay())
	}

	reconcileHealth := func() {
		if s.pausedOffline.Load() {
			if s.State() != StatePausedOffline {
				s.setState(StatePausedOffline)
			}
			return
		}
		if pool.HealthyCount() > 0 {
			if s.State() != StateHealthy {
				s.setState(StateHealthy)
			}
		} else if s.State() != StateDegraded {
			s.setState(StateDegraded)
		}
	}

	for {
		select {
		case <-ctx.Done():
			s.stopActiveProxy(true)
			pool.Close()
			s.executeOrderedShutdown()
			return nil
		case fatalErr := <-pool.FatalErrCh():
			s.fatalBootAbort.Store(true)
			s.stopActiveProxy(true)
			pool.Close()
			s.executeOrderedShutdown()
			return fatalErr
		case <-pool.HealthChangedCh():
			reconcileHealth()
			resetHealthTimer()
		case <-healthTimer.C:
			reconcileHealth()
			healthTimer.Reset(nextHealthDelay())
		case <-summaryTicker.C:
			s.emitPoolSummary(proxy, pool)
		}
	}
}

func (s *Supervisor) stopActiveProxy(forceClose bool) {
	s.proxyMu.Lock()
	p := s.activeProxy
	s.activeProxy = nil
	s.boundAddr = ""
	s.activeProxyPtr.Store(nil)
	s.boundAddrPtr.Store(nil)
	s.proxyMu.Unlock()
	if p != nil {
		p.Stop(forceClose)
		up, down := p.TotalBytes()
		s.closedBytesUp.Add(up)
		s.closedBytesDown.Add(down)
	}
}

func (s *Supervisor) executeOrderedShutdown() {
	s.shutdownOnce.Do(func() {
		finalState := s.AtomicState()
		s.setState(StateShutdown)
		s.stopActiveProxy(true)

		s.poolMu.Lock()
		pool := s.activePool
		s.activePool = nil
		s.activePoolPtr.Store(nil)
		s.poolMu.Unlock()
		var lastPoolSnap PoolSnapshot
		if pool != nil {
			lastPoolSnap = pool.CachedSnapshot()
			if pool.HasWokenVM() {
				s.vmWoken.Store(true)
			}
			pool.Close()
		}

		stopInvoked := false
		if s.cfg.StopOnExit && s.deps.StopCodespace != nil && !s.fatalBootAbort.Load() && (s.everHealthy.Load() || s.vmWoken.Load()) {
			stopInvoked = true
			stopCtx, cancelStop := context.WithTimeout(context.Background(), s.cfg.StopTimeout)
			_ = s.deps.StopCodespace(stopCtx, s.cfg)
			cancelStop()
		}

		s.shutdownMu.Lock()
		reason := s.shutdownReason
		if reason == "" {
			reason = "context_canceled"
		}
		s.shutdownMu.Unlock()

		if s.logger != nil {
			var gs GitHubGuardSnapshot
			if s.guard != nil {
				gs = s.guard.CachedSnapshot()
			}
			deduped, archSegs := s.logger.ArchiveStats()
			s.logger.Log("SESSION_ROLLUP", map[string]any{
				"duration_sec":             int64(time.Since(s.sessionStart).Seconds()),
				"total_bytes_up":           s.closedBytesUp.Load(),
				"total_bytes_down":         s.closedBytesDown.Load(),
				"total_failovers":          lastPoolSnap.TotalFailovers,
				"primary_switches":         lastPoolSnap.PrimarySwitches,
				"slow_lane_evictions":      lastPoolSnap.SlowLaneEvictions,
				"waf_calls_5m":             gs.CallsLast5Min,
				"waf_calls_hour":           gs.CallsLastHour,
				"final_state":              string(finalState),
				"stop_reason":              reason,
				"clustered_errors_deduped": deduped,
				"archive_segments_count":   archSegs,
			})
			s.logger.Log("SHUTDOWN_COMPLETE", map[string]any{
				"reason":                 reason,
				"stop_codespace_invoked": stopInvoked,
				"total_bytes_up":         s.closedBytesUp.Load(),
				"total_bytes_down":       s.closedBytesDown.Load(),
				"session_uptime_ms":      time.Since(s.sessionStart).Milliseconds(),
				"ever_healthy":           s.everHealthy.Load(),
				"vm_woken":               s.vmWoken.Load(),
			})
			_ = s.logger.Close()
		}
		if s.metrics != nil {
			_ = s.metrics.Close()
		}
	})
}
