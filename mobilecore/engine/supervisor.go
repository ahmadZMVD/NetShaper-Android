package engine

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"runtime"
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
	if pool := s.activePoolPtr.Load(); pool != nil {
		pool.SetPausedOffline(false)
		pool.ForceReconnectForHandover()
	}
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
			if s.logger != nil {
				st := proxy.SnapshotWindow(true)
				ps := pool.PoolSnapshot()
				s.logger.Log("POOL_SUMMARY", map[string]any{
					"state":                string(s.State()),
					"power_state":          string(ps.PowerState),
					"healthy_workers":      ps.HealthyWorkers,
					"parked_workers":       ps.ParkedWorkers,
					"pool_size":            ps.PoolSize,
					"active_conns":         st.ActiveConns,
					"bytes_up_window":      st.BytesUpWindow,
					"bytes_down_window":    st.BytesDownWindow,
					"aggregate_p50_ms":     ps.AggregateP50MS,
					"underlay_baseline_ms": ps.UnderlayBaselineMS,
					"goroutines":           runtime.NumGoroutine(),
				})
			}
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
		s.setState(StateShutdown)
		s.stopActiveProxy(true)

		s.poolMu.Lock()
		pool := s.activePool
		s.activePool = nil
		s.activePoolPtr.Store(nil)
		s.poolMu.Unlock()
		if pool != nil {
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
