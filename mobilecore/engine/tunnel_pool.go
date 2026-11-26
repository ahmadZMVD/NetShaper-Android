package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type PowerState string

const (
	PowerActive    PowerState = "ACTIVE"
	PowerIdleLight PowerState = "IDLE_LIGHT"
	PowerIdleDeep  PowerState = "IDLE_DEEP"
)

type UpstreamLease struct {
	TunnelID    string
	PMTU576Safe bool
	DialTarget  func(ctx context.Context, host string, port uint16) (net.Conn, error)
	release     func()
}

func (l UpstreamLease) Release() {
	if l.release != nil {
		l.release()
	}
}

type UpstreamSelector interface {
	AcquireEndpoint(ctx context.Context) (UpstreamLease, error)
	NotifyDialFailure(tunnelID string, err error)
	NotifyDialSuccess(tunnelID string, rtt time.Duration)
	NotifyWANBytes(tunnelID string, n uint64)
}

type PoolSnapshot struct {
	PoolSize           int              `json:"pool_size"`
	HealthyWorkers     int              `json:"healthy_workers"`
	DegradedWorkers    int              `json:"degraded_workers"`
	ParkedWorkers      int              `json:"parked_workers"`
	SlowLaneWorkers    int              `json:"slow_lane_workers"`
	TotalActive        int64            `json:"total_active"`
	TotalFailovers     int64            `json:"total_failovers"`
	SlowLaneEvictions  int64            `json:"slow_lane_evictions"`
	PrimarySwitches    int64            `json:"primary_switches"`
	RoutingMode        string           `json:"routing_mode"`
	PrimaryTunnelID    string           `json:"primary_tunnel_id"`
	PowerState         PowerState       `json:"power_state"`
	PausedOffline      bool             `json:"paused_offline"`
	UnderlayBaselineMS float64          `json:"underlay_baseline_ms"`
	UnderlayTarget     string           `json:"underlay_target"`
	Workers            []TunnelSnapshot `json:"workers"`
	AggregateP50MS     float64          `json:"aggregate_p50_ms"`
}

// TunnelPool manages PoolSize=2 in-process SSH workers with:
//   - Serialized cold boot (tunnel-1 -> HEALTHY -> tunnel-2)
//   - 3-layer Schmitt-trigger hysteresis & guard-gated slow-lane eviction (incl. TunnelDegraded)
//   - Lossless P2C + Burst Cap (up to 64 on surviving worker) + TOCTOU rescan
//   - Adaptive Idle Scaling (ACTIVE -> IDLE_LIGHT -> IDLE_DEEP 2->1 parking with 0ms wake-up)
//   - PAUSED_OFFLINE offline brake + cellular handover ResetUnderlayBaseline()
//   - Android Doze Suspend-to-RAM clock-jump detection (wallDelta - monoDelta > 14s).
type TunnelPool struct {
	cfg       Config
	transport WorkerTransport
	probeFn   func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error)
	microFn   func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error)
	underlay  func(context.Context, []string, time.Duration) (time.Duration, string, error)
	logger    *EventLogger
	metrics   *MetricsEmitter
	guard     *GitHubGuard

	mu                sync.RWMutex
	workers           []*TunnelInstance
	workerByID        map[string]*TunnelInstance
	dialFailChs       map[string]chan error
	totalFailovers    atomic.Int64
	slowLaneEvictions atomic.Int64
	primarySwitches   atomic.Int64

	underlayMu      sync.RWMutex
	underlayRawMS   float64
	underlayTarget  string
	underlaySampled bool

	hystMu          sync.RWMutex
	routingMode     string
	primaryTunnelID string
	challengerID    string
	challengerSince time.Time
	rebalanceSince  time.Time

	powerMu           sync.RWMutex
	powerState        PowerState
	lastTrafficAt     time.Time
	lastUnparkAt      time.Time
	unparkBroadcastCh chan struct{}
	parkCh            chan bool // true = park worker #2, false = unpark worker #2
	pausedOffline     atomic.Bool
	offlineMu         sync.Mutex
	offlineWakeCh     chan struct{}
	resumeOffline     chan struct{}
	proactiveProbeChs map[string]chan struct{}
	healthChangedCh   chan struct{}
	coordWakeCh       chan struct{}

	// Injectable clock hook for deterministic Suspend-to-RAM clock-jump testing (MT-13).
	clockHook func() (mono time.Time, wallNS int64)

	fatalErrCh    chan error
	vmWoken       atomic.Bool
	onVMWoken     atomic.Pointer[func()]
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	started       atomic.Bool
	closed        atomic.Bool
	publishedSnap atomic.Pointer[PoolSnapshot]
}

type PoolHooks struct {
	ProbeFunc             func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error)
	MicroPayloadProbeFunc func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error)
	UnderlayProbeFunc     func(context.Context, []string, time.Duration) (time.Duration, string, error)
	SampleDelay           time.Duration
	RetryDelay            time.Duration
	ClockHook             func() (mono time.Time, wallNS int64)
}

func NewTunnelPool(cfg Config, transport WorkerTransport, logger *EventLogger, metrics *MetricsEmitter, guard *GitHubGuard, hooks PoolHooks) *TunnelPool {
	n := cfg.PoolSize
	if n < 1 {
		n = 1
	}
	workers := make([]*TunnelInstance, 0, n)
	byID := make(map[string]*TunnelInstance, n)
	failChs := make(map[string]chan error, n)
	proactiveChs := make(map[string]chan struct{}, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("tunnel-%d", i+1)
		w := NewTunnelInstance(id, cfg, transport, hooks.ProbeFunc, hooks.MicroPayloadProbeFunc, logger, metrics, guard)
		if hooks.SampleDelay > 0 {
			w.sampleDel = hooks.SampleDelay
		}
		if hooks.RetryDelay > 0 {
			w.retryDel = hooks.RetryDelay
		}
		workers = append(workers, w)
		byID[id] = w
		failChs[id] = make(chan error, 16)
		proactiveChs[id] = make(chan struct{}, 2)
	}
	initBase := cfg.UnderlayBaselineMS
	if initBase <= 0 {
		initBase = DefaultUnderlayBaselineMS
	}
	clockFn := hooks.ClockHook
	if clockFn == nil {
		clockFn = func() (time.Time, int64) {
			now := time.Now()
			return now, now.UnixNano()
		}
	}
	pool := &TunnelPool{
		cfg:               cfg,
		transport:         transport,
		probeFn:           hooks.ProbeFunc,
		microFn:           hooks.MicroPayloadProbeFunc,
		underlay:          hooks.UnderlayProbeFunc,
		logger:            logger,
		metrics:           metrics,
		guard:             guard,
		workers:           workers,
		workerByID:        byID,
		dialFailChs:       failChs,
		underlayRawMS:     initBase,
		routingMode:       "balanced",
		powerState:        PowerActive,
		lastTrafficAt:     time.Now(),
		lastUnparkAt:      time.Now(),
		unparkBroadcastCh: make(chan struct{}),
		parkCh:            make(chan bool, 4),
		offlineWakeCh:     make(chan struct{}),
		resumeOffline:     make(chan struct{}, 4),
		proactiveProbeChs: proactiveChs,
		healthChangedCh:   make(chan struct{}, 1),
		coordWakeCh:       make(chan struct{}, 1),
		clockHook:         clockFn,
		fatalErrCh:        make(chan error, 1),
	}
	if pool.probeFn == nil {
		pool.probeFn = ProbeDirectSSH
	}
	for _, w := range workers {
		w.SetOnVMReached(pool.markVMWoken)
	}
	pool.publishSnapshot()
	return pool
}

func (p *TunnelPool) SetOnVMWoken(fn func()) {
	if fn == nil {
		p.onVMWoken.Store(nil)
		return
	}
	p.onVMWoken.Store(&fn)
}

func (p *TunnelPool) HasWokenVM() bool { return p.vmWoken.Load() }

func (p *TunnelPool) markVMWoken() {
	p.vmWoken.Store(true)
	if cb := p.onVMWoken.Load(); cb != nil && *cb != nil {
		(*cb)()
	}
}

func (p *TunnelPool) reportFatalError(err error) {
	if err == nil {
		return
	}
	select {
	case p.fatalErrCh <- err:
	default:
	}
}

func (p *TunnelPool) FatalErrCh() <-chan error { return p.fatalErrCh }

func (p *TunnelPool) UnderlayBaselineMS() float64 {
	p.underlayMu.RLock()
	v := p.underlayRawMS
	p.underlayMu.RUnlock()
	if v < 50.0 {
		return 50.0
	}
	return v
}

func (p *TunnelPool) SetUnderlayBaselineMS(ms float64) {
	if ms < 50.0 {
		ms = 50.0
	}
	p.underlayMu.Lock()
	p.underlayRawMS = ms
	p.underlaySampled = true
	p.underlayMu.Unlock()
}

// ResetUnderlayBaseline clears stale B_raw(t) after a Wi-Fi <-> Cellular handover so the first
// probe on the new radio interface re-seeds the baseline cleanly without old-network bias.
func (p *TunnelPool) ResetUnderlayBaseline() {
	initBase := p.cfg.UnderlayBaselineMS
	if initBase <= 0 {
		initBase = DefaultUnderlayBaselineMS
	}
	p.underlayMu.Lock()
	p.underlayRawMS = initBase
	p.underlaySampled = false
	p.underlayMu.Unlock()
	p.publishSnapshot()
}

func (p *TunnelPool) recordUnderlaySample(d time.Duration, target string) {
	const (
		maxInitialUnderlayMS  = 1200.0
		maxUnderlaySpikeRatio = 2.0
	)
	ms := float64(d.Microseconds()) / 1000.0
	if ms < 10.0 {
		ms = 10.0
	}
	p.underlayMu.Lock()
	clamped := ms
	if !p.underlaySampled {
		if clamped > maxInitialUnderlayMS {
			clamped = maxInitialUnderlayMS
		}
		p.underlayRawMS = clamped
		p.underlaySampled = true
	} else {
		maxStep := math.Max(p.underlayRawMS, 50.0) * maxUnderlaySpikeRatio
		if clamped > maxStep {
			clamped = maxStep
		}
		p.underlayRawMS = 0.70*p.underlayRawMS + 0.30*clamped
	}
	p.underlayTarget = target
	p.underlayMu.Unlock()
}

func (p *TunnelPool) RoutingMode() (string, string) {
	p.hystMu.RLock()
	defer p.hystMu.RUnlock()
	return p.routingMode, p.primaryTunnelID
}

func (p *TunnelPool) PowerState() PowerState {
	p.powerMu.RLock()
	defer p.powerMu.RUnlock()
	return p.powerState
}

func (p *TunnelPool) PrimarySwitches() int64   { return p.primarySwitches.Load() }
func (p *TunnelPool) SlowLaneEvictions() int64 { return p.slowLaneEvictions.Load() }

func (p *TunnelPool) HealthChangedCh() <-chan struct{} { return p.healthChangedCh }

func (p *TunnelPool) signalCoordWake() {
	select {
	case p.coordWakeCh <- struct{}{}:
	default:
	}
}

func (p *TunnelPool) parkedWatchState() (<-chan struct{}, PowerState) {
	p.powerMu.RLock()
	ch, st := p.unparkBroadcastCh, p.powerState
	p.powerMu.RUnlock()
	return ch, st
}

// NotifyTrafficActivity wakes the pool from IDLE_LIGHT / IDLE_DEEP back to ACTIVE immediately (0ms delay).
func (p *TunnelPool) NotifyTrafficActivity() {
	now := time.Now()
	p.powerMu.Lock()
	prev := p.powerState
	p.lastTrafficAt = now
	if prev != PowerActive {
		p.powerState = PowerActive
		if prev == PowerIdleDeep {
			p.lastUnparkAt = now
			close(p.unparkBroadcastCh)
			p.unparkBroadcastCh = make(chan struct{})
		}
	}
	p.powerMu.Unlock()

	if prev == PowerIdleDeep {
		p.signalPark(false)
		p.signalCoordWake()
		if p.logger != nil && len(p.workers) > 1 {
			p.logger.Log("WORKER_UNPARKED", map[string]any{"tunnel_id": p.workers[1].ID()})
		}
		p.publishSnapshot()
	}
}

func (p *TunnelPool) signalPark(park bool) {
	select {
	case p.parkCh <- park:
	default:
		// Replace stale pending signal so latest state always wins.
		select {
		case <-p.parkCh:
		default:
		}
		select {
		case p.parkCh <- park:
		default:
		}
	}
}

// SetPausedOffline pauses all worker reconnects (0 API calls) while phone has no network,
// or resumes cleanly and fast-probes existing sessions when connectivity returns.
func (p *TunnelPool) SetPausedOffline(offline bool) {
	prev := p.pausedOffline.Swap(offline)
	if offline {
		// Drop dead sockets immediately so stale interface descriptors don't linger.
		for _, w := range p.workers {
			w.TriggerEviction("paused_offline")
		}
		p.signalCoordWake()
		p.publishSnapshot()
		return
	}
	if prev {
		p.ResetUnderlayBaseline()
		p.offlineMu.Lock()
		close(p.offlineWakeCh)
		p.offlineWakeCh = make(chan struct{})
		p.offlineMu.Unlock()
		p.signalCoordWake()
		select {
		case p.resumeOffline <- struct{}{}:
		default:
		}
		p.publishSnapshot()
	}
}

// ForceReconnectForHandover resets underlay baseline and triggers immediate fast-probe / reconnect
// of workers bound to a stale network interface without burning extra GitHub API calls (reuses cached JWT).
func (p *TunnelPool) ForceReconnectForHandover() {
	p.ResetUnderlayBaseline()
	for _, w := range p.workers {
		if w.State() == TunnelHealthy || w.State() == TunnelDegraded {
			w.TriggerEviction("network_handover")
		}
	}
	p.publishSnapshot()
}

// TriggerProactiveProbe wakes workers to immediately check liveness (e.g. after Doze Suspend-to-RAM jump).
func (p *TunnelPool) TriggerProactiveProbe() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, ch := range p.proactiveProbeChs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (p *TunnelPool) Start(ctx context.Context) error {
	if !p.started.CompareAndSwap(false, true) {
		return errors.New("tunnel pool already started")
	}
	poolCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	p.wg.Add(1)
	safeGo(p.logger, "pool_coordinator", func() { p.coordinatorLoop(poolCtx) })

	firstReady := make(chan struct{}, len(p.workers))
	if len(p.workers) > 1 {
		// Always serialized: boot tunnel-1 to TunnelHealthy before spawning tunnel-2..N.
		p.wg.Add(1)
		safeGo(p.logger, "worker_0", func() { p.superviseWorker(poolCtx, 0, p.workers[0], firstReady) })

		select {
		case <-firstReady:
		case fatalErr := <-p.fatalErrCh:
			p.Close()
			return fatalErr
		case <-ctx.Done():
			p.Close()
			return ctx.Err()
		}

		for i := 1; i < len(p.workers); i++ {
			idx := i
			w := p.workers[i]
			p.wg.Add(1)
			safeGo(p.logger, fmt.Sprintf("worker_%d", idx), func() { p.superviseWorker(poolCtx, idx, w, firstReady) })
		}
		p.publishSnapshot()
		return nil
	}

	p.wg.Add(1)
	safeGo(p.logger, "worker_0", func() { p.superviseWorker(poolCtx, 0, p.workers[0], firstReady) })

	select {
	case <-firstReady:
		p.publishSnapshot()
		return nil
	case fatalErr := <-p.fatalErrCh:
		p.Close()
		return fatalErr
	case <-ctx.Done():
		p.Close()
		return ctx.Err()
	}
}

func (p *TunnelPool) currentUnderlayInterval() time.Duration {
	if p.PowerState() != PowerActive && p.cfg.IdleUnderlayInterval > 0 {
		return p.cfg.IdleUnderlayInterval
	}
	if p.cfg.UnderlayProbeInterval > 0 {
		return p.cfg.UnderlayProbeInterval
	}
	return DefaultUnderlayProbeInterval
}

func (p *TunnelPool) currentWorkerProbeInterval() time.Duration {
	if p.PowerState() != PowerActive && p.cfg.IdleWorkerProbeInterval > 0 {
		return p.cfg.IdleWorkerProbeInterval
	}
	if p.cfg.ProbeInterval > 0 {
		return p.cfg.ProbeInterval
	}
	return DefaultProbeInterval
}

func (p *TunnelPool) coordinatorLoop(ctx context.Context) {
	defer p.wg.Done()

	underlayTimeout := p.cfg.UnderlayProbeTimeout
	if underlayTimeout <= 0 {
		underlayTimeout = DefaultUnderlayProbeTimeout
	}
	targets := p.cfg.ParsedUnderlayTargets()

	runUnderlay := func() {
		if p.underlay == nil || p.pausedOffline.Load() || p.PowerState() == PowerIdleDeep {
			return
		}
		pctx, pcancel := context.WithTimeout(ctx, underlayTimeout)
		rtt, usedTarget, err := p.underlay(pctx, targets, underlayTimeout)
		pcancel()
		if err == nil && rtt > 0 {
			p.recordUnderlaySample(rtt, usedTarget)
		}
	}

	if p.underlay != nil {
		runUnderlay()
	}
	lastUnderlayAt := time.Now()

	fastEval := 500 * time.Millisecond
	if p.cfg.HysteresisDwellWindow > 0 && p.cfg.HysteresisDwellWindow/4 < fastEval {
		fastEval = p.cfg.HysteresisDwellWindow / 4
	}
	if p.cfg.SlowLaneEvictWindow > 0 && p.cfg.SlowLaneEvictWindow/4 < fastEval {
		fastEval = p.cfg.SlowLaneEvictWindow / 4
	}
	if p.cfg.IdleDeepAfter > 0 && p.cfg.IdleDeepAfter/4 < fastEval {
		fastEval = p.cfg.IdleDeepAfter / 4
	}
	if fastEval < 20*time.Millisecond {
		fastEval = 20 * time.Millisecond
	}

	nextEvalInterval := func() time.Duration {
		// Preserve tight cadence when unit tests configure sub-second dwell/idle durations.
		if fastEval < 500*time.Millisecond {
			return fastEval
		}
		if p.pausedOffline.Load() {
			return 30 * time.Second
		}
		switch p.PowerState() {
		case PowerIdleDeep:
			return 30 * time.Second
		case PowerIdleLight:
			return 5 * time.Second
		default:
			return fastEval
		}
	}

	prevMono, prevWallNS := p.clockHook()
	jumpThresh := p.cfg.SuspendJumpThreshold
	if jumpThresh <= 0 {
		jumpThresh = DefaultSuspendJumpThreshold
	}

	evalTimer := time.NewTimer(nextEvalInterval())
	defer evalTimer.Stop()

	runEvalStep := func() {
		now := time.Now()
		// 1. Android Doze Suspend-to-RAM clock-jump detection (wallDelta - monoDelta > 14s).
		curMono, curWallNS := p.clockHook()
		monoDelta := curMono.Sub(prevMono)
		wallDelta := time.Duration(curWallNS - prevWallNS)
		prevMono, prevWallNS = curMono, curWallNS
		if jump := wallDelta - monoDelta; jump > jumpThresh && !p.pausedOffline.Load() {
			if p.logger != nil {
				p.logger.Log("SUSPEND_CLOCK_JUMP", map[string]any{
					"jump_ms": jump.Milliseconds(),
				})
			}
			p.TriggerProactiveProbe()
		}

		// 2. Adaptive Underlay Probe cadence (35s ACTIVE / 90s IDLE).
		if time.Since(lastUnderlayAt) >= p.currentUnderlayInterval() {
			lastUnderlayAt = now
			runUnderlay()
		}

		// 3. Adaptive Idle Scaling state machine (ACTIVE -> IDLE_LIGHT -> IDLE_DEEP 2->1 parking).
		p.evaluateIdlePowerState(now)

		// 4. Slow-lane eviction + 3-layer Schmitt-trigger hysteresis.
		if !p.pausedOffline.Load() {
			p.CheckSlowLaneEviction(now)
			p.EvaluateRoutingMode(now)
		}
		p.publishSnapshot()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.coordWakeCh:
			if !evalTimer.Stop() {
				select {
				case <-evalTimer.C:
				default:
				}
			}
			runEvalStep()
			evalTimer.Reset(nextEvalInterval())
		case <-evalTimer.C:
			runEvalStep()
			evalTimer.Reset(nextEvalInterval())
		}
	}
}

func (p *TunnelPool) evaluateIdlePowerState(now time.Time) {
	if !p.cfg.EnableIdleParking || p.pausedOffline.Load() {
		return
	}
	var activeTotal int64
	for _, w := range p.workers {
		activeTotal += w.activeStreams.Load()
	}

	p.powerMu.Lock()
	if activeTotal > 0 {
		prev := p.powerState
		p.lastTrafficAt = now
		p.powerState = PowerActive
		if prev == PowerIdleDeep {
			p.lastUnparkAt = now
			close(p.unparkBroadcastCh)
			p.unparkBroadcastCh = make(chan struct{})
		}
		p.powerMu.Unlock()
		if prev == PowerIdleDeep {
			p.signalPark(false)
			p.signalCoordWake()
		}
		return
	}

	idleFor := now.Sub(p.lastTrafficAt)
	sinceUnpark := now.Sub(p.lastUnparkAt)
	prev := p.powerState

	next := prev
	if p.cfg.IdleDeepAfter > 0 && idleFor >= p.cfg.IdleDeepAfter && sinceUnpark >= p.cfg.IdleMinActiveDwell && len(p.workers) >= 2 {
		next = PowerIdleDeep
	} else if p.cfg.IdleLightAfter > 0 && idleFor >= p.cfg.IdleLightAfter {
		if prev != PowerIdleDeep {
			next = PowerIdleLight
		}
	}
	p.powerState = next
	p.powerMu.Unlock()

	if prev != PowerIdleDeep && next == PowerIdleDeep && len(p.workers) >= 2 {
		p.signalPark(true)
		if p.logger != nil {
			p.logger.Log("WORKER_PARKED", map[string]any{
				"tunnel_id": p.workers[1].ID(),
				"idle_ms":   idleFor.Milliseconds(),
			})
		}
	}
}

// EvaluateRoutingMode executes exact v6.4 3-layer Schmitt-trigger hysteresis (ignoring TunnelParked workers).
func (p *TunnelPool) EvaluateRoutingMode(now time.Time) {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	baselineMS := p.UnderlayBaselineMS()
	relMargin := p.cfg.HysteresisRelMargin
	if relMargin <= 0 {
		relMargin = DefaultHysteresisRelMargin
	}
	absMarginMS := float64(p.cfg.HysteresisAbsMargin.Milliseconds())
	if absMarginMS <= 0 {
		absMarginMS = float64(DefaultHysteresisAbsMargin.Milliseconds())
	}
	dwell := p.cfg.HysteresisDwellWindow
	if dwell <= 0 {
		dwell = DefaultHysteresisDwellWindow
	}
	fastRatio := p.cfg.FastLaneMaxRatio
	if fastRatio < 1.0 {
		fastRatio = DefaultFastLaneMaxRatio
	}

	var healthyFast []*TunnelInstance
	for _, w := range workers {
		if w.State() == TunnelHealthy && !w.IsSlowLaneDegraded() {
			healthyFast = append(healthyFast, w)
		}
	}

	p.hystMu.Lock()
	defer p.hystMu.Unlock()

	if len(healthyFast) == 0 {
		p.routingMode = "degraded"
		p.primaryTunnelID = ""
		p.challengerID = ""
		p.challengerSince = time.Time{}
		p.rebalanceSince = time.Time{}
		return
	}
	if len(healthyFast) == 1 {
		p.routingMode = "single_primary"
		p.primaryTunnelID = healthyFast[0].ID()
		p.challengerID = ""
		p.challengerSince = time.Time{}
		p.rebalanceSince = time.Time{}
		return
	}

	sort.SliceStable(healthyFast, func(i, j int) bool {
		return healthyFast[i].QualityScore(baselineMS) < healthyFast[j].QualityScore(baselineMS)
	})
	best := healthyFast[0]
	worst := healthyFast[len(healthyFast)-1]

	var compareAgainst *TunnelInstance
	if p.routingMode == "primary_preferred" && p.primaryTunnelID != "" {
		for _, w := range healthyFast {
			if w.ID() == p.primaryTunnelID {
				compareAgainst = w
				break
			}
		}
	}

	if compareAgainst != nil {
		if best.ID() != compareAgainst.ID() {
			incScore := compareAgainst.QualityScore(baselineMS)
			bestScore := best.QualityScore(baselineMS)
			relGain := 0.0
			if incScore > 0 {
				relGain = (incScore - bestScore) / incScore
			}
			absGainMS := compareAgainst.EWMARTTMS() - best.EWMARTTMS()
			if relGain >= relMargin && absGainMS >= absMarginMS {
				p.rebalanceSince = time.Time{}
				if p.challengerID != best.ID() {
					p.challengerID = best.ID()
					p.challengerSince = now
				} else if now.Sub(p.challengerSince) >= dwell {
					prevPrimary := p.primaryTunnelID
					p.primaryTunnelID = best.ID()
					p.challengerID = ""
					p.challengerSince = time.Time{}
					p.primarySwitches.Add(1)
					p.logPrimarySwitchLocked(prevPrimary, best.ID(), "schmitt_challenger_dwell_met", baselineMS, relGain, absGainMS)
				}
				return
			}
			p.challengerID = ""
			p.challengerSince = time.Time{}
		}
		allFast := true
		for _, w := range healthyFast {
			if w.Rho(baselineMS) > fastRatio {
				allFast = false
				break
			}
		}
		worstScore := worst.QualityScore(baselineMS)
		bestScore := best.QualityScore(baselineMS)
		relGap := 0.0
		if worstScore > 0 {
			relGap = (worstScore - bestScore) / worstScore
		}
		absGapMS := math.Abs(worst.EWMARTTMS() - best.EWMARTTMS())
		if allFast && (relGap < relMargin*0.5 || absGapMS < absMarginMS*0.5) {
			if p.rebalanceSince.IsZero() {
				p.rebalanceSince = now
			} else if now.Sub(p.rebalanceSince) >= dwell {
				prevPrimary := p.primaryTunnelID
				p.routingMode = "balanced"
				p.primaryTunnelID = ""
				p.rebalanceSince = time.Time{}
				p.challengerID = ""
				p.challengerSince = time.Time{}
				p.logPrimarySwitchLocked(prevPrimary, "balanced", "fast_peers_converged", baselineMS, relGap, absGapMS)
			}
		} else {
			p.rebalanceSince = time.Time{}
		}
		return
	}

	worstScore := worst.QualityScore(baselineMS)
	bestScore := best.QualityScore(baselineMS)
	relGain := 0.0
	if worstScore > 0 {
		relGain = (worstScore - bestScore) / worstScore
	}
	absGainMS := worst.EWMARTTMS() - best.EWMARTTMS()
	if relGain >= relMargin && absGainMS >= absMarginMS {
		if p.challengerID != best.ID() {
			p.challengerID = best.ID()
			p.challengerSince = now
		} else if now.Sub(p.challengerSince) >= dwell {
			prevPrimary := p.primaryTunnelID
			p.routingMode = "primary_preferred"
			p.primaryTunnelID = best.ID()
			p.challengerID = ""
			p.challengerSince = time.Time{}
			p.rebalanceSince = time.Time{}
			p.primarySwitches.Add(1)
			p.logPrimarySwitchLocked(prevPrimary, best.ID(), "schmitt_primary_promoted", baselineMS, relGain, absGainMS)
		}
	} else {
		p.routingMode = "balanced"
		p.primaryTunnelID = ""
		p.challengerID = ""
		p.challengerSince = time.Time{}
		p.rebalanceSince = time.Time{}
	}
}

func (p *TunnelPool) logPrimarySwitchLocked(fromID, toID, reason string, baselineMS, relGain, absGainMS float64) {
	if p.logger != nil {
		p.logger.Log("POOL_PRIMARY_SWITCH", map[string]any{
			"from":                 fromID,
			"to":                   toID,
			"routing_mode":         p.routingMode,
			"reason":               reason,
			"underlay_baseline_ms": round2(baselineMS),
			"rel_gain":             round2(relGain),
			"abs_gain_ms":          round2(absGainMS),
			"primary_switches":     p.primarySwitches.Load(),
		})
	}
}

// CheckSlowLaneEviction evicts chronic slow-lane workers (TunnelHealthy OR TunnelDegraded) gated by GitHubGuard.
func (p *TunnelPool) CheckSlowLaneEviction(now time.Time) int {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()
	if len(workers) < 2 {
		return 0
	}

	baselineMS := p.UnderlayBaselineMS()
	underlayCeilingMS := float64(p.cfg.SlowLaneUnderlayCeiling.Milliseconds())
	if underlayCeilingMS <= 0 {
		underlayCeilingMS = float64(DefaultSlowLaneUnderlayCeiling.Milliseconds())
	}
	evictRatio := p.cfg.SlowLaneEvictRatio
	if evictRatio <= 1.0 {
		evictRatio = DefaultSlowLaneEvictRatio
	}
	evictWindow := p.cfg.SlowLaneEvictWindow
	if evictWindow <= 0 {
		evictWindow = DefaultSlowLaneEvictWindow
	}

	if baselineMS > underlayCeilingMS {
		for _, w := range workers {
			w.stateMu.Lock()
			w.slowLaneSince = time.Time{}
			w.stateMu.Unlock()
			if w.IsSlowLaneDegraded() {
				w.SetSlowLaneDegraded(false)
			}
			w.ResetEvictionState()
		}
		return 0
	}

	healthyFastCount := 0
	for _, w := range workers {
		if w.State() == TunnelHealthy && !w.IsSlowLaneDegraded() && w.Rho(baselineMS) <= evictRatio {
			healthyFastCount++
		}
	}

	evicted := 0
	for _, w := range workers {
		st := w.State()
		if st != TunnelHealthy && st != TunnelDegraded {
			w.stateMu.Lock()
			w.slowLaneSince = time.Time{}
			w.stateMu.Unlock()
			continue
		}
		rho := w.Rho(baselineMS)
		if rho > evictRatio {
			w.stateMu.Lock()
			if w.slowLaneSince.IsZero() {
				w.slowLaneSince = now
			}
			elapsed := now.Sub(w.slowLaneSince)
			w.stateMu.Unlock()

			if elapsed >= evictWindow && healthyFastCount >= 1 {
				w.SetSlowLaneDegraded(true)
				if evicted == 0 && !w.IsEvictionTriggered() {
					if p.guard != nil {
						if canReroll, deferReason := p.guard.CanAllowNonConsuming(); !canReroll {
							if w.MarkEvictDeferLogged() && p.logger != nil {
								p.logger.Log("WORKER_SLOW_LANE_EVICT_DEFERRED", map[string]any{
									"tunnel_id":            w.ID(),
									"defer_reason":         deferReason,
									"ewma_rtt_ms":          round2(w.EWMARTTMS()),
									"underlay_baseline_ms": round2(baselineMS),
									"relative_rho":         round2(rho),
								})
							}
							continue
						}
					}
					if w.MarkEvictionTriggered() {
						p.slowLaneEvictions.Add(1)
						evicted++
						if p.logger != nil {
							p.logger.Log("WORKER_SLOW_LANE_EVICT", map[string]any{
								"tunnel_id":            w.ID(),
								"worker_state":         string(st),
								"ewma_rtt_ms":          round2(w.EWMARTTMS()),
								"underlay_baseline_ms": round2(baselineMS),
								"relative_rho":         round2(rho),
							})
						}
						w.TriggerEviction("chronic_slow_lane")
					}
				}
			}
		} else {
			w.stateMu.Lock()
			w.slowLaneSince = time.Time{}
			w.stateMu.Unlock()
			if w.IsSlowLaneDegraded() {
				w.SetSlowLaneDegraded(false)
			}
			w.ResetEvictionState()
		}
	}
	return evicted
}

func (p *TunnelPool) PeerFastMedianMS(excludeID string) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var vals []float64
	for _, w := range p.workers {
		if w.ID() == excludeID {
			continue
		}
		if w.State() == TunnelHealthy && !w.IsSlowLaneDegraded() {
			if rtt := w.EWMARTTMS(); rtt > 0 {
				vals = append(vals, rtt)
			}
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	return vals[(len(vals)-1)/2]
}

func (p *TunnelPool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, w := range p.workers {
		if w.State() == TunnelHealthy {
			n++
		}
	}
	return n
}

func (p *TunnelPool) AcquireEndpoint(ctx context.Context) (UpstreamLease, error) {
	if err := ctx.Err(); err != nil {
		return UpstreamLease{}, err
	}
	// Instant wake-up from IDLE_DEEP (0ms latency on tunnel-1 while tunnel-2 unparks asynchronously).
	p.NotifyTrafficActivity()

	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	var healthyFast, healthySlow, degraded []*TunnelInstance
	for _, w := range workers {
		switch w.State() {
		case TunnelHealthy:
			if w.IsSlowLaneDegraded() {
				healthySlow = append(healthySlow, w)
			} else {
				healthyFast = append(healthyFast, w)
			}
		case TunnelDegraded:
			degraded = append(degraded, w)
		}
	}

	candidates := healthyFast
	if len(candidates) == 0 {
		candidates = healthySlow
	}
	if len(candidates) == 0 {
		candidates = degraded
	}
	if len(candidates) == 0 {
		return UpstreamLease{}, errors.New("no healthy upstream tunnel workers available")
	}

	mode, primaryID := p.RoutingMode()
	order := make([]*TunnelInstance, len(candidates))
	copy(order, candidates)

	if mode == "primary_preferred" && primaryID != "" && len(order) >= 2 {
		sort.SliceStable(order, func(i, j int) bool {
			if order[i].ID() == primaryID {
				return true
			}
			if order[j].ID() == primaryID {
				return false
			}
			return order[i].RoutingScore() < order[j].RoutingScore()
		})
	} else if len(order) > 2 {
		i := rand.IntN(len(order))
		j := rand.IntN(len(order) - 1)
		if j >= i {
			j++
		}
		if order[j].RoutingScore() < order[i].RoutingScore() {
			i, j = j, i
		}
		order[0], order[i] = order[i], order[0]
		if j == 0 {
			j = i
		}
		order[1], order[j] = order[j], order[1]
		sort.SliceStable(order[2:], func(x, y int) bool {
			return order[2+x].RoutingScore() < order[2+y].RoutingScore()
		})
	} else {
		sort.SliceStable(order, func(i, j int) bool {
			return order[i].RoutingScore() < order[j].RoutingScore()
		})
	}

	perTunnelCap := p.cfg.PerTunnelMaxConns
	if perTunnelCap < 1 {
		perTunnelCap = DefaultPerTunnelMaxConns
	}
	if lease, ok := tryAcquireFromOrder(order, perTunnelCap); ok {
		return lease, nil
	}

	// Pass 2 (Burst Cap): surviving healthy worker(s) absorb up to MaxActiveConns=64 when peer is parked/booting/evicted.
	if len(healthyFast) < len(workers) {
		globalCap := p.cfg.MaxActiveConns
		if globalCap < perTunnelCap {
			globalCap = perTunnelCap
		}
		burstCap := perTunnelCap
		if len(healthyFast) == 1 {
			burstCap = globalCap
		} else if len(healthyFast) >= 2 {
			burstCap = (globalCap + len(healthyFast) - 1) / len(healthyFast)
		} else if len(healthySlow) > 0 {
			burstCap = (globalCap + len(healthySlow) - 1) / len(healthySlow)
		} else if len(degraded) > 0 {
			burstCap = (globalCap + len(degraded) - 1) / len(degraded)
		}
		if burstCap < perTunnelCap {
			burstCap = perTunnelCap
		}
		if burstCap > globalCap {
			burstCap = globalCap
		}
		if burstCap > perTunnelCap {
			sort.SliceStable(order, func(i, j int) bool {
				ai := order[i].activeStreams.Load()
				aj := order[j].activeStreams.Load()
				if ai != aj {
					return ai < aj
				}
				return order[i].RoutingScore() < order[j].RoutingScore()
			})
			if lease, ok := tryAcquireFromOrder(order, burstCap); ok {
				return lease, nil
			}
		}
	}
	return UpstreamLease{}, errors.New("all healthy upstream tunnel workers at per-tunnel capacity")
}

func tryAcquireFromOrder(order []*TunnelInstance, capLimit int) (UpstreamLease, bool) {
	makeLease := func(w *TunnelInstance) UpstreamLease {
		return UpstreamLease{
			TunnelID:    w.ID(),
			PMTU576Safe: w.PMTU576Active(),
			DialTarget:  w.DialTarget,
			release:     w.ReleaseSlot,
		}
	}
	for _, w := range order {
		if w.TryAcquireSlotWithCap(capLimit) {
			return makeLease(w), true
		}
	}
	for retry := 0; retry < 6; retry++ {
		hasFree := false
		for _, w := range order {
			if w.activeStreams.Load() < int64(capLimit) {
				hasFree = true
				break
			}
		}
		if !hasFree {
			return UpstreamLease{}, false
		}
		sort.SliceStable(order, func(i, j int) bool {
			return order[i].activeStreams.Load() < order[j].activeStreams.Load()
		})
		for _, w := range order {
			if w.TryAcquireSlotWithCap(capLimit) {
				return makeLease(w), true
			}
		}
	}
	return UpstreamLease{}, false
}

func (p *TunnelPool) NotifyDialFailure(tunnelID string, err error) {
	w := p.workerByID[tunnelID]
	if w == nil {
		return
	}
	w.dialFailures.Add(1)
	w.RecordStreamError()
	if ch, ok := p.dialFailChs[tunnelID]; ok {
		select {
		case ch <- err:
		default:
		}
	}
}

func (p *TunnelPool) NotifyDialSuccess(tunnelID string, _ time.Duration) {
	if w := p.workerByID[tunnelID]; w != nil {
		w.RecordStreamSuccess()
	}
}

func (p *TunnelPool) NotifyWANBytes(tunnelID string, n uint64) {
	if w := p.workerByID[tunnelID]; w != nil {
		w.RecordWANBytes(n)
	}
}

func (p *TunnelPool) PoolSnapshot() PoolSnapshot {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	baselineMS := p.UnderlayBaselineMS()
	p.underlayMu.RLock()
	underlayTarget := p.underlayTarget
	p.underlayMu.RUnlock()
	mode, primaryID := p.RoutingMode()

	snaps := make([]TunnelSnapshot, 0, len(workers))
	healthy, degraded, parked, slowLane := 0, 0, 0, 0
	var totalActive int64
	var rtts []float64
	for _, w := range workers {
		s := w.SnapshotWithBaseline(baselineMS)
		snaps = append(snaps, s)
		totalActive += s.ActiveStreams
		if s.SlowLaneDegraded {
			slowLane++
		}
		switch s.State {
		case TunnelHealthy:
			healthy++
			if s.EWMARTTMS > 0 {
				rtts = append(rtts, s.EWMARTTMS)
			}
		case TunnelDegraded:
			degraded++
		case TunnelParked:
			parked++
		}
	}
	_, p50, _, _ := computeRTTStats(rtts)
	return PoolSnapshot{
		PoolSize:           len(workers),
		HealthyWorkers:     healthy,
		DegradedWorkers:    degraded,
		ParkedWorkers:      parked,
		SlowLaneWorkers:    slowLane,
		TotalActive:        totalActive,
		TotalFailovers:     p.totalFailovers.Load(),
		SlowLaneEvictions:  p.slowLaneEvictions.Load(),
		PrimarySwitches:    p.primarySwitches.Load(),
		RoutingMode:        mode,
		PrimaryTunnelID:    primaryID,
		PowerState:         p.PowerState(),
		PausedOffline:      p.pausedOffline.Load(),
		UnderlayBaselineMS: round2(baselineMS),
		UnderlayTarget:     underlayTarget,
		Workers:            snaps,
		AggregateP50MS:     round2(p50),
	}
}

func (p *TunnelPool) publishSnapshot() {
	if p == nil {
		return
	}
	snap := p.PoolSnapshot()
	p.publishedSnap.Store(&snap)
	select {
	case p.healthChangedCh <- struct{}{}:
	default:
	}
}

func (p *TunnelPool) CachedSnapshot() PoolSnapshot {
	if p == nil {
		return PoolSnapshot{}
	}
	if ptr := p.publishedSnap.Load(); ptr != nil {
		return *ptr
	}
	return PoolSnapshot{PoolSize: p.cfg.PoolSize, RoutingMode: "starting", PowerState: PowerActive}
}

func (p *TunnelPool) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	for _, w := range p.workers {
		w.setSession(nil)
		w.setState(TunnelDead)
	}
	p.publishSnapshot()
}

func (p *TunnelPool) waitWhileOffline(ctx context.Context) bool {
	for {
		p.offlineMu.Lock()
		wakeCh := p.offlineWakeCh
		p.offlineMu.Unlock()
		if !p.pausedOffline.Load() {
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-wakeCh:
		}
	}
	return ctx.Err() == nil
}

func (p *TunnelPool) superviseWorker(ctx context.Context, idx int, w *TunnelInstance, firstReady chan<- struct{}) {
	defer p.wg.Done()
	attempt := 0
	signaledReady := false
	failCh := p.dialFailChs[w.ID()]

	for {
		if ctx.Err() != nil {
			w.DrainAndClose(200*time.Millisecond, TunnelDead)
			return
		}
		if p.pausedOffline.Load() {
			w.DrainAndClose(100*time.Millisecond, TunnelDead)
			p.publishSnapshot()
			if !p.waitWhileOffline(ctx) {
				return
			}
			attempt = 0
			continue
		}
		// Worker #2 (idx == 1) honors IDLE_DEEP parking cleanly without 200ms timer polling.
		if idx == 1 && p.PowerState() == PowerIdleDeep {
			w.DrainAndClose(200*time.Millisecond, TunnelParked)
			p.publishSnapshot()
			for {
				wakeCh, st := p.parkedWatchState()
				if st != PowerIdleDeep {
					break
				}
				select {
				case <-ctx.Done():
					w.DrainAndClose(100*time.Millisecond, TunnelDead)
					return
				case <-wakeCh:
				}
			}
			attempt = 0
			continue
		}

		sess, _, err := w.BootAndQualify(ctx, p.PeerFastMedianMS, p.UnderlayBaselineMS)
		if err != nil {
			var fatalErr *FatalBootError
			if errors.As(err, &fatalErr) {
				w.DrainAndClose(100*time.Millisecond, TunnelDead)
				p.reportFatalError(fatalErr)
				p.publishSnapshot()
				return
			}
			if ctx.Err() != nil {
				w.DrainAndClose(200*time.Millisecond, TunnelDead)
				return
			}
			if p.pausedOffline.Load() {
				continue
			}
			attempt++
			backoff := ComputeBackoff(attempt, p.cfg.BackoffMin, p.cfg.BackoffMax, nil)
			if p.logger != nil {
				p.logger.Log("WORKER_BOOT_FAIL", map[string]any{
					"tunnel_id":  w.id,
					"attempt":    attempt,
					"backoff_ms": backoff.Milliseconds(),
					"error":      RedactSecrets(err.Error()),
				})
			}
			tm := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				tm.Stop()
				return
			case <-p.resumeOffline:
				tm.Stop()
			case <-tm.C:
			}
			continue
		}

		attempt = 0
		if !signaledReady {
			signaledReady = true
			select {
			case firstReady <- struct{}{}:
			default:
			}
		}
		p.publishSnapshot()

		reason := p.monitorSingleWorker(ctx, idx, w, sess, failCh)
		if ctx.Err() != nil {
			w.DrainAndClose(200*time.Millisecond, TunnelDead)
			p.publishSnapshot()
			return
		}
		if reason == "idle_deep_park" {
			// Clean power-saving park: NEVER increments TotalFailovers or Restarts!
			w.DrainAndClose(300*time.Millisecond, TunnelParked)
			p.publishSnapshot()
			continue
		}
		if reason == "paused_offline" {
			w.DrainAndClose(100*time.Millisecond, TunnelDead)
			p.publishSnapshot()
			continue
		}

		// If primary worker #1 dies while worker #2 is parked in IDLE_DEEP, immediately unpark worker #2!
		if idx == 0 && p.PowerState() == PowerIdleDeep {
			p.NotifyTrafficActivity()
		}

		w.restarts.Add(1)
		p.totalFailovers.Add(1)
		p.publishSnapshot()
		if p.logger != nil {
			p.logger.Log("POOL_WORKER_FAILOVER", map[string]any{
				"tunnel_id":       w.ID(),
				"reason":          reason,
				"healthy_peers":   p.HealthyCount(),
				"worker_restarts": w.restarts.Load(),
				"total_failovers": p.totalFailovers.Load(),
			})
		}
		drainTimeout := 300 * time.Millisecond
		if reason == "chronic_slow_lane" {
			drainTimeout = 1500 * time.Millisecond
		}
		w.DrainAndClose(drainTimeout, TunnelDead)

		if reason == "network_handover" {
			// Fast handover reconnect without exponential sleep penalty.
			continue
		}
		attempt++
		backoff := ComputeBackoff(attempt, p.cfg.BackoffMin, p.cfg.BackoffMax, nil)
		tm := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			tm.Stop()
			return
		case <-p.resumeOffline:
			tm.Stop()
		case <-tm.C:
		}
	}
}

type asyncProbeResult struct {
	rtt time.Duration
	err error
}

func (p *TunnelPool) monitorSingleWorker(
	ctx context.Context,
	idx int,
	w *TunnelInstance,
	sess WorkerSession,
	failCh <-chan error,
) string {
	degradedInterval := p.cfg.DegradedProbeInterval
	if degradedInterval <= 0 {
		degradedInterval = DefaultDegradedProbeInterval
	}

	probeTimer := time.NewTimer(p.currentWorkerProbeInterval())
	defer probeTimer.Stop()

	consecProbeFails := 0
	var firstFailAt time.Time
	probeResCh := make(chan asyncProbeResult, 1)
	probeInFlight := false
	var probeCancel context.CancelFunc
	var probeWG sync.WaitGroup

	cancelProbe := func() {
		if probeCancel != nil {
			probeCancel()
			probeCancel = nil
		}
	}
	defer func() {
		cancelProbe()
		probeWG.Wait()
	}()

	startProbe := func() {
		if probeInFlight {
			return
		}
		probeInFlight = true
		pctx, pcancel := context.WithCancel(ctx)
		probeCancel = pcancel
		probeWG.Add(1)
		safeGo(p.logger, w.ID()+"_probe", func() {
			defer probeWG.Done()
			rtt, err := p.probeFn(pctx, sess, p.cfg.ProbeTarget, p.cfg.ProbeTimeout)
			select {
			case probeResCh <- asyncProbeResult{rtt: rtt, err: err}:
			case <-pctx.Done():
			}
		})
	}

	resetTimer := func(d time.Duration) {
		if !probeTimer.Stop() {
			select {
			case <-probeTimer.C:
			default:
			}
		}
		probeTimer.Reset(d)
	}

	var parkCh <-chan bool
	if idx == 1 {
		parkCh = p.parkCh
	}
	proactiveCh := p.proactiveProbeChs[w.ID()]

	for {
		select {
		case <-ctx.Done():
			return "shutdown"
		case park := <-parkCh:
			if park {
				cancelProbe()
				return "idle_deep_park"
			}
		case evictReason := <-w.evictCh:
			cancelProbe()
			return evictReason
		case <-sess.Done():
			cancelProbe()
			if p.pausedOffline.Load() {
				return "paused_offline"
			}
			return "ssh_session_closed"
		case <-proactiveCh:
			// Triggered by Doze Suspend-to-RAM clock-jump detection: verify keepalive immediately.
			kCtx, kCancel := context.WithTimeout(ctx, 4*time.Second)
			kErr := sess.SendKeepalive(kCtx)
			kCancel()
			if kErr != nil {
				cancelProbe()
				return "suspend_keepalive_dead"
			}
			startProbe()
		case <-failCh:
			startProbe()
		case <-probeTimer.C:
			startProbe()
		case res := <-probeResCh:
			probeInFlight = false
			cancelProbe()
			if ctx.Err() != nil {
				return "shutdown"
			}
			now := time.Now()
			if res.err != nil {
				consecProbeFails++
				if firstFailAt.IsZero() {
					firstFailAt = now
				}
				minWin := p.cfg.BreakerMinWindow
				freshWin := minWin
				if freshWin <= 0 {
					freshWin = p.cfg.ProbeTimeout
				}
				lastWAN := w.LastWANBytesAt()
				wanRecent := !lastWAN.IsZero() && now.Sub(lastWAN) < freshWin
				if consecProbeFails >= p.cfg.BreakerThreshold && now.Sub(firstFailAt) >= minWin && !wanRecent {
					return "sustained_e2e_blackhole"
				}
				prevState := w.State()
				w.setState(TunnelDegraded)
				if prevState != TunnelDegraded && p.logger != nil {
					p.logger.Log("WORKER_DEGRADED", map[string]any{
						"tunnel_id":            w.ID(),
						"reason":               "e2e_probe_failed",
						"consecutive_failures": consecProbeFails,
						"error":                res.err.Error(),
					})
				}
				resetTimer(degradedInterval)
				continue
			}

			w.RecordRTT(res.rtt)
			consecProbeFails = 0
			firstFailAt = time.Time{}
			if p.cfg.DegradedRTTThreshold > 0 && res.rtt > p.cfg.DegradedRTTThreshold {
				prevState := w.State()
				w.setState(TunnelDegraded)
				if prevState != TunnelDegraded && p.logger != nil {
					p.logger.Log("WORKER_DEGRADED", map[string]any{
						"tunnel_id":    w.ID(),
						"reason":       "high_rtt_bufferbloat",
						"probe_rtt_ms": res.rtt.Milliseconds(),
					})
				}
				resetTimer(degradedInterval)
				continue
			}
			prevState := w.State()
			w.setState(TunnelHealthy)
			if prevState == TunnelDegraded && p.logger != nil {
				p.logger.Log("WORKER_RECOVERED", map[string]any{
					"tunnel_id":             w.ID(),
					"recovery_probe_rtt_ms": res.rtt.Milliseconds(),
				})
			}
			resetTimer(p.currentWorkerProbeInterval())
		}
	}
}
