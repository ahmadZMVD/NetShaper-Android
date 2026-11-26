package engine

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type TunnelState string

const (
	TunnelStarting TunnelState = "STARTING"
	TunnelHealthy  TunnelState = "HEALTHY"
	TunnelDegraded TunnelState = "DEGRADED"
	TunnelDraining TunnelState = "DRAINING"
	TunnelParked   TunnelState = "PARKED" // IDLE_DEEP mobile power-saving state (distinct from DEAD/DEGRADED)
	TunnelDead     TunnelState = "DEAD"
)

type TunnelSnapshot struct {
	ID               string      `json:"id"`
	State            TunnelState `json:"state"`
	SlowLaneDegraded bool        `json:"slow_lane_degraded"`
	WANRemote        string      `json:"wan_remote"`
	PMTU576Active    bool        `json:"pmtu576_active"`
	ActiveStreams    int64       `json:"active_streams"`
	MaxStreams       int         `json:"max_streams"`
	EWMARTTMS        float64     `json:"ewma_rtt_ms"`
	EWMAJitterMS     float64     `json:"ewma_jitter_ms"`
	RelativeRho      float64     `json:"relative_rho"`
	StreamErrorRate  float64     `json:"stream_error_rate"`
	TotalRouted      uint64      `json:"total_routed"`
	DialFailures     uint64      `json:"dial_failures"`
	BootRetries      int         `json:"boot_retries"`
	Restarts         int64       `json:"restarts"`
	LastBootMS       int64       `json:"last_boot_ms"`
}

// TunnelInstance owns one in-process multiplexed SSH WorkerSession (zero subprocesses).
type TunnelInstance struct {
	id        string
	cfg       Config
	transport WorkerTransport
	probeFn   func(ctx context.Context, sess WorkerSession, target string, timeout time.Duration) (time.Duration, error)
	microFn   func(ctx context.Context, sess WorkerSession, target string, timeout time.Duration) (time.Duration, error)
	sampleDel time.Duration
	retryDel  time.Duration

	logger  *EventLogger
	metrics *MetricsEmitter
	guard   *GitHubGuard

	maxStreams        int
	activeStreams     atomic.Int64
	totalRouted       atomic.Uint64
	dialFailures      atomic.Uint64
	restarts          atomic.Int64
	lastWANBytes      atomic.Int64
	ewmaRTTBits       atomic.Uint64
	ewmaJitterBits    atomic.Uint64
	lastRTTBits       atomic.Uint64
	streamErrRateBit  atomic.Uint64
	slowLaneDegraded  atomic.Bool
	evictionTriggered atomic.Bool
	evictDeferLogged  atomic.Bool
	vmReached         atomic.Bool

	stateMu       sync.RWMutex
	state         TunnelState
	lastBootMS    int64
	bootRetries   int
	wanRemote     string
	pmtu576Active bool
	slowLaneSince time.Time
	onVMReached   func()

	sessMu  sync.RWMutex
	session WorkerSession

	evictCh chan string
}

func NewTunnelInstance(
	id string,
	cfg Config,
	transport WorkerTransport,
	probeFn func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error),
	microFn func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error),
	logger *EventLogger,
	metrics *MetricsEmitter,
	guard *GitHubGuard,
) *TunnelInstance {
	capPer := cfg.PerTunnelMaxConns
	if capPer < 1 {
		capPer = DefaultPerTunnelMaxConns
	}
	if probeFn == nil {
		probeFn = ProbeDirectSSH
	}
	if microFn == nil {
		microFn = ProbeDirectSSHMicroPayload
	}
	ti := &TunnelInstance{
		id:         id,
		cfg:        cfg,
		transport:  transport,
		probeFn:    probeFn,
		microFn:    microFn,
		sampleDel:  120 * time.Millisecond,
		retryDel:   1500 * time.Millisecond,
		logger:     logger,
		metrics:    metrics,
		guard:      guard,
		maxStreams: capPer,
		state:      TunnelStarting,
		evictCh:    make(chan string, 2),
	}
	ti.ewmaRTTBits.Store(math.Float64bits(350.0))
	ti.ewmaJitterBits.Store(math.Float64bits(0.0))
	ti.lastRTTBits.Store(math.Float64bits(0.0))
	ti.streamErrRateBit.Store(math.Float64bits(0.0))
	return ti
}

func (t *TunnelInstance) ID() string { return t.id }

func (t *TunnelInstance) SetOnVMReached(fn func()) {
	t.stateMu.Lock()
	t.onVMReached = fn
	t.stateMu.Unlock()
}

func (t *TunnelInstance) HasReachedVM() bool { return t.vmReached.Load() }

func (t *TunnelInstance) State() TunnelState {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.state
}

func (t *TunnelInstance) setState(next TunnelState) {
	t.stateMu.Lock()
	prev := t.state
	t.state = next
	if next == TunnelStarting || next == TunnelDead || next == TunnelParked {
		t.slowLaneSince = time.Time{}
	}
	t.stateMu.Unlock()
	if next == TunnelStarting || next == TunnelDead || next == TunnelParked {
		t.slowLaneDegraded.Store(false)
		t.ResetEvictionState()
	}
	if prev != next && t.metrics != nil {
		t.metrics.Emit("tunnel", map[string]any{
			"tunnel_id": t.id,
			"event":     "state_change",
			"from":      string(prev),
			"to":        string(next),
		})
	}
}

func (t *TunnelInstance) Session() WorkerSession {
	t.sessMu.RLock()
	s := t.session
	t.sessMu.RUnlock()
	return s
}

func (t *TunnelInstance) setSession(s WorkerSession) {
	t.sessMu.Lock()
	old := t.session
	t.session = s
	t.sessMu.Unlock()
	if old != nil && old != s {
		_ = old.Close()
	}
}

// DialTarget opens an RFC 4254 direct-tcpip stream through this worker's active WorkerSession.
func (t *TunnelInstance) DialTarget(ctx context.Context, host string, port uint16) (net.Conn, error) {
	s := t.Session()
	if s == nil {
		return nil, errors.New("tunnel worker has no active ssh session")
	}
	return s.DialTarget(ctx, host, port)
}

func (t *TunnelInstance) IsSlowLaneDegraded() bool { return t.slowLaneDegraded.Load() }

func (t *TunnelInstance) SetSlowLaneDegraded(degraded bool) {
	prev := t.slowLaneDegraded.Swap(degraded)
	if prev != degraded && t.metrics != nil {
		t.metrics.Emit("tunnel", map[string]any{
			"tunnel_id":          t.id,
			"event":              "slow_lane_flag_change",
			"slow_lane_degraded": degraded,
		})
	}
}

func (t *TunnelInstance) IsEvictionTriggered() bool { return t.evictionTriggered.Load() }
func (t *TunnelInstance) MarkEvictionTriggered() bool {
	return t.evictionTriggered.CompareAndSwap(false, true)
}
func (t *TunnelInstance) MarkEvictDeferLogged() bool {
	return t.evictDeferLogged.CompareAndSwap(false, true)
}
func (t *TunnelInstance) ResetEvictionState() {
	t.evictionTriggered.Store(false)
	t.evictDeferLogged.Store(false)
}

func (t *TunnelInstance) TriggerEviction(reason string) bool {
	select {
	case t.evictCh <- reason:
		return true
	default:
		return false
	}
}

func (t *TunnelInstance) drainEvictSignal() {
	for {
		select {
		case <-t.evictCh:
		default:
			return
		}
	}
}

func (t *TunnelInstance) PMTU576Active() bool {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.pmtu576Active
}

func (t *TunnelInstance) EWMARTTMS() float64      { return math.Float64frombits(t.ewmaRTTBits.Load()) }
func (t *TunnelInstance) EWMAJitterMS() float64   { return math.Float64frombits(t.ewmaJitterBits.Load()) }
func (t *TunnelInstance) StreamErrorRate() float64 { return math.Float64frombits(t.streamErrRateBit.Load()) }
func (t *TunnelInstance) Rho(baselineMS float64) float64 {
	return ComputeRelativeOverhead(t.EWMARTTMS(), baselineMS)
}

func (t *TunnelInstance) RecordRTT(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	if ms <= 0 {
		ms = 1.0
	}
	prevSample := math.Float64frombits(t.lastRTTBits.Swap(math.Float64bits(ms)))
	if prevSample > 0 {
		delta := math.Abs(ms - prevSample)
		for {
			oldJBits := t.ewmaJitterBits.Load()
			oldJ := math.Float64frombits(oldJBits)
			nextJ := 0.75*oldJ + 0.25*delta
			if t.ewmaJitterBits.CompareAndSwap(oldJBits, math.Float64bits(nextJ)) {
				break
			}
		}
	}
	for {
		oldBits := t.ewmaRTTBits.Load()
		oldVal := math.Float64frombits(oldBits)
		nextVal := 0.75*oldVal + 0.25*ms
		if oldVal <= 0 {
			nextVal = ms
		}
		if t.ewmaRTTBits.CompareAndSwap(oldBits, math.Float64bits(nextVal)) {
			break
		}
	}
}

func (t *TunnelInstance) SetEWMARTT(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	if ms <= 0 {
		ms = 1.0
	}
	t.ewmaRTTBits.Store(math.Float64bits(ms))
	t.lastRTTBits.Store(math.Float64bits(ms))
}

func (t *TunnelInstance) RecordStreamSuccess() {
	for {
		oldBits := t.streamErrRateBit.Load()
		oldVal := math.Float64frombits(oldBits)
		nextVal := 0.85 * oldVal
		if nextVal < 0.0001 {
			nextVal = 0.0
		}
		if t.streamErrRateBit.CompareAndSwap(oldBits, math.Float64bits(nextVal)) {
			break
		}
	}
}

func (t *TunnelInstance) RecordStreamError() {
	for {
		oldBits := t.streamErrRateBit.Load()
		oldVal := math.Float64frombits(oldBits)
		nextVal := 0.85*oldVal + 0.15
		if nextVal > 1.0 {
			nextVal = 1.0
		}
		if t.streamErrRateBit.CompareAndSwap(oldBits, math.Float64bits(nextVal)) {
			break
		}
	}
}

func (t *TunnelInstance) RecordWANBytes(n uint64) {
	if n > 0 {
		t.lastWANBytes.Store(time.Now().UnixNano())
	}
}

func (t *TunnelInstance) LastWANBytesAt() time.Time {
	ns := t.lastWANBytes.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (t *TunnelInstance) TryAcquireSlotWithCap(capLimit int) bool {
	if capLimit < 1 {
		return false
	}
	for {
		cur := t.activeStreams.Load()
		if cur >= int64(capLimit) {
			return false
		}
		if t.activeStreams.CompareAndSwap(cur, cur+1) {
			t.totalRouted.Add(1)
			return true
		}
	}
}

func (t *TunnelInstance) ReleaseSlot() {
	for {
		cur := t.activeStreams.Load()
		if cur <= 0 {
			return
		}
		if t.activeStreams.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

func (t *TunnelInstance) QualityScore(baselineMS float64) float64 {
	denom := baselineMS
	if denom < 50.0 {
		denom = 50.0
	}
	rho := t.Rho(denom)
	jitterRatio := t.EWMAJitterMS() / denom
	errRate := t.StreamErrorRate()
	score := rho + 0.5*jitterRatio + 2.0*errRate
	if t.IsSlowLaneDegraded() || t.State() == TunnelDegraded {
		score *= 4.0
	}
	return score
}

func (t *TunnelInstance) RoutingScore() float64 {
	active := float64(t.activeStreams.Load())
	if active < 0 {
		active = 0
	}
	rtt := t.EWMARTTMS()
	if rtt < 1.0 {
		rtt = 1.0
	}
	penalty := 1.0 + 2.0*t.StreamErrorRate()
	if t.State() == TunnelDegraded || t.IsSlowLaneDegraded() {
		penalty *= 4.0
	}
	return (active + 1.0) * (rtt + 50.0) * penalty
}

func (t *TunnelInstance) SnapshotWithBaseline(baselineMS float64) TunnelSnapshot {
	t.stateMu.RLock()
	st := t.state
	lb := t.lastBootMS
	br := t.bootRetries
	wan := t.wanRemote
	pmtu576 := t.pmtu576Active
	t.stateMu.RUnlock()
	return TunnelSnapshot{
		ID:               t.id,
		State:            st,
		SlowLaneDegraded: t.slowLaneDegraded.Load(),
		WANRemote:        wan,
		PMTU576Active:    pmtu576,
		ActiveStreams:    t.activeStreams.Load(),
		MaxStreams:       t.maxStreams,
		EWMARTTMS:        round2(t.EWMARTTMS()),
		EWMAJitterMS:     round2(t.EWMAJitterMS()),
		RelativeRho:      round2(t.Rho(baselineMS)),
		StreamErrorRate:  round2(t.StreamErrorRate()),
		TotalRouted:      t.totalRouted.Load(),
		DialFailures:     t.dialFailures.Load(),
		BootRetries:      br,
		Restarts:         t.restarts.Load(),
		LastBootMS:       lb,
	}
}

// BootAndQualify connects an in-process WorkerSession and executes the Two-Stage 5-Tuple Boot Quality Gate.
func (t *TunnelInstance) BootAndQualify(
	ctx context.Context,
	peerMedianFn func(excludeID string) float64,
	underlayBaselineFn func() float64,
) (WorkerSession, BootQualityReport, error) {
	t.setState(TunnelStarting)
	t.drainEvictSignal()

	qualityRetries := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, BootQualityReport{}, err
		}
		bootStart := time.Now()
		bootCtx, cancelBoot := context.WithTimeout(ctx, t.cfg.BootTimeout)
		sess, err := t.transport.Connect(bootCtx, t.id)
		cancelBoot()
		if err != nil {
			var fatalErr *FatalBootError
			if errors.As(err, &fatalErr) {
				if t.logger != nil {
					t.logger.Log("FATAL_BOOT_ERROR", map[string]any{
						"tunnel_id": t.id,
						"code":      fatalErr.Code,
						"message":   fatalErr.Message,
					})
				}
				return nil, BootQualityReport{}, fatalErr
			}
			return nil, BootQualityReport{}, err
		}

		// Stage 1: Initial E2E direct-tcpip RTT sample(s).
		rtts := make([]time.Duration, 0, max(1, t.cfg.BootQualitySamples))
		failures := 0
		samples := t.cfg.BootQualitySamples
		if samples < 1 {
			samples = 1
		}
		for i := 0; i < samples; i++ {
			if i > 0 && t.sampleDel > 0 {
				tm := time.NewTimer(t.sampleDel)
				select {
				case <-ctx.Done():
					tm.Stop()
					_ = sess.Close()
					return nil, BootQualityReport{}, ctx.Err()
				case <-sess.Done():
					tm.Stop()
					_ = sess.Close()
					return nil, BootQualityReport{}, errors.New("session dropped during boot qualification")
				case <-tm.C:
				}
			}
			rtt, pErr := t.probeFn(ctx, sess, t.cfg.ProbeTarget, t.cfg.ProbeTimeout)
			if pErr != nil {
				failures++
				break
			}
			if i == 0 {
				t.vmReached.Store(true)
				t.stateMu.RLock()
				cb := t.onVMReached
				t.stateMu.RUnlock()
				if cb != nil {
					cb()
				}
			}
			rtts = append(rtts, rtt)
		}

		// Stage 2: Micro-payload bidirectional byte transit check.
		microOK := true
		var microRTT time.Duration
		if t.cfg.BootMicroPayloadCheck && failures == 0 && t.cfg.BootQualitySamples > 1 {
			var mpErr error
			microRTT, mpErr = t.microFn(ctx, sess, t.cfg.ProbeTarget, t.cfg.ProbeTimeout)
			if mpErr != nil {
				microOK = false
			}
		}

		bootDuration := time.Since(bootStart)
		var peerMedian float64
		if peerMedianFn != nil {
			peerMedian = peerMedianFn(t.id)
		}
		var underlayRaw float64
		if underlayBaselineFn != nil {
			underlayRaw = underlayBaselineFn()
		}
		qRep := EvaluateFastLaneGateNormalized(t.cfg, bootDuration, rtts, failures, peerMedian, underlayRaw, microOK, microRTT)
		wan := sess.WANRemote()
		pmtu576 := sess.PMTU576Active() || (t.cfg.PMTU576SafeMode && IsPMTU576RelayIP(wan))

		canRetry := true
		deferReason := ""
		if !qRep.Accepted && t.guard != nil {
			if ok, why := t.guard.CanAllowNonConsuming(); !ok && why != "min_call_spacing" {
				canRetry = false
				deferReason = why
			}
		}

		if !qRep.Accepted && qualityRetries < t.cfg.BootQualityMaxRetries && (canRetry || qRep.Failures > 0 || !qRep.MicroPayloadOK) {
			qualityRetries++
			if t.logger != nil {
				t.logger.Log("BOOT_QUALITY_REJECT", map[string]any{
					"tunnel_id":     t.id,
					"reason":        qRep.Reason,
					"p50_ms":        qRep.P50MS,
					"jitter_ms":     qRep.JitterMS,
					"relative_rho":  qRep.RelativeRho,
					"quality_retry": qualityRetries,
					"wan_remote":    wan,
				})
			}
			_ = sess.Close()
			tm := time.NewTimer(t.retryDel)
			select {
			case <-ctx.Done():
				tm.Stop()
				return nil, BootQualityReport{}, ctx.Err()
			case <-tm.C:
			}
			continue
		}

		if !qRep.Accepted && t.logger != nil {
			t.logger.Log("BOOT_QUALITY_ACCEPTED_BEST_EFFORT", map[string]any{
				"tunnel_id":          t.id,
				"reason":             qRep.Reason,
				"p50_ms":             qRep.P50MS,
				"relative_rho":       qRep.RelativeRho,
				"budget_constrained": !canRetry,
				"defer_reason":       deferReason,
			})
		}

		t.setSession(sess)
		if qRep.P50MS > 0 {
			t.SetEWMARTT(time.Duration(qRep.P50MS) * time.Millisecond)
		} else if len(rtts) > 0 {
			t.SetEWMARTT(rtts[0])
		}
		t.streamErrRateBit.Store(math.Float64bits(0.0))
		t.ewmaJitterBits.Store(math.Float64bits(float64(qRep.JitterMS)))
		t.slowLaneDegraded.Store(false)

		t.stateMu.Lock()
		t.lastBootMS = bootDuration.Milliseconds()
		t.bootRetries = qualityRetries
		t.wanRemote = wan
		t.pmtu576Active = pmtu576
		t.slowLaneSince = time.Time{}
		t.stateMu.Unlock()
		t.setState(TunnelHealthy)

		if t.metrics != nil {
			t.metrics.Emit("tunnel", map[string]any{
				"tunnel_id":        t.id,
				"event":            "boot_ready",
				"boot_ms":          bootDuration.Milliseconds(),
				"p50_ms":           qRep.P50MS,
				"jitter_ms":        qRep.JitterMS,
				"relative_rho":     qRep.RelativeRho,
				"micro_payload_ok": qRep.MicroPayloadOK,
				"wan_remote":       wan,
				"pmtu576_active":   pmtu576,
			})
		}
		return sess, qRep, nil
	}
}

// DrainAndClose gracefully drains active streams up to drainTimeout and closes the in-process SSH session.
func (t *TunnelInstance) DrainAndClose(drainTimeout time.Duration, finalState TunnelState) {
	t.setState(TunnelDraining)
	if drainTimeout > 0 {
		deadline := time.Now().Add(drainTimeout)
		for t.activeStreams.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(15 * time.Millisecond)
		}
	}
	t.setSession(nil)
	t.setState(finalState)
}
