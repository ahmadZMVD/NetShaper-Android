package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type BootQualityReport struct {
	Accepted       bool
	Reason         string
	Samples        int
	Failures       int
	MinMS          int64
	P50MS          int64
	MaxMS          int64
	JitterMS       int64
	SlowBoot       bool
	BootDurMS      int64
	MicroPayloadOK bool
	MicroPayloadMS int64
	PeerMedianMS   float64
	UnderlayRawMS  float64
	RelativeRho    float64
}

// IsGitHubHost enforces the hard WAF invariant: underlay baseline probing NEVER touches GitHub.
func IsGitHubHost(target string) bool {
	s := strings.TrimSpace(target)
	if s == "" {
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."), "[]")
	return host == "github.com" || strings.HasSuffix(host, ".github.com") ||
		host == "githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
}

// MeasureUnderlayBaseline executes a dual-stack 1-RTT direct TLS ClientHello->ServerHello probe
// against non-GitHub targets (1.1.1.1:443, 20.120.56.11:443, [2606:4700:4700::1111]:443).
func MeasureUnderlayBaseline(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error) {
	if len(targets) == 0 {
		targets = []string{"1.1.1.1:443", "20.120.56.11:443", "[2606:4700:4700::1111]:443"}
	}
	if timeout <= 0 {
		timeout = DefaultUnderlayProbeTimeout
	}
	for _, t := range targets {
		if IsGitHubHost(t) {
			return 0, t, fmt.Errorf("underlay baseline refused GitHub host target %q (WAF safety invariant)", t)
		}
	}
	var lastErr error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		rtt, err := probeDirectTLS(ctx, target, timeout)
		if err == nil {
			return rtt, target, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no underlay baseline targets succeeded")
	}
	return 0, "", lastErr
}

func probeDirectTLS(ctx context.Context, targetAddr string, timeout time.Duration) (time.Duration, error) {
	deadline := time.Now().Add(timeout)
	if parentDL, ok := ctx.Deadline(); ok && parentDL.Before(deadline) {
		deadline = parentDL
	}
	dialCtx, cancelDial := context.WithDeadline(ctx, deadline)
	dialer := &net.Dialer{Timeout: time.Until(deadline)}
	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancelDial()
	if err != nil {
		return 0, fmt.Errorf("underlay dial %s: %w", targetAddr, err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	_ = conn.SetDeadline(deadline)
	tlsStart := time.Now()
	if _, err := conn.Write(minimalTLSClientHelloProbe()); err != nil {
		return 0, fmt.Errorf("underlay write %s: %w", targetAddr, err)
	}
	var resp [5]byte
	n, err := conn.Read(resp[:])
	if n > 0 {
		return time.Since(tlsStart), nil
	}
	if err != nil {
		return 0, fmt.Errorf("underlay read %s: %w", targetAddr, err)
	}
	return 0, fmt.Errorf("underlay read %s: 0 bytes", targetAddr)
}

func minimalTLSClientHelloProbe() []byte {
	body := make([]byte, 0, 43)
	body = append(body, 0x03, 0x03)
	for i := 0; i < 32; i++ {
		body = append(body, byte(0x41+i))
	}
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00)
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01, 0x00, byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)
	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

// ProbeDirectSSH executes Stage 1 of the Two-Stage Boot Quality Gate directly over WorkerSession.DialTarget.
func ProbeDirectSSH(ctx context.Context, sess WorkerSession, targetAddr string, timeout time.Duration) (time.Duration, error) {
	if sess == nil {
		return 0, errors.New("nil worker session")
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	host, port, err := splitHostPortUint16(targetAddr)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	pCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := sess.DialTarget(pCtx, host, port)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// ProbeDirectSSHMicroPayload executes Stage 2 of the Two-Stage Boot Gate directly over WorkerSession.DialTarget,
// sending a compact TLS ClientHello and verifying live bidirectional payload transit.
func ProbeDirectSSHMicroPayload(ctx context.Context, sess WorkerSession, targetAddr string, timeout time.Duration) (time.Duration, error) {
	if sess == nil {
		return 0, errors.New("nil worker session")
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	host, port, err := splitHostPortUint16(targetAddr)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	deadline := start.Add(timeout)
	pCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := sess.DialTarget(pCtx, host, port)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(minimalTLSClientHelloProbe()); err != nil {
		return 0, fmt.Errorf("micro-payload write: %w", err)
	}
	var resp [5]byte
	n, err := conn.Read(resp[:])
	if n > 0 {
		return time.Since(start), nil
	}
	if err != nil {
		return 0, fmt.Errorf("micro-payload read: %w", err)
	}
	return 0, errors.New("micro-payload read: 0 bytes")
}

// ComputeRelativeOverhead calculates rho_i = EWMA_RTT_i / max(B_raw, 50ms).
func ComputeRelativeOverhead(ewmaRTTMS, baselineMS float64) float64 {
	if ewmaRTTMS <= 0 {
		return 1.0
	}
	denom := baselineMS
	if denom < 50.0 {
		denom = 50.0
	}
	return ewmaRTTMS / denom
}

func EvaluateBootQuality(cfg Config, bootDuration time.Duration, rtts []time.Duration, failures int) BootQualityReport {
	slowBoot := cfg.BootSlowThreshold > 0 && bootDuration >= cfg.BootSlowThreshold
	rep := BootQualityReport{
		Accepted:       true,
		Reason:         "ok",
		Samples:        len(rtts),
		Failures:       failures,
		SlowBoot:       slowBoot,
		BootDurMS:      bootDuration.Milliseconds(),
		MicroPayloadOK: true,
	}
	if len(rtts) > 0 {
		sorted := make([]time.Duration, len(rtts))
		copy(sorted, rtts)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		minD := sorted[0]
		maxD := sorted[len(sorted)-1]
		p50D := sorted[(len(sorted)-1)/2]
		jitterD := maxD - minD

		rep.MinMS = minD.Milliseconds()
		rep.P50MS = p50D.Milliseconds()
		rep.MaxMS = maxD.Milliseconds()
		rep.JitterMS = jitterD.Milliseconds()

		if cfg.BootQualitySamples <= 1 {
			rep.Reason = "gate_disabled"
			return rep
		}
		if failures > 0 {
			rep.Accepted = false
			rep.Reason = "qualification_probe_failed"
			return rep
		}
		if cfg.BootQualityMaxRTT > 0 && p50D > cfg.BootQualityMaxRTT {
			rep.Accepted = false
			rep.Reason = "idle_rtt_exceeded"
			return rep
		}
		if cfg.BootQualityMaxJitter > 0 && jitterD > cfg.BootQualityMaxJitter {
			rep.Accepted = false
			rep.Reason = "idle_jitter_exceeded"
			return rep
		}
		if slowBoot && cfg.BootSlowMaxRTT > 0 && p50D > cfg.BootSlowMaxRTT {
			rep.Accepted = false
			rep.Reason = "slow_boot_elevated_rtt"
			return rep
		}
		if slowBoot && cfg.BootSlowMaxJitter > 0 && jitterD > cfg.BootSlowMaxJitter {
			rep.Accepted = false
			rep.Reason = "slow_boot_elevated_jitter"
			return rep
		}
		return rep
	}
	if cfg.BootQualitySamples > 1 && failures > 0 {
		rep.Accepted = false
		rep.Reason = "qualification_probe_failed"
	}
	return rep
}

func EvaluateFastLaneGate(
	cfg Config,
	bootDuration time.Duration,
	rtts []time.Duration,
	failures int,
	peerMedianMS float64,
	microPayloadOK bool,
	microPayloadRTT time.Duration,
) BootQualityReport {
	rep := EvaluateBootQuality(cfg, bootDuration, rtts, failures)
	rep.PeerMedianMS = round2(peerMedianMS)
	rep.MicroPayloadOK = microPayloadOK
	rep.MicroPayloadMS = microPayloadRTT.Milliseconds()
	if !rep.Accepted || cfg.BootQualitySamples <= 1 {
		return rep
	}
	if cfg.BootFastLaneMaxRTT > 0 && rep.P50MS > cfg.BootFastLaneMaxRTT.Milliseconds() {
		rep.Accepted = false
		rep.Reason = "mci_slow_lane_detected"
		return rep
	}
	if peerMedianMS > 0 {
		dynCeiling := peerMedianMS * 2.5
		if dynCeiling < 600.0 {
			dynCeiling = 600.0
		}
		if float64(rep.P50MS) > dynCeiling {
			rep.Accepted = false
			rep.Reason = "slow_lane_vs_peer"
			return rep
		}
	}
	if cfg.BootMicroPayloadCheck && !microPayloadOK {
		rep.Accepted = false
		rep.Reason = "micro_payload_failed"
		return rep
	}
	return rep
}

// IsSlowLinkLatencyReason reports whether EvaluateFastLaneGateNormalized rejected solely due
// to latency/jitter/lane-ratio thresholds while probes and micro-payload data transit succeeded.
func IsSlowLinkLatencyReason(reason string) bool {
	switch reason {
	case "slow_lane_vs_underlay_baseline",
		"idle_jitter_exceeded",
		"slow_boot_elevated_jitter",
		"slow_boot_elevated_rtt",
		"idle_rtt_exceeded",
		"mci_slow_lane_detected",
		"slow_lane_vs_peer":
		return true
	default:
		return false
	}
}

// EvaluateFastLaneGateNormalized preserves 100% parity with Windows v6.4 baseline-normalized boot qualification.
func EvaluateFastLaneGateNormalized(
	cfg Config,
	bootDuration time.Duration,
	rtts []time.Duration,
	failures int,
	peerMedianMS float64,
	underlayRawMS float64,
	microPayloadOK bool,
	microPayloadRTT time.Duration,
) BootQualityReport {
	effCfg := cfg
	if underlayRawMS > 0 {
		const (
			maxAdaptiveFastRTT    = 1800 * time.Millisecond
			maxAdaptiveSlowRTT    = 1500 * time.Millisecond
			maxAdaptiveFastJitter = 1400 * time.Millisecond
			maxAdaptiveSlowJitter = 1100 * time.Millisecond
		)
		fastRatio := cfg.FastLaneMaxRatio
		if fastRatio < 1.0 {
			fastRatio = DefaultFastLaneMaxRatio
		}
		adaptiveMax := time.Duration(underlayRawMS*fastRatio) * time.Millisecond
		if adaptiveMax > maxAdaptiveFastRTT {
			adaptiveMax = maxAdaptiveFastRTT
		}
		if adaptiveMax > effCfg.BootQualityMaxRTT && effCfg.BootQualityMaxRTT > 0 {
			effCfg.BootQualityMaxRTT = adaptiveMax
		}
		if adaptiveMax > effCfg.BootFastLaneMaxRTT && effCfg.BootFastLaneMaxRTT > 0 {
			effCfg.BootFastLaneMaxRTT = adaptiveMax
		}
		slowRatio := fastRatio * 0.85
		if slowRatio < 1.6 {
			slowRatio = 1.6
		}
		if slowRatio > fastRatio {
			slowRatio = fastRatio
		}
		adaptiveSlowMax := time.Duration(underlayRawMS*slowRatio) * time.Millisecond
		if adaptiveSlowMax > maxAdaptiveSlowRTT {
			adaptiveSlowMax = maxAdaptiveSlowRTT
		}
		if adaptiveSlowMax > effCfg.BootSlowMaxRTT && effCfg.BootSlowMaxRTT > 0 {
			effCfg.BootSlowMaxRTT = adaptiveSlowMax
		}
		maxJitterRatio := fastRatio * 0.90
		if maxJitterRatio < 1.75 {
			maxJitterRatio = 1.75
		}
		if maxJitterRatio > fastRatio {
			maxJitterRatio = fastRatio
		}
		adaptiveMaxJitter := time.Duration(underlayRawMS*maxJitterRatio) * time.Millisecond
		if adaptiveMaxJitter > maxAdaptiveFastJitter {
			adaptiveMaxJitter = maxAdaptiveFastJitter
		}
		if adaptiveMaxJitter > effCfg.BootQualityMaxJitter && effCfg.BootQualityMaxJitter > 0 {
			effCfg.BootQualityMaxJitter = adaptiveMaxJitter
		}
		slowJitterRatio := slowRatio * 0.80
		if slowJitterRatio < 1.45 {
			slowJitterRatio = 1.45
		}
		if slowJitterRatio > fastRatio {
			slowJitterRatio = fastRatio
		}
		adaptiveSlowJitter := time.Duration(underlayRawMS*slowJitterRatio) * time.Millisecond
		if adaptiveSlowJitter > maxAdaptiveSlowJitter {
			adaptiveSlowJitter = maxAdaptiveSlowJitter
		}
		if adaptiveSlowJitter > effCfg.BootSlowMaxJitter && effCfg.BootSlowMaxJitter > 0 {
			effCfg.BootSlowMaxJitter = adaptiveSlowJitter
		}
	}

	rep := EvaluateFastLaneGate(effCfg, bootDuration, rtts, failures, peerMedianMS, microPayloadOK, microPayloadRTT)
	rep.UnderlayRawMS = round2(underlayRawMS)
	if underlayRawMS > 0 && rep.P50MS > 0 {
		rho := ComputeRelativeOverhead(float64(rep.P50MS), underlayRawMS)
		rep.RelativeRho = round2(rho)
		evictRatio := cfg.SlowLaneEvictRatio
		if evictRatio <= 1.0 {
			evictRatio = DefaultSlowLaneEvictRatio
		}
		if rep.Accepted && cfg.BootQualitySamples > 1 && rho > evictRatio {
			rep.Accepted = false
			rep.Reason = "slow_lane_vs_underlay_baseline"
		}
	}
	return rep
}
