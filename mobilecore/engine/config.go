package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	CoreVersionString = "v7.0-mobile-core6.4"

	DefaultLocalHost = "127.0.0.1"
	DefaultLocalPort = uint16(1080)

	// Exact v6.4 pool & multiplexed SSH channel defaults.
	DefaultPoolSize                     = 2
	DefaultRecommendedMaxPoolSize       = 3
	DefaultMaxPoolSize                  = 4
	DefaultMaxActiveConns               = 64
	DefaultPerTunnelMaxConns            = 32
	DefaultMaxQueuedConns               = 128
	DefaultCopyBufferSize               = 16 * 1024
	DefaultPMTU576CopyBufSize           = 8 * 1024
	DefaultProbeInterval                = 25 * time.Second
	DefaultDegradedProbeInterval        = 8 * time.Second
	DefaultProbeTimeout                 = 12 * time.Second
	DefaultProbeTarget                  = "1.1.1.1:443"
	DefaultBootTimeout                  = 90 * time.Second
	DefaultDialTimeout                  = 10 * time.Second // WAN direct-tcpip open inside Codespace
	DefaultSOCKS5HandshakeTimeout       = 5 * time.Second
	DefaultIdleTimeout                  = 60 * time.Second
	DefaultPressureIdleTimeout          = 12 * time.Second
	DefaultStreamingIdleTimeout         = 180 * time.Second
	DefaultStreamingPressureIdleTimeout = 20 * time.Second // strictly < DefaultSemaphoreWaitTimeout (25s)
	DefaultStalledHandshakeMaxDownBytes = 128
	DefaultPressureThresholdPct         = 75
	DefaultHalfCloseDrainTimeout        = 15 * time.Second
	DefaultTCPKeepAlivePeriod           = 8 * time.Second  // strictly < 15s aggressive CG-NAT drop
	DefaultTCPUserTimeout               = 25 * time.Second // Linux/Android kernel RTO hard abort
	DefaultStopTimeout                  = 10 * time.Second
	DefaultDegradedRTTThreshold         = 4000 * time.Millisecond
	DefaultBreakerThreshold             = 5
	DefaultBreakerMinWindow             = 45 * time.Second
	DefaultBackoffMin                   = 2 * time.Second
	DefaultBackoffMax                   = 30 * time.Second
	DefaultSemaphoreWaitTimeout         = 25 * time.Second // strictly > StreamingPressureIdleTimeout (20s)
	DefaultSummaryLogInterval           = 60 * time.Second
	DefaultSSHAliveInterval             = 10 // strictly < 15s CG-NAT drop (30s dead-tunnel detect)
	DefaultSSHAliveCountMax             = 3

	// Two-Stage 5-tuple Boot Quality Gate.
	DefaultBootQualitySamples    = 3
	DefaultBootQualityMaxRetries = 2
	DefaultBootQualityMaxRTT     = 850 * time.Millisecond
	DefaultBootQualityMaxJitter  = 700 * time.Millisecond
	DefaultBootSlowThreshold     = 13 * time.Second
	DefaultBootSlowMaxRTT        = 550 * time.Millisecond
	DefaultBootSlowMaxJitter     = 400 * time.Millisecond
	DefaultBootFastLaneMaxRTT    = 1200 * time.Millisecond

	// Baseline-Normalized Quality Scoring, Schmitt-Trigger Hysteresis & Slow-Lane Eviction.
	DefaultUnderlayProbeInterval   = 35 * time.Second
	DefaultUnderlayProbeTimeout    = 5 * time.Second
	DefaultUnderlayProbeTargets    = "1.1.1.1:443,20.120.56.11:443,[2606:4700:4700::1111]:443"
	DefaultUnderlayBaselineMS      = 250.0
	DefaultHysteresisDwellWindow   = 25 * time.Second
	DefaultHysteresisRelMargin     = 0.30
	DefaultHysteresisAbsMargin     = 100 * time.Millisecond
	DefaultFastLaneMaxRatio        = 2.2
	DefaultSlowLaneEvictRatio      = 3.5
	DefaultSlowLaneEvictWindow     = 30 * time.Second
	DefaultSlowLaneUnderlayCeiling = 800 * time.Millisecond

	// Stage-2 Anti-Drop Stability, Multi-Metric Routing & Low-Speed Network Resilience.
	DefaultSlowLaneAbsoluteFloor      = 900 * time.Millisecond
	DefaultSlowLanePeerAdvantageMS    = 250.0
	DefaultSlowLanePeerAdvantageRatio = 1.50
	DefaultActiveStreamLivenessWindow = 30 * time.Second
	DefaultActiveStreamStallWindow    = 45 * time.Second
	DefaultActiveStreamMaxErrRate     = 0.20 // strictly in (E_1=0.15, E_2=0.2775)
	DefaultBlackholeErrRate           = 0.35 // strictly in (E_2=0.2775, E_3=0.3859)
	DefaultSoleWorkingMaxRTT          = 6000 * time.Millisecond
	DefaultRoutingProfile             = "balanced"

	// GitHub API & WAF Guard.
	DefaultGitHubMaxCallsPer5Min      = 6
	DefaultGitHubMaxCallsPerHour      = 24
	DefaultGitHubMinCallSpacing       = 2 * time.Second
	DefaultGitHubRateLimitBaseBackoff = 15 * time.Second
	DefaultGitHubRateLimitMaxBackoff  = 5 * time.Minute
	DefaultGitHubWarmCacheTTL         = 10 * time.Minute

	// Mobile power, handover & flash storage safety defaults.
	DefaultIdleLightAfter           = 60 * time.Second
	DefaultIdleDeepAfter            = 10 * time.Minute
	DefaultIdleMinActiveDwell       = 30 * time.Minute
	DefaultIdleUnderlayInterval     = 90 * time.Second
	DefaultIdleWorkerProbeInterval  = 60 * time.Second
	DefaultNetworkDebounceInterval  = 1500 * time.Millisecond
	DefaultSuspendJumpThreshold     = 14 * time.Second
	DefaultMaxLogFileBytes          = 2 * 1024 * 1024
	DefaultLogFileName              = "netshaper_mobile.log"
	DefaultMetricsFileName          = "netshaper_mobile_metrics.ndjson"
	DefaultCodespaceCacheFileName   = "codespace_state_cache.json"
	DefaultGitHubAPIBaseURL         = "https://api.github.com"
	DefaultGitHubOAuthBaseURL       = "https://github.com"
)

// MobileConfigJSON is the flat JSON payload passed from Kotlin into mobilecore.Start(configJSON, cb).
type MobileConfigJSON struct {
	GitHubToken       string `json:"github_token"`
	CodespaceName     string `json:"codespace_name"`
	LocalHost         string `json:"local_host,omitempty"`
	LocalPort         *int   `json:"local_port,omitempty"`
	DataDir           string `json:"data_dir"`
	PoolSize          int    `json:"pool_size,omitempty"`
	StopOnExit        *bool  `json:"stop_on_exit,omitempty"`
	EnableIdleParking *bool  `json:"enable_idle_parking,omitempty"`
	EnableMetricsLog  bool   `json:"enable_metrics_log,omitempty"`
	ProbeTarget       string `json:"probe_target,omitempty"`
	GitHubAPIBaseURL  string `json:"github_api_base_url,omitempty"`
}

// Config holds all runtime parameters for the mobilecore pure-Go engine.
type Config struct {
	GitHubToken                  string
	CodespaceName                string
	DataDir                      string
	GitHubAPIBaseURL             string
	GitHubOAuthBaseURL           string
	LocalHost                    string
	LocalPort                    uint16
	PoolSize                     int
	MaxActiveConns               int
	PerTunnelMaxConns            int
	MaxQueuedConns               int
	CopyBufferSize               int
	PMTU576SafeMode              bool
	PMTU576CopyBufSize           int
	ProbeInterval                time.Duration
	DegradedProbeInterval        time.Duration
	ProbeTimeout                 time.Duration
	ProbeTarget                  string
	BootTimeout                  time.Duration
	DialTimeout                  time.Duration
	SOCKS5HandshakeTimeout       time.Duration
	IdleTimeout                  time.Duration
	PressureIdleTimeout          time.Duration
	StreamingIdleTimeout         time.Duration
	StreamingPressureIdleTimeout time.Duration
	StalledHandshakeMaxDownBytes int
	PressureThresholdPct         int
	HalfCloseDrainTimeout        time.Duration
	TCPKeepAlivePeriod           time.Duration
	TCPUserTimeout               time.Duration
	StopTimeout                  time.Duration
	StopOnExit                   bool
	DegradedRTTThreshold         time.Duration
	BreakerThreshold             int
	BreakerMinWindow             time.Duration
	BackoffMin                   time.Duration
	BackoffMax                   time.Duration
	SemaphoreWaitTimeout         time.Duration
	SummaryLogInterval           time.Duration
	SSHServerAliveInterval       int
	SSHServerAliveCountMax       int
	BootQualitySamples           int
	BootQualityMaxRetries        int
	BootQualityMaxRTT            time.Duration
	BootQualityMaxJitter         time.Duration
	BootSlowThreshold            time.Duration
	BootSlowMaxRTT               time.Duration
	BootSlowMaxJitter            time.Duration
	BootFastLaneMaxRTT           time.Duration
	BootMicroPayloadCheck        bool
	UnderlayProbeInterval        time.Duration
	UnderlayProbeTimeout         time.Duration
	UnderlayProbeTargets         string
	UnderlayBaselineMS           float64
	HysteresisDwellWindow        time.Duration
	HysteresisRelMargin          float64
	HysteresisAbsMargin          time.Duration
	FastLaneMaxRatio             float64
	SlowLaneEvictRatio           float64
	SlowLaneEvictWindow          time.Duration
	SlowLaneUnderlayCeiling      time.Duration
	SlowLaneAbsoluteFloor        time.Duration
	SlowLanePeerAdvantageMS      float64
	SlowLanePeerAdvantageRatio   float64
	ActiveStreamShieldEnabled    bool
	ActiveStreamLivenessWindow   time.Duration
	ActiveStreamStallWindow      time.Duration
	ActiveStreamMaxErrRate       float64
	BlackholeErrRate             float64
	SoleWorkingMaxRTT            time.Duration
	RoutingProfile               string
	GitHubMaxCallsPer5Min        int
	GitHubMaxCallsPerHour        int
	GitHubMinCallSpacing         time.Duration
	GitHubRateLimitBase          time.Duration
	GitHubRateLimitMax           time.Duration
	GitHubWarmCacheTTL           time.Duration
	EnableIdleParking            bool
	IdleLightAfter               time.Duration
	IdleDeepAfter                time.Duration
	IdleMinActiveDwell           time.Duration
	IdleUnderlayInterval         time.Duration
	IdleWorkerProbeInterval      time.Duration
	NetworkDebounceInterval      time.Duration
	SuspendJumpThreshold         time.Duration
	MaxLogFileBytes              int64
	EnableMetricsLog             bool
	AllowInsecureLocalEndpoints  bool // strictly for offline loopback mock tests
}

// DefaultConfig returns production-hardened mobilecore defaults preserving 100% of v6.4 invariants.
func DefaultConfig() Config {
	return Config{
		GitHubAPIBaseURL:             DefaultGitHubAPIBaseURL,
		GitHubOAuthBaseURL:           DefaultGitHubOAuthBaseURL,
		LocalHost:                    DefaultLocalHost,
		LocalPort:                    DefaultLocalPort,
		PoolSize:                     DefaultPoolSize,
		MaxActiveConns:               DefaultMaxActiveConns,
		PerTunnelMaxConns:            DefaultPerTunnelMaxConns,
		MaxQueuedConns:               DefaultMaxQueuedConns,
		CopyBufferSize:               DefaultCopyBufferSize,
		PMTU576SafeMode:              true,
		PMTU576CopyBufSize:           DefaultPMTU576CopyBufSize,
		ProbeInterval:                DefaultProbeInterval,
		DegradedProbeInterval:        DefaultDegradedProbeInterval,
		ProbeTimeout:                 DefaultProbeTimeout,
		ProbeTarget:                  DefaultProbeTarget,
		BootTimeout:                  DefaultBootTimeout,
		DialTimeout:                  DefaultDialTimeout,
		SOCKS5HandshakeTimeout:       DefaultSOCKS5HandshakeTimeout,
		IdleTimeout:                  DefaultIdleTimeout,
		PressureIdleTimeout:          DefaultPressureIdleTimeout,
		StreamingIdleTimeout:         DefaultStreamingIdleTimeout,
		StreamingPressureIdleTimeout: DefaultStreamingPressureIdleTimeout,
		StalledHandshakeMaxDownBytes: DefaultStalledHandshakeMaxDownBytes,
		PressureThresholdPct:         DefaultPressureThresholdPct,
		HalfCloseDrainTimeout:        DefaultHalfCloseDrainTimeout,
		TCPKeepAlivePeriod:           DefaultTCPKeepAlivePeriod,
		TCPUserTimeout:               DefaultTCPUserTimeout,
		StopTimeout:                  DefaultStopTimeout,
		StopOnExit:                   true,
		DegradedRTTThreshold:         DefaultDegradedRTTThreshold,
		BreakerThreshold:             DefaultBreakerThreshold,
		BreakerMinWindow:             DefaultBreakerMinWindow,
		BackoffMin:                   DefaultBackoffMin,
		BackoffMax:                   DefaultBackoffMax,
		SemaphoreWaitTimeout:         DefaultSemaphoreWaitTimeout,
		SummaryLogInterval:           DefaultSummaryLogInterval,
		SSHServerAliveInterval:       DefaultSSHAliveInterval,
		SSHServerAliveCountMax:       DefaultSSHAliveCountMax,
		BootQualitySamples:           DefaultBootQualitySamples,
		BootQualityMaxRetries:        DefaultBootQualityMaxRetries,
		BootQualityMaxRTT:            DefaultBootQualityMaxRTT,
		BootQualityMaxJitter:         DefaultBootQualityMaxJitter,
		BootSlowThreshold:            DefaultBootSlowThreshold,
		BootSlowMaxRTT:               DefaultBootSlowMaxRTT,
		BootSlowMaxJitter:            DefaultBootSlowMaxJitter,
		BootFastLaneMaxRTT:           DefaultBootFastLaneMaxRTT,
		BootMicroPayloadCheck:        true,
		UnderlayProbeInterval:        DefaultUnderlayProbeInterval,
		UnderlayProbeTimeout:         DefaultUnderlayProbeTimeout,
		UnderlayProbeTargets:         DefaultUnderlayProbeTargets,
		UnderlayBaselineMS:           DefaultUnderlayBaselineMS,
		HysteresisDwellWindow:        DefaultHysteresisDwellWindow,
		HysteresisRelMargin:          DefaultHysteresisRelMargin,
		HysteresisAbsMargin:          DefaultHysteresisAbsMargin,
		FastLaneMaxRatio:             DefaultFastLaneMaxRatio,
		SlowLaneEvictRatio:           DefaultSlowLaneEvictRatio,
		SlowLaneEvictWindow:          DefaultSlowLaneEvictWindow,
		SlowLaneUnderlayCeiling:      DefaultSlowLaneUnderlayCeiling,
		SlowLaneAbsoluteFloor:        DefaultSlowLaneAbsoluteFloor,
		SlowLanePeerAdvantageMS:      DefaultSlowLanePeerAdvantageMS,
		SlowLanePeerAdvantageRatio:   DefaultSlowLanePeerAdvantageRatio,
		ActiveStreamShieldEnabled:    true,
		ActiveStreamLivenessWindow:   DefaultActiveStreamLivenessWindow,
		ActiveStreamStallWindow:      DefaultActiveStreamStallWindow,
		ActiveStreamMaxErrRate:       DefaultActiveStreamMaxErrRate,
		BlackholeErrRate:             DefaultBlackholeErrRate,
		SoleWorkingMaxRTT:            DefaultSoleWorkingMaxRTT,
		RoutingProfile:               DefaultRoutingProfile,
		GitHubMaxCallsPer5Min:        DefaultGitHubMaxCallsPer5Min,
		GitHubMaxCallsPerHour:        DefaultGitHubMaxCallsPerHour,
		GitHubMinCallSpacing:         DefaultGitHubMinCallSpacing,
		GitHubRateLimitBase:          DefaultGitHubRateLimitBaseBackoff,
		GitHubRateLimitMax:           DefaultGitHubRateLimitMaxBackoff,
		GitHubWarmCacheTTL:           DefaultGitHubWarmCacheTTL,
		EnableIdleParking:            true,
		IdleLightAfter:               DefaultIdleLightAfter,
		IdleDeepAfter:                DefaultIdleDeepAfter,
		IdleMinActiveDwell:           DefaultIdleMinActiveDwell,
		IdleUnderlayInterval:         DefaultIdleUnderlayInterval,
		IdleWorkerProbeInterval:      DefaultIdleWorkerProbeInterval,
		NetworkDebounceInterval:      DefaultNetworkDebounceInterval,
		SuspendJumpThreshold:         DefaultSuspendJumpThreshold,
		MaxLogFileBytes:              DefaultMaxLogFileBytes,
		EnableMetricsLog:             false,
	}
}

// ParseMobileConfigJSON merges JSON fields into DefaultConfig and validates invariants.
func ParseMobileConfigJSON(rawJSON string) (Config, error) {
	cfg := DefaultConfig()
	if strings.TrimSpace(rawJSON) == "" {
		return cfg, errors.New("config JSON must not be empty")
	}
	var in MobileConfigJSON
	if err := json.Unmarshal([]byte(rawJSON), &in); err != nil {
		return cfg, fmt.Errorf("parse config JSON: %w", err)
	}
	cfg.GitHubToken = strings.TrimSpace(in.GitHubToken)
	cfg.CodespaceName = strings.TrimSpace(in.CodespaceName)
	cfg.DataDir = strings.TrimSpace(in.DataDir)
	if strings.TrimSpace(in.LocalHost) != "" {
		cfg.LocalHost = strings.TrimSpace(in.LocalHost)
	}
	if in.LocalPort != nil {
		if *in.LocalPort < 0 || *in.LocalPort > 65535 {
			return cfg, fmt.Errorf("invalid local_port: %d", *in.LocalPort)
		}
		cfg.LocalPort = uint16(*in.LocalPort)
	}
	if in.PoolSize > 0 {
		cfg.PoolSize = in.PoolSize
	}
	if in.StopOnExit != nil {
		cfg.StopOnExit = *in.StopOnExit
	}
	if in.EnableIdleParking != nil {
		cfg.EnableIdleParking = *in.EnableIdleParking
	}
	cfg.EnableMetricsLog = in.EnableMetricsLog
	if strings.TrimSpace(in.ProbeTarget) != "" {
		cfg.ProbeTarget = strings.TrimSpace(in.ProbeTarget)
	}
	if strings.TrimSpace(in.GitHubAPIBaseURL) != "" {
		cfg.GitHubAPIBaseURL = strings.TrimRight(strings.TrimSpace(in.GitHubAPIBaseURL), "/")
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ParsedUnderlayTargets returns trimmed non-empty direct underlay probe targets.
func (c Config) ParsedUnderlayTargets() []string {
	raw := strings.TrimSpace(c.UnderlayProbeTargets)
	if raw == "" {
		raw = DefaultUnderlayProbeTargets
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// LocalAddr returns host:port for the local SOCKS5 listener (v2rayNG outbound).
func (c Config) LocalAddr() string {
	host := strings.TrimSpace(c.LocalHost)
	if host == "" {
		host = DefaultLocalHost
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", c.LocalPort))
}

// Validate enforces all v6.4 structural, deadlock-freedom, and WAF invariants.
func (c Config) Validate() error {
	if err := ValidateCodespaceName(c.CodespaceName); err != nil {
		return err
	}
	if c.LocalPort == 10808 {
		return errors.New("local-port must not overlap v2rayNG/Xray inbound port 10808")
	}
	if c.PoolSize < 1 || c.PoolSize > DefaultMaxPoolSize {
		return fmt.Errorf("pool-size must be in 1..%d, got %d", DefaultMaxPoolSize, c.PoolSize)
	}
	if c.MaxActiveConns < 1 {
		return fmt.Errorf("max-conns must be >= 1, got %d", c.MaxActiveConns)
	}
	if c.PerTunnelMaxConns < 1 {
		return fmt.Errorf("per-tunnel-max-conns must be >= 1, got %d", c.PerTunnelMaxConns)
	}
	if c.MaxQueuedConns < 0 {
		return fmt.Errorf("max-queued-conns must be >= 0, got %d", c.MaxQueuedConns)
	}
	if c.CopyBufferSize < 4096 || c.CopyBufferSize > 256*1024 {
		return fmt.Errorf("copy-buffer-bytes must be in [4096, 262144], got %d", c.CopyBufferSize)
	}
	if c.PMTU576SafeMode && (c.PMTU576CopyBufSize < 4096 || c.PMTU576CopyBufSize > c.CopyBufferSize) {
		return fmt.Errorf("pmtu576-copy-buffer-bytes (%d) must be in [4096, copy-buffer-bytes=%d]", c.PMTU576CopyBufSize, c.CopyBufferSize)
	}
	if c.DialTimeout <= 0 || c.IdleTimeout <= 0 || c.HalfCloseDrainTimeout <= 0 {
		return errors.New("timeouts must be positive")
	}
	if c.PressureIdleTimeout <= 0 || c.PressureIdleTimeout > c.IdleTimeout {
		return fmt.Errorf("pressure-idle-timeout (%s) must be in (0, idle-timeout=%s]", c.PressureIdleTimeout, c.IdleTimeout)
	}
	if c.StreamingPressureIdleTimeout > 0 && c.SemaphoreWaitTimeout > 0 && c.StreamingPressureIdleTimeout >= c.SemaphoreWaitTimeout {
		return fmt.Errorf("deadlock invariant violated: streaming-pressure-idle-timeout (%s) must be < semaphore-wait (%s)",
			c.StreamingPressureIdleTimeout, c.SemaphoreWaitTimeout)
	}
	if c.PressureThresholdPct < 10 || c.PressureThresholdPct > 100 {
		return fmt.Errorf("pressure-threshold-pct must be in [10, 100], got %d", c.PressureThresholdPct)
	}
	if c.TCPKeepAlivePeriod <= 0 {
		return errors.New("tcp-keepalive must be positive")
	}
	if c.GitHubMaxCallsPer5Min < 1 || c.GitHubMaxCallsPerHour < c.GitHubMaxCallsPer5Min {
		return fmt.Errorf("invalid GitHub API budget: 5m=%d hour=%d", c.GitHubMaxCallsPer5Min, c.GitHubMaxCallsPerHour)
	}
	if c.HysteresisRelMargin < 0 || c.HysteresisRelMargin >= 1.0 {
		return fmt.Errorf("hysteresis-rel-margin must be in [0, 1), got %.2f", c.HysteresisRelMargin)
	}
	if c.FastLaneMaxRatio < 1.0 || c.SlowLaneEvictRatio <= c.FastLaneMaxRatio {
		return fmt.Errorf("invalid lane ratios: fast=%.2f evict=%.2f", c.FastLaneMaxRatio, c.SlowLaneEvictRatio)
	}
	rp := strings.ToLower(strings.TrimSpace(c.RoutingProfile))
	if rp != "" && rp != "balanced" && rp != "sticky" {
		return fmt.Errorf("invalid routing-profile %q (must be \"balanced\" or \"sticky\")", c.RoutingProfile)
	}
	if c.ActiveStreamMaxErrRate < 0 || c.ActiveStreamMaxErrRate > 1.0 {
		return fmt.Errorf("active-stream-max-err-rate must be in [0, 1], got %.2f", c.ActiveStreamMaxErrRate)
	}
	if c.BlackholeErrRate < 0 || c.BlackholeErrRate > 1.0 {
		return fmt.Errorf("blackhole-err-rate must be in [0, 1], got %.2f", c.BlackholeErrRate)
	}
	if c.SlowLanePeerAdvantageRatio > 0 && c.SlowLanePeerAdvantageRatio < 1.0 {
		return fmt.Errorf("slow-lane-peer-advantage-ratio must be >= 1.0, got %.2f", c.SlowLanePeerAdvantageRatio)
	}
	for _, t := range c.ParsedUnderlayTargets() {
		if IsGitHubHost(t) {
			return fmt.Errorf("underlay-probe-targets must NEVER contain GitHub host %q", t)
		}
	}
	return nil
}
