package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type FailureClass string

const (
	FailureNetworkLane   FailureClass = "network_lane"
	FailureAPIRateLimit  FailureClass = "api_rate_limit"
	FailureVMTransition  FailureClass = "vm_transition"
	FailureAuthOrStopped FailureClass = "auth_or_stopped"
)

type FatalBootError struct {
	Code    string
	Message string
	Detail  string
}

func (e *FatalBootError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func isVMTransitionText(lower string) bool {
	for _, tok := range []string{
		"too many codespaces starting",
		"http 400",
		"shutting down",
		"codespace is currently",
	} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// IsQuotaRateLimitOrWAF detects genuine WAF/rate-limit/429 signatures (excluding billing-scope 403).
func IsQuotaRateLimitOrWAF(text string) bool {
	low := strings.ToLower(text)
	for _, tok := range []string{
		"http 429",
		"429 too many requests",
		"too many requests",
		"secondary rate limit",
		"api rate limit exceeded",
		"rate limit",
		"abuse detection",
		"retry-after",
		"waf",
		"bot detection",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// IsQuotaBillingScope403 isolates missing billing-scope HTTP 403/404 without WAF throttling.
func IsQuotaBillingScope403(text string) bool {
	if IsQuotaRateLimitOrWAF(text) {
		return false
	}
	low := strings.ToLower(text)
	for _, tok := range []string{"http 403", "403", "forbidden", "resource not accessible", "scope", "must have admin", "http 404"} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// ClassifyPermanentBootError returns *FatalBootError ONLY for non-retriable permanent failures.
func ClassifyPermanentBootError(detail string) *FatalBootError {
	trimmed := strings.TrimSpace(detail)
	if trimmed == "" || IsQuotaRateLimitOrWAF(trimmed) {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if isVMTransitionText(lower) {
		return nil
	}
	for _, tok := range []string{
		"http 404", "404 not found", "codespace not found",
		"no codespaces found", "no codespaces available", "no such codespace",
	} {
		if strings.Contains(lower, tok) {
			return &FatalBootError{
				Code:    "codespace_not_found",
				Message: "Codespace not found (404) — check Account tab",
				Detail:  RedactSecrets(trimmed),
			}
		}
	}
	if strings.Contains(lower, "spending limit") {
		return &FatalBootError{
			Code:    "spending_limit",
			Message: "Codespaces spending limit reached — check GitHub billing",
			Detail:  RedactSecrets(trimmed),
		}
	}
	if strings.Contains(lower, "codespace is suspended") {
		return &FatalBootError{
			Code:    "codespace_suspended",
			Message: "Codespace is suspended — check GitHub Codespaces",
			Detail:  RedactSecrets(trimmed),
		}
	}
	for _, tok := range []string{
		"http 401", "unauthorized", "bad credentials", "token expired",
		"authentication failed", "missing required scope", "requires authentication",
		"permission denied (publickey)",
	} {
		if strings.Contains(lower, tok) {
			return &FatalBootError{
				Code:    "auth_required",
				Message: "GitHub authentication required — sign in again in Account tab",
				Detail:  RedactSecrets(trimmed),
			}
		}
	}
	return nil
}

type GitHubGuardSnapshot struct {
	CallsLast5Min       int    `json:"calls_last_5m"`
	MaxCallsPer5Min     int    `json:"max_calls_5m"`
	CallsLastHour       int    `json:"calls_last_hour"`
	MaxCallsPerHour     int    `json:"max_calls_hour"`
	MinCallSpacingMS    int64  `json:"min_call_spacing_ms"`
	TotalAllowed        int64  `json:"total_allowed"`
	TotalThrottled      int64  `json:"total_throttled"`
	RateLimitHits       int64  `json:"rate_limit_hits"`
	VMTransitionHits    int64  `json:"vm_transition_hits"`
	AuthOrStoppedHits   int64  `json:"auth_or_stopped_hits"`
	CooldownRemainingMS int64  `json:"cooldown_remaining_ms"`
	BudgetWaitMS        int64  `json:"budget_wait_ms"`
	ThrottleWaitMS      int64  `json:"throttle_wait_ms"`
	ThrottleReason      string `json:"throttle_reason,omitempty"`
	CodespaceWarm       bool   `json:"codespace_warm"`
}

type codespaceStateCacheEntry struct {
	Codespace string    `json:"codespace"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CodespaceStateCache stores warm VM state strictly under Android's injected DataDir (zero UserConfigDir).
type CodespaceStateCache struct {
	mu        sync.Mutex
	path      string
	codespace string
	state     string
	updatedAt time.Time
	nowFn     func() time.Time
}

func NewCodespaceStateCache(codespaceName, dataDir string) *CodespaceStateCache {
	path := ""
	if strings.TrimSpace(dataDir) != "" {
		path = filepath.Join(strings.TrimSpace(dataDir), DefaultCodespaceCacheFileName)
	}
	c := &CodespaceStateCache{
		path:      path,
		codespace: strings.TrimSpace(codespaceName),
		nowFn:     time.Now,
	}
	_ = c.Load()
	return c
}

func (c *CodespaceStateCache) Load() error {
	if c == nil || c.path == "" {
		return nil
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var entry codespaceStateCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	if entry.Codespace != "" && c.codespace != "" && entry.Codespace != c.codespace {
		return nil
	}
	c.mu.Lock()
	c.state = entry.State
	c.updatedAt = entry.UpdatedAt
	c.mu.Unlock()
	return nil
}

func (c *CodespaceStateCache) Get(maxAge time.Duration) (string, bool) {
	if c == nil || maxAge <= 0 {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == "" || c.updatedAt.IsZero() {
		return "", false
	}
	age := c.nowFn().Sub(c.updatedAt)
	if age < 0 || age > maxAge {
		return "", false
	}
	return c.state, true
}

func (c *CodespaceStateCache) Set(state string) error {
	if c == nil {
		return nil
	}
	now := c.nowFn().UTC()
	c.mu.Lock()
	c.state = strings.TrimSpace(state)
	c.updatedAt = now
	entry := codespaceStateCacheEntry{
		Codespace: c.codespace,
		State:     c.state,
		UpdatedAt: now,
	}
	path := c.path
	c.mu.Unlock()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

var (
	reRetryAfterLine   = regexp.MustCompile(`(?im)retry-after\s*[:=]\s*([^\r\n;]+)`)
	reRetryAfterDigits = regexp.MustCompile(`^(\d+)\b`)
	reRetryAfterText   = regexp.MustCompile(`(?i)(?:retry\s+after|wait\s+at\s+least|try\s+again\s+in)\s+(\d+)\s*(?:s|sec|second)`)
)

// ParseRetryAfterAt extracts delta-seconds or RFC 9110 HTTP-date Retry-After relative to now.
func ParseRetryAfterAt(raw string, now time.Time) time.Duration {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	if m := reRetryAfterLine.FindStringSubmatch(raw); len(m) == 2 {
		val := strings.TrimSpace(m[1])
		if dm := reRetryAfterDigits.FindStringSubmatch(val); len(dm) == 2 {
			if secs, err := strconv.Atoi(dm[1]); err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
		layouts := []string{http.TimeFormat, time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC}
		cleanVal := strings.Trim(val, `"' `)
		candidates := []string{cleanVal}
		if fields := strings.Fields(cleanVal); len(fields) > 4 {
			if len(fields) >= 6 {
				candidates = append(candidates, strings.Join(fields[:6], " "))
			}
			if len(fields) >= 5 {
				candidates = append(candidates, strings.Join(fields[:5], " "))
			}
			candidates = append(candidates, strings.Join(fields[:4], " "))
		}
		for _, cand := range candidates {
			for _, layout := range layouts {
				if ts, err := time.Parse(layout, cand); err == nil {
					if d := ts.Sub(now); d > 0 {
						return d
					}
					return 0
				}
			}
		}
	}
	if m := reRetryAfterText.FindStringSubmatch(raw); len(m) == 2 {
		if secs, err := strconv.Atoi(m[1]); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// GitHubGuard enforces sliding-window GitHub API budgets (6/5m, 24/1h, 2s spacing) purely in memory
// (0 disk persistence of sliding counters across clean launches) plus WAF 429/400/403 backoff.
type GitHubGuard struct {
	mu             sync.Mutex
	maxPer5Min     int
	maxPerHour     int
	minCallSpacing time.Duration
	rateLimitBase  time.Duration
	rateLimitMax   time.Duration
	warmCacheTTL   time.Duration
	loggerPtr      atomic.Pointer[EventLogger]
	metricsPtr     atomic.Pointer[MetricsEmitter]
	stateCache     *CodespaceStateCache
	nowFn          func() time.Time
	rng            *rand.Rand

	callTimes           []time.Time
	lastCallAt          time.Time
	cooldownUntil       time.Time
	cooldownReason      string
	rateLimitStreak     int
	warmUntil           time.Time
	sessionStopped      bool
	sessionStoppedUntil time.Time

	totalAllowed      int64
	totalThrottled    int64
	rateLimitHits     int64
	vmTransitionHits  int64
	authOrStoppedHits int64

	publishedSnap         atomic.Pointer[GitHubGuardSnapshot]
	publishedTimes        atomic.Pointer[[]time.Time]
	cooldownUntilNS       atomic.Int64
	cooldownReasonPtr     atomic.Pointer[string]
	sessionStoppedUntilNS atomic.Int64
}

func NewGitHubGuard(cfg Config, logger *EventLogger, metrics *MetricsEmitter) *GitHubGuard {
	max5 := cfg.GitHubMaxCallsPer5Min
	if max5 < 1 {
		max5 = DefaultGitHubMaxCallsPer5Min
	}
	max60 := cfg.GitHubMaxCallsPerHour
	if max60 < max5 {
		max60 = DefaultGitHubMaxCallsPerHour
	}
	spacing := cfg.GitHubMinCallSpacing
	if spacing < 0 {
		spacing = 0
	}
	base := cfg.GitHubRateLimitBase
	if base <= 0 {
		base = DefaultGitHubRateLimitBaseBackoff
	}
	maxB := cfg.GitHubRateLimitMax
	if maxB < base {
		maxB = DefaultGitHubRateLimitMaxBackoff
	}
	warmTTL := cfg.GitHubWarmCacheTTL
	if warmTTL <= 0 {
		warmTTL = DefaultGitHubWarmCacheTTL
	}
	g := &GitHubGuard{
		maxPer5Min:     max5,
		maxPerHour:     max60,
		minCallSpacing: spacing,
		rateLimitBase:  base,
		rateLimitMax:   maxB,
		warmCacheTTL:   warmTTL,
		nowFn:          time.Now,
	}
	g.loggerPtr.Store(logger)
	g.metricsPtr.Store(metrics)
	if strings.TrimSpace(cfg.DataDir) != "" && strings.TrimSpace(cfg.CodespaceName) != "" {
		cache := NewCodespaceStateCache(cfg.CodespaceName, cfg.DataDir)
		g.stateCache = cache
		if st, ok := cache.Get(warmTTL); ok && strings.EqualFold(st, "Available") {
			g.warmUntil = g.nowFn().Add(warmTTL)
		}
	}
	g.publishSnapshotLocked(g.nowFn())
	return g
}

func (g *GitHubGuard) SetSinks(logger *EventLogger, metrics *MetricsEmitter) {
	if g == nil {
		return
	}
	g.loggerPtr.Store(logger)
	g.metricsPtr.Store(metrics)
}

func (g *GitHubGuard) SetStateCache(cache *CodespaceStateCache) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.stateCache = cache
	if cache != nil {
		if st, ok := cache.Get(g.warmCacheTTL); ok && strings.EqualFold(st, "Available") {
			g.warmUntil = g.nowFn().Add(g.warmCacheTTL)
		}
	}
	g.publishSnapshotLocked(g.nowFn())
	g.mu.Unlock()
}

func (g *GitHubGuard) MarkCodespaceState(state string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	now := g.nowFn()
	low := strings.ToLower(strings.TrimSpace(state))
	if low == "available" {
		g.warmUntil = now.Add(g.warmCacheTTL)
		g.sessionStopped = false
		g.sessionStoppedUntil = time.Time{}
	} else if low == "shutdown" || low == "stopped" || low == "unavailable" {
		g.warmUntil = time.Time{}
		g.sessionStopped = true
		g.sessionStoppedUntil = now.Add(g.warmCacheTTL)
	}
	cache := g.stateCache
	g.publishSnapshotLocked(now)
	g.mu.Unlock()
	if cache != nil {
		_ = cache.Set(state)
	}
}

func (g *GitHubGuard) ClearSessionStopped() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.sessionStopped = false
	g.sessionStoppedUntil = time.Time{}
	g.publishSnapshotLocked(g.nowFn())
	g.mu.Unlock()
}

func ClassifyErrorText(text string) FailureClass {
	lower := strings.ToLower(text)
	if lower == "" {
		return FailureNetworkLane
	}
	if ClassifyPermanentBootError(text) != nil {
		return FailureAuthOrStopped
	}
	for _, tok := range []string{
		"http 429", "429 too many requests", "too many requests",
		"secondary rate limit", "api rate limit exceeded", "rate limit",
		"abuse detection", "http 403", "forbidden", "waf", "bot detection", "retry-after",
	} {
		if strings.Contains(lower, tok) {
			return FailureAPIRateLimit
		}
	}
	if isVMTransitionText(lower) {
		return FailureVMTransition
	}
	for _, tok := range []string{"http 401", "unauthorized", "codespace is stopped", "codespace not found", "http 404"} {
		if strings.Contains(lower, tok) {
			return FailureAuthOrStopped
		}
	}
	return FailureNetworkLane
}

func (g *GitHubGuard) pruneLocked(now time.Time) {
	cutoff := now.Add(-time.Hour)
	idx := 0
	for idx < len(g.callTimes) && !g.callTimes[idx].After(cutoff) {
		idx++
	}
	if idx > 0 {
		g.callTimes = append(g.callTimes[:0], g.callTimes[idx:]...)
	}
}

func (g *GitHubGuard) countRecentLocked(now time.Time, window time.Duration) (int, time.Time) {
	cutoff := now.Add(-window)
	cnt := 0
	var earliest time.Time
	for _, ts := range g.callTimes {
		if ts.After(cutoff) {
			if cnt == 0 {
				earliest = ts
			}
			cnt++
		}
	}
	return cnt, earliest
}

func (g *GitHubGuard) TryAllow(reason string) (bool, time.Duration, string) {
	if g == nil {
		return true, 0, ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	defer func() { g.publishSnapshotLocked(now) }()
	g.pruneLocked(now)

	if g.sessionStopped {
		if !g.sessionStoppedUntil.IsZero() && !now.Before(g.sessionStoppedUntil) {
			g.sessionStopped = false
			g.sessionStoppedUntil = time.Time{}
		} else {
			g.totalThrottled++
			return false, g.rateLimitBase, "codespace_cached_stopped"
		}
	}
	if now.Before(g.cooldownUntil) {
		g.totalThrottled++
		why := g.cooldownReason
		if why == "" {
			why = "api_rate_limit_cooldown"
		}
		return false, g.cooldownUntil.Sub(now), why
	}
	if g.minCallSpacing > 0 && !g.lastCallAt.IsZero() {
		nextAllowed := g.lastCallAt.Add(g.minCallSpacing)
		if now.Before(nextAllowed) {
			g.totalThrottled++
			return false, nextAllowed.Sub(now), "min_call_spacing"
		}
	}
	c5, earliest5 := g.countRecentLocked(now, 5*time.Minute)
	if c5 >= g.maxPer5Min {
		g.totalThrottled++
		w := earliest5.Add(5 * time.Minute).Sub(now)
		if w < 50*time.Millisecond {
			w = 50 * time.Millisecond
		}
		return false, w, "budget_5m_exhausted"
	}
	c60, earliest60 := g.countRecentLocked(now, time.Hour)
	if c60 >= g.maxPerHour {
		g.totalThrottled++
		w := earliest60.Add(time.Hour).Sub(now)
		if w < 50*time.Millisecond {
			w = 50 * time.Millisecond
		}
		return false, w, "budget_hour_exhausted"
	}

	g.callTimes = append(g.callTimes, now)
	g.lastCallAt = now
	g.totalAllowed++
	snap := g.snapshotLocked(now)
	if m := g.metricsPtr.Load(); m != nil {
		m.Emit("api_guard", map[string]any{
			"action":          "allowed",
			"reason":          reason,
			"calls_last_5m":   snap.CallsLast5Min,
			"calls_last_hour": snap.CallsLastHour,
		})
	}
	return true, 0, ""
}

func (g *GitHubGuard) CanAllowNonConsuming() (bool, string) {
	if g == nil {
		return true, ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.nowFn()
	g.pruneLocked(now)
	if g.sessionStopped {
		if !g.sessionStoppedUntil.IsZero() && !now.Before(g.sessionStoppedUntil) {
			g.sessionStopped = false
			g.sessionStoppedUntil = time.Time{}
		} else {
			return false, "codespace_cached_stopped"
		}
	}
	if now.Before(g.cooldownUntil) {
		why := g.cooldownReason
		if why == "" {
			why = "api_rate_limit_cooldown"
		}
		return false, why
	}
	if g.minCallSpacing > 0 && !g.lastCallAt.IsZero() && now.Before(g.lastCallAt.Add(g.minCallSpacing)) {
		return false, "min_call_spacing"
	}
	if c5, _ := g.countRecentLocked(now, 5*time.Minute); c5 >= g.maxPer5Min {
		return false, "budget_5m_exhausted"
	}
	if c60, _ := g.countRecentLocked(now, time.Hour); c60 >= g.maxPerHour {
		return false, "budget_hour_exhausted"
	}
	return true, ""
}

func (g *GitHubGuard) Allow(ctx context.Context, reason string) error {
	if g == nil {
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, wait, blockReason := g.TryAllow(reason)
		if ok {
			return nil
		}
		if l := g.loggerPtr.Load(); l != nil {
			snap := g.Snapshot()
			l.Log("GITHUB_API_THROTTLED", map[string]any{
				"reason":          reason,
				"block_reason":    blockReason,
				"wait_ms":         wait.Milliseconds(),
				"calls_last_5m":   snap.CallsLast5Min,
				"calls_last_hour": snap.CallsLastHour,
			})
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// RecordHTTPResponse ingests a live GitHub REST HTTP status, headers, and body snippet into GitHubGuard.
func (g *GitHubGuard) RecordHTTPResponse(statusCode int, hdr http.Header, body string) (FailureClass, time.Duration) {
	if statusCode >= 200 && statusCode < 300 {
		g.RecordSuccess()
		return FailureNetworkLane, 0
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP %d: %s", statusCode, strings.TrimSpace(body))
	if hdr != nil {
		if ra := strings.TrimSpace(hdr.Get("Retry-After")); ra != "" {
			fmt.Fprintf(&sb, "\nRetry-After: %s", ra)
		}
		if rem := strings.TrimSpace(hdr.Get("X-RateLimit-Remaining")); rem == "0" {
			if resetStr := strings.TrimSpace(hdr.Get("X-RateLimit-Reset")); resetStr != "" {
				if unixSec, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
					if d := time.Until(time.Unix(unixSec, 0)); d > 0 {
						fmt.Fprintf(&sb, "\nRetry-After: %d", int(d.Seconds())+1)
					}
				}
			}
		}
	}
	return g.RecordFailure(sb.String())
}

func (g *GitHubGuard) RecordFailure(detail string) (FailureClass, time.Duration) {
	cls := ClassifyErrorText(detail)
	if g == nil {
		return cls, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	var cooldown time.Duration
	retryAfter := ParseRetryAfterAt(detail, now)

	switch cls {
	case FailureAPIRateLimit:
		g.rateLimitHits++
		g.rateLimitStreak++
		shift := g.rateLimitStreak - 1
		if shift > 6 {
			shift = 6
		}
		raw := float64(g.rateLimitBase) * math.Pow(2, float64(shift))
		if raw > float64(g.rateLimitMax) {
			raw = float64(g.rateLimitMax)
		}
		cooldown = time.Duration(raw * (0.5 + 0.5*g.randFloat64Locked()))
		if retryAfter > cooldown {
			cooldown = retryAfter
			if g.rateLimitMax > 0 && cooldown > g.rateLimitMax {
				cooldown = g.rateLimitMax
			}
		}
		if until := now.Add(cooldown); until.After(g.cooldownUntil) {
			g.cooldownUntil = until
			g.cooldownReason = "api_rate_limit_cooldown"
		}
	case FailureVMTransition:
		g.vmTransitionHits++
		g.warmUntil = time.Time{}
		minB := 10 * time.Second
		maxB := 20 * time.Second
		if g.rateLimitBase > 0 && g.rateLimitBase < minB {
			minB = g.rateLimitBase
			maxB = g.rateLimitBase * 2
		}
		if g.rateLimitMax > 0 && maxB > g.rateLimitMax {
			maxB = g.rateLimitMax
			if minB > maxB {
				minB = maxB
			}
		}
		cooldown = minB + time.Duration(float64(maxB-minB)*g.randFloat64Locked())
		if until := now.Add(cooldown); until.After(g.cooldownUntil) {
			g.cooldownUntil = until
			g.cooldownReason = "vm_transition_cooldown"
		}
	case FailureAuthOrStopped:
		g.authOrStoppedHits++
		g.warmUntil = time.Time{}
		low := strings.ToLower(detail)
		if strings.Contains(low, "stopped") || strings.Contains(low, "shutdown") {
			g.sessionStopped = true
			g.sessionStoppedUntil = now.Add(g.warmCacheTTL)
			if g.stateCache != nil {
				_ = g.stateCache.Set("Shutdown")
			}
		}
		if ClassifyPermanentBootError(detail) != nil {
			g.publishSnapshotLocked(now)
			return cls, 0
		}
		cooldown = g.rateLimitBase
		if until := now.Add(cooldown); until.After(g.cooldownUntil) {
			g.cooldownUntil = until
			g.cooldownReason = "api_rate_limit_cooldown"
		}
	default:
		return cls, 0
	}

	if l := g.loggerPtr.Load(); l != nil {
		l.Log("GITHUB_API_BACKOFF", map[string]any{
			"failure_class":      string(cls),
			"cooldown_ms":        cooldown.Milliseconds(),
			"retry_after_ms":     retryAfter.Milliseconds(),
			"rate_limit_streak":  g.rateLimitStreak,
			"rate_limit_hits":    g.rateLimitHits,
			"vm_transition_hits": g.vmTransitionHits,
		})
	}
	g.publishSnapshotLocked(now)
	return cls, cooldown
}

func (g *GitHubGuard) RecordSuccess() {
	if g == nil {
		return
	}
	g.mu.Lock()
	now := g.nowFn()
	g.rateLimitStreak = 0
	g.sessionStopped = false
	g.sessionStoppedUntil = time.Time{}
	g.warmUntil = now.Add(g.warmCacheTTL)
	cache := g.stateCache
	g.publishSnapshotLocked(now)
	g.mu.Unlock()
	if cache != nil {
		_ = cache.Set("Available")
	}
}

func (g *GitHubGuard) randFloat64Locked() float64 {
	if g.rng != nil {
		return g.rng.Float64()
	}
	return rand.Float64()
}

func (g *GitHubGuard) snapshotLocked(now time.Time) GitHubGuardSnapshot {
	g.pruneLocked(now)
	c5, earliest5 := g.countRecentLocked(now, 5*time.Minute)
	c60, earliest60 := g.countRecentLocked(now, time.Hour)
	var remMS int64
	var throttleReason string
	if now.Before(g.cooldownUntil) {
		remMS = g.cooldownUntil.Sub(now).Milliseconds()
		throttleReason = g.cooldownReason
		if throttleReason == "" {
			throttleReason = "api_rate_limit_cooldown"
		}
	}
	var budgetWaitMS int64
	var budgetReason string
	if c5 >= g.maxPer5Min && !earliest5.IsZero() {
		if w := earliest5.Add(5 * time.Minute).Sub(now).Milliseconds(); w > budgetWaitMS {
			budgetWaitMS = w
			budgetReason = "budget_5m_exhausted"
		}
	}
	if c60 >= g.maxPerHour && !earliest60.IsZero() {
		if w := earliest60.Add(time.Hour).Sub(now).Milliseconds(); w > budgetWaitMS {
			budgetWaitMS = w
			budgetReason = "budget_hour_exhausted"
		}
	}
	throttleWaitMS := remMS
	if budgetWaitMS > throttleWaitMS {
		throttleWaitMS = budgetWaitMS
		throttleReason = budgetReason
	}
	if g.sessionStopped && !g.sessionStoppedUntil.IsZero() && now.Before(g.sessionStoppedUntil) {
		if w := g.sessionStoppedUntil.Sub(now).Milliseconds(); w > throttleWaitMS {
			throttleWaitMS = w
			throttleReason = "codespace_cached_stopped"
		}
	}
	return GitHubGuardSnapshot{
		CallsLast5Min:       c5,
		MaxCallsPer5Min:     g.maxPer5Min,
		CallsLastHour:       c60,
		MaxCallsPerHour:     g.maxPerHour,
		MinCallSpacingMS:    g.minCallSpacing.Milliseconds(),
		TotalAllowed:        g.totalAllowed,
		TotalThrottled:      g.totalThrottled,
		RateLimitHits:       g.rateLimitHits,
		VMTransitionHits:    g.vmTransitionHits,
		AuthOrStoppedHits:   g.authOrStoppedHits,
		CooldownRemainingMS: remMS,
		BudgetWaitMS:        budgetWaitMS,
		ThrottleWaitMS:      throttleWaitMS,
		ThrottleReason:      throttleReason,
		CodespaceWarm:       now.Before(g.warmUntil),
	}
}

func (g *GitHubGuard) publishSnapshotLocked(now time.Time) {
	snap := g.snapshotLocked(now)
	g.publishedSnap.Store(&snap)
	timesCopy := make([]time.Time, len(g.callTimes))
	copy(timesCopy, g.callTimes)
	g.publishedTimes.Store(&timesCopy)
	if !g.cooldownUntil.IsZero() && g.cooldownUntil.After(now) {
		g.cooldownUntilNS.Store(g.cooldownUntil.UnixNano())
		r := g.cooldownReason
		if r == "" {
			r = "api_rate_limit_cooldown"
		}
		g.cooldownReasonPtr.Store(&r)
	} else {
		g.cooldownUntilNS.Store(0)
		g.cooldownReasonPtr.Store(nil)
	}
	if g.sessionStopped && !g.sessionStoppedUntil.IsZero() && g.sessionStoppedUntil.After(now) {
		g.sessionStoppedUntilNS.Store(g.sessionStoppedUntil.UnixNano())
	} else {
		g.sessionStoppedUntilNS.Store(0)
	}
}

// CachedSnapshot returns a wait-free live GitHubGuardSnapshot with 0 mutex acquisitions.
func (g *GitHubGuard) CachedSnapshot() GitHubGuardSnapshot {
	if g == nil {
		return GitHubGuardSnapshot{}
	}
	var snap GitHubGuardSnapshot
	if ptr := g.publishedSnap.Load(); ptr != nil {
		snap = *ptr
	}
	now := time.Now()
	if g.nowFn != nil {
		now = g.nowFn()
	}
	var budgetWaitMS int64
	var budgetReason string
	if timesPtr := g.publishedTimes.Load(); timesPtr != nil {
		times := *timesPtr
		cutoff5 := now.Add(-5 * time.Minute)
		cutoff60 := now.Add(-time.Hour)
		c5, c60 := 0, 0
		var earliest5, earliest60 time.Time
		for _, ts := range times {
			if ts.After(cutoff60) {
				if c60 == 0 {
					earliest60 = ts
				}
				c60++
				if ts.After(cutoff5) {
					if c5 == 0 {
						earliest5 = ts
					}
					c5++
				}
			}
		}
		snap.CallsLast5Min = c5
		snap.CallsLastHour = c60
		if snap.MaxCallsPer5Min > 0 && c5 >= snap.MaxCallsPer5Min && !earliest5.IsZero() {
			if w := earliest5.Add(5 * time.Minute).Sub(now).Milliseconds(); w > budgetWaitMS {
				budgetWaitMS = w
				budgetReason = "budget_5m_exhausted"
			}
		}
		if snap.MaxCallsPerHour > 0 && c60 >= snap.MaxCallsPerHour && !earliest60.IsZero() {
			if w := earliest60.Add(time.Hour).Sub(now).Milliseconds(); w > budgetWaitMS {
				budgetWaitMS = w
				budgetReason = "budget_hour_exhausted"
			}
		}
	}
	snap.BudgetWaitMS = budgetWaitMS
	var cooldownMS int64
	var throttleReason string
	if untilNS := g.cooldownUntilNS.Load(); untilNS > 0 {
		if rem := time.Unix(0, untilNS).Sub(now).Milliseconds(); rem > 0 {
			cooldownMS = rem
			if rPtr := g.cooldownReasonPtr.Load(); rPtr != nil && *rPtr != "" {
				throttleReason = *rPtr
			} else {
				throttleReason = "api_rate_limit_cooldown"
			}
		}
	}
	snap.CooldownRemainingMS = cooldownMS
	throttleWaitMS := cooldownMS
	if budgetWaitMS > throttleWaitMS {
		throttleWaitMS = budgetWaitMS
		throttleReason = budgetReason
	}
	if ssNS := g.sessionStoppedUntilNS.Load(); ssNS > 0 {
		if rem := time.Unix(0, ssNS).Sub(now).Milliseconds(); rem > throttleWaitMS {
			throttleWaitMS = rem
			throttleReason = "codespace_cached_stopped"
		}
	}
	snap.ThrottleWaitMS = throttleWaitMS
	snap.ThrottleReason = throttleReason
	return snap
}

func (g *GitHubGuard) Snapshot() GitHubGuardSnapshot {
	if g == nil {
		return GitHubGuardSnapshot{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshotLocked(g.nowFn())
}
