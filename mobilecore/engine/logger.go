package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	loggerChannelCap     = 512
	loggerBufSize        = 8192
	loggerFlushCadence   = 2 * time.Second
	TerminalRingCapacity = 500
	TerminalMaxLineBytes = 256
)

// LogSeverity classifies terminal ring lines.
type LogSeverity uint8

const (
	LogInfo LogSeverity = iota
	LogSuccess
	LogWarn
	LogError
)

func (s LogSeverity) String() string {
	switch s {
	case LogSuccess:
		return "SUCCESS"
	case LogWarn:
		return "WARN"
	case LogError:
		return "ERROR"
	default:
		return "INFO"
	}
}

var (
	reGitHubToken  = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b`)
	reGitHubPAT    = regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{12,}\b`)
	reBearerAuth   = regexp.MustCompile(`(?i)\b(Bearer|token|tunnel)\s+[A-Za-z0-9._~+/=-]{8,}`)
	reJWTToken     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	reJSONSecField = regexp.MustCompile(`(?i)("(?:access_token|github_token|connect_access_token|manage_ports_access_token|connectAccessToken|managePortsAccessToken|authorization)"\s*:\s*")([^"]+)(")`)
	reURLSecParam  = regexp.MustCompile(`(?i)([?&](?:access_token|token|connect_access_token|manage_ports_access_token|connectAccessToken|managePortsAccessToken)=)([^&\s"']+)`)
)

// RedactSecrets strips GitHub OAuth tokens, PATs, Bearer/tunnel headers, URL query secrets, and Dev Tunnels JWTs.
func RedactSecrets(s string) string {
	if s == "" {
		return ""
	}
	s = reJSONSecField.ReplaceAllString(s, `${1}[REDACTED]${3}`)
	s = reURLSecParam.ReplaceAllString(s, `${1}[REDACTED]`)
	s = reGitHubPAT.ReplaceAllString(s, "[REDACTED_GH_PAT]")
	s = reGitHubToken.ReplaceAllString(s, "[REDACTED_GH_TOKEN]")
	s = reJWTToken.ReplaceAllString(s, "[REDACTED_JWT]")
	s = reBearerAuth.ReplaceAllString(s, `$1 [REDACTED]`)
	return s
}

func redactFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "authorization") {
			out[k] = "[REDACTED]"
			continue
		}
		if sv, ok := v.(string); ok {
			out[k] = RedactSecrets(sv)
		} else {
			out[k] = v
		}
	}
	return out
}

// LogRecord represents a single append-only JSONL telemetry record.
type LogRecord struct {
	Timestamp string         `json:"ts"`
	SessionID string         `json:"session_id"`
	Event     string         `json:"event"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// EventLogger provides panic-proof, non-blocking, rotating JSONL telemetry safe for mobile flash storage.
type EventLogger struct {
	sessionID string
	path      string
	maxBytes  int64
	file      *os.File
	written   int64
	ch        chan LogRecord
	quitCh    chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	dropped   atomic.Uint64
	observer  atomic.Pointer[func(LogRecord)]
	closeOnce sync.Once
}

// NewEventLogger opens path (or runs in-memory-observer-only mode if path == "") with a rotating byte cap.
func NewEventLogger(path string, maxBytes int64) (*EventLogger, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxLogFileBytes
	}
	var f *os.File
	var size int64
	if strings.TrimSpace(path) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("mkdir log dir: %w", err)
		}
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open log %q: %w", path, err)
		}
		if info, statErr := f.Stat(); statErr == nil {
			size = info.Size()
		}
	}
	l := &EventLogger{
		sessionID: fmt.Sprintf("mob%d-%d", os.Getpid(), time.Now().UTC().UnixNano()),
		path:      path,
		maxBytes:  maxBytes,
		file:      f,
		written:   size,
		ch:        make(chan LogRecord, loggerChannelCap),
		quitCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	safeGo(nil, "event_logger_writer", l.writerLoop)
	return l, nil
}

func (l *EventLogger) SessionID() string {
	if l == nil {
		return ""
	}
	return l.sessionID
}

func (l *EventLogger) DroppedCount() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

func (l *EventLogger) SetObserver(fn func(LogRecord)) {
	if l == nil {
		return
	}
	if fn == nil {
		l.observer.Store(nil)
		return
	}
	l.observer.Store(&fn)
}

func (l *EventLogger) Log(event string, fields map[string]any) {
	if l == nil || l.closed.Load() {
		return
	}
	rec := LogRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: l.sessionID,
		Event:     event,
		Fields:    redactFields(fields),
	}
	select {
	case <-l.quitCh:
		return
	default:
	}
	select {
	case l.ch <- rec:
	case <-l.quitCh:
		return
	default:
		l.dropped.Add(1)
	}
}

func (l *EventLogger) rotateLocked(bw **bufio.Writer) {
	if l.file == nil || l.path == "" || l.maxBytes <= 0 || l.written < l.maxBytes {
		return
	}
	if *bw != nil {
		_ = (*bw).Flush()
	}
	_ = l.file.Close()
	backup := l.path + ".1"
	_ = os.Remove(backup)
	_ = os.Rename(l.path, backup)
	nf, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		l.file = nil
		*bw = nil
		return
	}
	l.file = nf
	l.written = 0
	*bw = bufio.NewWriterSize(nf, loggerBufSize)
}

func (l *EventLogger) writerLoop() {
	defer close(l.done)
	var bw *bufio.Writer
	if l.file != nil {
		bw = bufio.NewWriterSize(l.file, loggerBufSize)
	}
	flushTimer := time.NewTimer(loggerFlushCadence)
	if !flushTimer.Stop() {
		select {
		case <-flushTimer.C:
		default:
		}
	}
	defer flushTimer.Stop()
	dirty := false

	writeRecord := func(rec LogRecord) {
		if obs := l.observer.Load(); obs != nil && *obs != nil {
			(*obs)(rec)
		}
		if bw == nil {
			return
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return
		}
		n1, _ := bw.Write(data)
		_ = bw.WriteByte('\n')
		l.written += int64(n1 + 1)
		if !dirty {
			dirty = true
			flushTimer.Reset(loggerFlushCadence)
		}
		if l.written >= l.maxBytes {
			l.rotateLocked(&bw)
			dirty = false
		}
	}

	for {
		select {
		case rec := <-l.ch:
			writeRecord(rec)
		case <-flushTimer.C:
			if bw != nil && dirty {
				_ = bw.Flush()
			}
			dirty = false
		case <-l.quitCh:
			for {
				select {
				case rec := <-l.ch:
					writeRecord(rec)
				default:
					if bw != nil {
						_ = bw.Flush()
					}
					if l.file != nil {
						_ = l.file.Sync()
						_ = l.file.Close()
					}
					return
				}
			}
		}
	}
}

func (l *EventLogger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.quitCh)
		<-l.done
	})
	return nil
}

// TerminalLine is one bounded, UTF-8-safe, secret-redacted entry stored in TerminalRingBuffer.
type TerminalLine struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Text      string `json:"text"`
}

// TerminalRingBuffer provides O(1) bounded memory (500 lines x <=256B) for mobile Terminal tab.
type TerminalRingBuffer struct {
	mu      sync.Mutex
	lines   [TerminalRingCapacity]TerminalLine
	head    int
	count   int
	nextSeq int64
	onLine  atomic.Pointer[func(TerminalLine)]
}

func NewTerminalRingBuffer() *TerminalRingBuffer {
	return &TerminalRingBuffer{}
}

func (rb *TerminalRingBuffer) SetListener(fn func(TerminalLine)) {
	if rb == nil {
		return
	}
	if fn == nil {
		rb.onLine.Store(nil)
		return
	}
	rb.onLine.Store(&fn)
}

func truncateUTF8(s string, maxBytes int) string {
	s = RedactSecrets(s)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if maxBytes < 4 || len(s) <= maxBytes {
		return s
	}
	limit := maxBytes - 3
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + "..."
}

func (rb *TerminalRingBuffer) Append(sev LogSeverity, text string) TerminalLine {
	return rb.AppendAt(time.Now(), sev, text)
}

func (rb *TerminalRingBuffer) AppendAt(ts time.Time, sev LogSeverity, text string) TerminalLine {
	if rb == nil {
		return TerminalLine{}
	}
	clean := truncateUTF8(text, TerminalMaxLineBytes)
	if clean == "" {
		return TerminalLine{}
	}
	entry := TerminalLine{
		Timestamp: ts.Format("15:04:05"),
		Level:     sev.String(),
		Text:      clean,
	}
	rb.mu.Lock()
	rb.nextSeq++
	entry.Seq = rb.nextSeq
	if rb.count < TerminalRingCapacity {
		idx := (rb.head + rb.count) % TerminalRingCapacity
		rb.lines[idx] = entry
		rb.count++
	} else {
		rb.lines[rb.head] = entry
		rb.head = (rb.head + 1) % TerminalRingCapacity
	}
	rb.mu.Unlock()

	if fn := rb.onLine.Load(); fn != nil && *fn != nil {
		(*fn)(entry)
	}
	return entry
}

// Since returns all buffered lines with Seq > sinceSeq in chronological order.
func (rb *TerminalRingBuffer) Since(sinceSeq int64) []TerminalLine {
	if rb == nil {
		return nil
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	out := make([]TerminalLine, 0, rb.count)
	for i := 0; i < rb.count; i++ {
		ln := rb.lines[(rb.head+i)%TerminalRingCapacity]
		if ln.Seq > sinceSeq {
			out = append(out, ln)
		}
	}
	return out
}

func (rb *TerminalRingBuffer) Len() int {
	if rb == nil {
		return 0
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}

func (rb *TerminalRingBuffer) Clear() {
	if rb == nil {
		return
	}
	rb.mu.Lock()
	rb.head = 0
	rb.count = 0
	rb.mu.Unlock()
}

// FormatLogRecord converts an EventLogger record into a concise human-readable terminal line.
func FormatLogRecord(rec LogRecord) (LogSeverity, string) {
	sev := LogInfo
	f := rec.Fields
	sf := func(k string) string {
		if f == nil {
			return ""
		}
		if v, ok := f[k]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	switch rec.Event {
	case "STATE_TRANSITION":
		to := sf("to")
		if to == string(StateHealthy) {
			sev = LogSuccess
		} else if to == string(StateDegraded) || to == string(StateReconnecting) || to == string(StatePausedOffline) {
			sev = LogWarn
		}
		return sev, fmt.Sprintf("[Supervisor] %s -> %s", sf("from"), to)
	case "BOOT_READY":
		return LogSuccess, fmt.Sprintf("[Ready] %s | pool=%s/%s | route=%s | underlay=%sms",
			sf("local_addr"), sf("healthy_workers"), sf("pool_size"), sf("routing_mode"), sf("underlay_baseline_ms"))
	case "SESSION_START":
		return LogInfo, fmt.Sprintf("[Start] codespace=%s local=%s pool=%s max_ch=%s",
			sf("codespace"), sf("local_addr"), sf("pool_size"), sf("max_conns"))
	case "SHUTDOWN_COMPLETE":
		return LogInfo, fmt.Sprintf("[Stop] done (%s) | stop_invoked=%s", sf("reason"), sf("stop_codespace_invoked"))
	case "POOL_WORKER_FAILOVER":
		return LogWarn, fmt.Sprintf("[Pool] failover %s reason=%s healthy=%s", sf("tunnel_id"), sf("reason"), sf("healthy_peers"))
	case "POOL_PRIMARY_SWITCH":
		return LogInfo, fmt.Sprintf("[Route] %s -> %s (%s)", sf("from"), sf("to"), sf("reason"))
	case "WORKER_PARKED":
		return LogInfo, fmt.Sprintf("[Power] parked %s (IDLE_DEEP 2->1)", sf("tunnel_id"))
	case "WORKER_UNPARKED":
		return LogInfo, fmt.Sprintf("[Power] unparking %s (wake-up)", sf("tunnel_id"))
	case "WORKER_DEGRADED":
		return LogWarn, fmt.Sprintf("[Degraded] %s reason=%s", sf("tunnel_id"), sf("reason"))
	case "WORKER_RECOVERED":
		return LogSuccess, fmt.Sprintf("[Recovered] %s rtt=%sms", sf("tunnel_id"), sf("recovery_probe_rtt_ms"))
	case "WORKER_SLOW_LANE_EVICT":
		return LogWarn, fmt.Sprintf("[Pool] slow-lane evict %s rtt=%sms rho=%s", sf("tunnel_id"), sf("ewma_rtt_ms"), sf("relative_rho"))
	case "WORKER_SLOW_LANE_EVICT_DEFERRED":
		return LogWarn, fmt.Sprintf("[Pool] slow-lane evict deferred (%s) for %s", sf("defer_reason"), sf("tunnel_id"))
	case "NETWORK_CHANGE":
		return LogInfo, fmt.Sprintf("[Net] handover type=%s metered=%s action=%s", sf("network_type"), sf("is_metered"), sf("action"))
	case "SUSPEND_CLOCK_JUMP":
		return LogWarn, fmt.Sprintf("[Power] Doze suspend jump detected (%sms) — probing tunnels", sf("jump_ms"))
	case "GITHUB_API_BACKOFF":
		return LogError, fmt.Sprintf("[WAF Guard] backoff class=%s cooldown=%sms", sf("failure_class"), sf("cooldown_ms"))
	case "GITHUB_API_THROTTLED":
		return LogWarn, fmt.Sprintf("[WAF Guard] throttled (%s) wait=%sms 5m=%s", sf("block_reason"), sf("wait_ms"), sf("calls_last_5m"))
	case "FATAL_BOOT_ERROR":
		return LogError, fmt.Sprintf("[Fatal] %s", RedactSecrets(sf("message")))
	case "GITHUB_TUNNEL_PROPS_MISSING":
		return LogError, fmt.Sprintf("[GitHub] codespace=%s missing tunnelProperties (%s) — use Option A Device Flow", sf("codespace"), sf("keys"))
	case "WORKER_BOOT_STAGE":
		return LogInfo, fmt.Sprintf("[Boot %s] %s: %s", sf("stage"), sf("tunnel_id"), RedactSecrets(sf("detail")))
	case "WORKER_BOOT_FAIL":
		return LogError, fmt.Sprintf("[Boot] %s failed: %s", sf("tunnel_id"), RedactSecrets(sf("error")))
	case "WORKER_PROBE_FAIL":
		return LogWarn, fmt.Sprintf("[Probe] %s target=%s failed: %s", sf("tunnel_id"), sf("target"), RedactSecrets(sf("error")))
	case "WORKER_BOOT_OK":
		return LogSuccess, fmt.Sprintf("[Boot] %s online rtt=%sms wan=%s pmtu576=%s", sf("tunnel_id"), sf("p50_ms"), sf("wan_remote"), sf("pmtu576"))
	case "PANIC_RECOVERED":
		return LogError, fmt.Sprintf("[Panic] recovered in %s: %s", sf("goroutine"), sf("panic"))
	default:
		if e := sf("error"); e != "" {
			return LogWarn, fmt.Sprintf("[%s] %s", rec.Event, RedactSecrets(e))
		}
		if r := sf("reason"); r != "" {
			return LogInfo, fmt.Sprintf("[%s] %s", rec.Event, RedactSecrets(r))
		}
		return LogInfo, fmt.Sprintf("[%s]", rec.Event)
	}
}

// safeGo launches a goroutine wrapped in defer recover() so an unexpected panic NEVER crashes the Android JVM.
func safeGo(logger *EventLogger, name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				if logger != nil {
					logger.Log("PANIC_RECOVERED", map[string]any{
						"goroutine": name,
						"panic":     fmt.Sprintf("%v", r),
						"stack":     truncateUTF8(string(debug.Stack()), 512),
					})
				}
			}
		}()
		fn()
	}()
}
