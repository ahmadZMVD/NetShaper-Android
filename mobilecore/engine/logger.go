package engine

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	loggerChannelCap      = 512
	loggerBufSize         = 8192
	loggerFlushCadence    = DefaultLogFlushCadence
	TerminalRingCapacity  = 2500
	TerminalMaxLineBytes  = 384
	logSchemaVersion      = 1
	maxActiveClusters     = 64
	maxClusterRepeatCount = 100
	uiImmediateBurstLimit = 3
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
	reGitHubToken    = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b`)
	reGitHubPAT      = regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{12,}\b`)
	reHeaderSecField = regexp.MustCompile(`(?i)\b(X-Tunnel-Authorization|Authorization)\s*:\s*(?:(?:Bearer|tunnel)\s+)?[^\s"',;]+`)
	reBearerAuth     = regexp.MustCompile(`(?i)\b(Bearer|token|tunnel)\s+[A-Za-z0-9._~+/=-]{8,}`)
	reJWTToken       = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\b`)
	reJSONSecField   = regexp.MustCompile(`(?i)("(?:access_token|github_token|connect_access_token|manage_ports_access_token|connectAccessToken|managePortsAccessToken|authorization)"\s*:\s*")([^"]+)(")`)
	reURLSecParam    = regexp.MustCompile(`(?i)([?&](?:access_token|token|connect_access_token|manage_ports_access_token|connectAccessToken|managePortsAccessToken)=)([^&\s"']+)`)

	// Volatile token scrubbers for deterministic error-burst clustering (applied strictly AFTER RedactSecrets).
	reClusterTraceField = regexp.MustCompile(`(?i)"traceId"\s*:\s*"[^"]*"`)
	reClusterTraceParam = regexp.MustCompile(`(?i)([?&]traceId=)[^&\s"']+`)
	reClusterTraceHex   = regexp.MustCompile(`\b00-[0-9a-fA-F]{8,}[.\w-]*`)
	reClusterPort       = regexp.MustCompile(`:\d{4,5}\b`)
	reClusterDur        = regexp.MustCompile(`\b\d+(?:\.\d+)?\s*(?:ms|s)\b`)
	reClusterNum        = regexp.MustCompile(`\b\d{4,}\b`)
)

// RedactSecrets strips GitHub OAuth tokens, PATs, Bearer/tunnel headers, URL query secrets, and Dev Tunnels JWTs.
func RedactSecrets(s string) string {
	if s == "" {
		return ""
	}
	s = reJSONSecField.ReplaceAllString(s, `${1}[REDACTED]${3}`)
	s = reURLSecParam.ReplaceAllString(s, `${1}[REDACTED]`)
	s = reHeaderSecField.ReplaceAllString(s, `${1}: [REDACTED]`)
	s = reGitHubPAT.ReplaceAllString(s, "[REDACTED_GH_PAT]")
	s = reGitHubToken.ReplaceAllString(s, "[REDACTED_GH_TOKEN]")
	s = reJWTToken.ReplaceAllString(s, "[REDACTED_JWT]")
	s = reBearerAuth.ReplaceAllString(s, `$1 [REDACTED]`)
	return s
}

func redactValue(v any) any {
	switch tv := v.(type) {
	case string:
		return RedactSecrets(tv)
	case []string:
		cp := make([]string, len(tv))
		for i, item := range tv {
			cp[i] = RedactSecrets(item)
		}
		return cp
	case map[string]any:
		return redactFields(tv)
	default:
		return v
	}
}

func redactFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") ||
			strings.Contains(lk, "secret") ||
			strings.Contains(lk, "authorization") ||
			strings.Contains(lk, "password") ||
			strings.Contains(lk, "credential") {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func normalizeClusterSignature(event, tunnelID, errText string) string {
	s := RedactSecrets(strings.TrimSpace(errText))
	s = reClusterTraceField.ReplaceAllString(s, `"traceId":"<TRACE>"`)
	s = reClusterTraceParam.ReplaceAllString(s, `${1}<TRACE>`)
	s = reClusterTraceHex.ReplaceAllString(s, "<TRACE>")
	s = reClusterPort.ReplaceAllString(s, ":<PORT>")
	s = reClusterDur.ReplaceAllString(s, "<DUR>")
	s = reClusterNum.ReplaceAllString(s, "<N>")
	s = RedactSecrets(s)
	if len(s) > 128 {
		s = s[:128]
	}
	return event + "|" + RedactSecrets(strings.TrimSpace(tunnelID)) + "|" + s
}

func isClusterableEvent(event string) bool {
	switch event {
	case "WORKER_BOOT_FAIL",
		"WORKER_PROBE_FAIL",
		"SOCKS_STREAM_ERR",
		"GITHUB_API_THROTTLED",
		"WORKER_SLOW_LANE_EVICT_DEFERRED",
		"WORKER_SLOW_LANE_SOFT_DRAIN",
		"DNS_POISON_DETECTED":
		return true
	default:
		return false
	}
}

func fieldString(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	if v, ok := fields[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func extractClusterErrText(rec LogRecord) string {
	if e := fieldString(rec.Fields, "error"); e != "" {
		return e
	}
	if br := fieldString(rec.Fields, "block_reason"); br != "" {
		if r := fieldString(rec.Fields, "reason"); r != "" {
			return br + ":" + r
		}
		return br
	}
	if dr := fieldString(rec.Fields, "defer_reason"); dr != "" {
		return dr
	}
	if d := fieldString(rec.Fields, "detail"); d != "" {
		return d
	}
	if r := fieldString(rec.Fields, "reason"); r != "" {
		return r
	}
	return rec.Event
}

// LogRecord represents a single append-only JSONL telemetry or clustered-burst record.
type LogRecord struct {
	SchemaVersion int            `json:"v"`
	UnixMS        int64          `json:"unix_ms"`
	Timestamp     string         `json:"ts"`
	SessionID     string         `json:"session_id"`
	Event         string         `json:"event"`
	Severity      string         `json:"severity"`
	ClusterSig    string         `json:"cluster_sig,omitempty"`
	RepeatCount   int            `json:"repeat_count,omitempty"`
	FirstUnixMS   int64          `json:"first_unix_ms,omitempty"`
	LastUnixMS    int64          `json:"last_unix_ms,omitempty"`
	Fields        map[string]any `json:"fields,omitempty"`
}

type pendingCluster struct {
	sig          string
	event        string
	severity     string
	sessionID    string
	tunnelID     string
	firstAt      time.Time
	lastAt       time.Time
	firstUnixMS  int64
	lastUnixMS   int64
	count        int
	uiForwarded  int
	sampleFields map[string]any
}

// EventLogger provides panic-proof, non-blocking, zero-idle-wakeup, clustered & gzip-archived JSONL telemetry.
type EventLogger struct {
	sessionID       string
	path            string
	maxBytes        int64
	maxArchiveBytes int64
	archiveEnabled  bool
	clusterWindow   time.Duration
	flushCadence    time.Duration
	file            *os.File
	written         int64
	archiveSeq      uint64
	ch              chan LogRecord
	quitCh          chan struct{}
	done            chan struct{}
	closed          atomic.Bool
	dropped         atomic.Uint64
	dedupedCount    atomic.Uint64
	archiveCount    atomic.Int64
	flushCount      atomic.Uint64
	timerWakeCount  atomic.Uint64
	observer        atomic.Pointer[func(LogRecord)]
	closeOnce       sync.Once
}

// NewEventLogger opens path (or runs in-memory-observer-only mode if path == "") with legacy .1 single-backup rotation.
func NewEventLogger(path string, maxBytes int64) (*EventLogger, error) {
	return newEventLoggerInternal(path, maxBytes, 0, false, DefaultLogClusterWindow, loggerFlushCadence)
}

// NewEventLoggerWithArchive opens path with gzip-compressed segment rotation, error-burst clustering, and FIFO pruning.
func NewEventLoggerWithArchive(path string, maxSegmentBytes, maxArchiveBytes int64, clusterWindow time.Duration) (*EventLogger, error) {
	if maxArchiveBytes <= 0 {
		maxArchiveBytes = DefaultMaxArchiveTotalBytes
	}
	if clusterWindow <= 0 {
		clusterWindow = DefaultLogClusterWindow
	}
	return newEventLoggerInternal(path, maxSegmentBytes, maxArchiveBytes, true, clusterWindow, loggerFlushCadence)
}

func newEventLoggerForTest(path string, maxSegmentBytes, maxArchiveBytes int64, archiveEnabled bool, clusterWindow, flushCadence time.Duration) (*EventLogger, error) {
	return newEventLoggerInternal(path, maxSegmentBytes, maxArchiveBytes, archiveEnabled, clusterWindow, flushCadence)
}

func newEventLoggerInternal(
	path string,
	maxBytes int64,
	maxArchiveBytes int64,
	archiveEnabled bool,
	clusterWindow time.Duration,
	flushCadence time.Duration,
) (*EventLogger, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxLogFileBytes
	}
	if clusterWindow <= 0 {
		clusterWindow = DefaultLogClusterWindow
	}
	if flushCadence <= 0 {
		flushCadence = loggerFlushCadence
	}
	var f *os.File
	var size int64
	var initArchives int64
	if strings.TrimSpace(path) != "" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir log dir: %w", err)
		}
		if archiveEnabled {
			cleanupStaleArchiveArtifacts(dir)
			initArchives = int64(len(listArchiveFiles(dir)))
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
		sessionID:       fmt.Sprintf("mob%d-%d", os.Getpid(), time.Now().UTC().UnixNano()),
		path:            path,
		maxBytes:        maxBytes,
		maxArchiveBytes: maxArchiveBytes,
		archiveEnabled:  archiveEnabled,
		clusterWindow:   clusterWindow,
		flushCadence:    flushCadence,
		file:            f,
		written:         size,
		ch:              make(chan LogRecord, loggerChannelCap),
		quitCh:          make(chan struct{}),
		done:            make(chan struct{}),
	}
	l.archiveCount.Store(initArchives)
	safeGo(nil, "event_logger_writer", l.writerLoop)
	return l, nil
}

func cleanupStaleArchiveArtifacts(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasSuffix(name, ".jsonl.gz.tmp") || strings.Contains(name, ".rotating.") {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

func listArchiveFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasPrefix(name, "archive_") && strings.HasSuffix(name, ".jsonl.gz") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	sort.Strings(out)
	return out
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

// ArchiveStats returns (clustered_errors_deduped, archive_segments_count) wait-free.
func (l *EventLogger) ArchiveStats() (uint64, int) {
	if l == nil {
		return 0, 0
	}
	return l.dedupedCount.Load(), int(l.archiveCount.Load())
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
	now := time.Now().UTC()
	cleanFields := redactFields(fields)
	rec := LogRecord{
		SchemaVersion: logSchemaVersion,
		UnixMS:        now.UnixMilli(),
		Timestamp:     now.Format(time.RFC3339Nano),
		SessionID:     l.sessionID,
		Event:         event,
		Fields:        cleanFields,
	}
	sev, _ := FormatLogRecord(rec)
	rec.Severity = sev.String()

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

func (l *EventLogger) compressSegmentAtomic(srcPath string, now time.Time) {
	dir := filepath.Dir(srcPath)
	tsUTC := now.UTC().Format("20060102_150405")
	var dstPath string
	for {
		l.archiveSeq++
		cand := filepath.Join(dir, fmt.Sprintf("archive_%s_%06d.jsonl.gz", tsUTC, l.archiveSeq))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			dstPath = cand
			break
		}
	}
	tmpPath := dstPath + ".tmp"
	stagingPath := fmt.Sprintf("%s.rotating.%d", srcPath, l.archiveSeq)

	// Rename active segment to staging so concurrent live readers on POSIX never block compression.
	// On Windows where a concurrent reader may briefly hold srcPath open, retry rename briefly then fall back to copy+truncate.
	renamed := false
	for attempt := 0; attempt < 4; attempt++ {
		if err := os.Rename(srcPath, stagingPath); err == nil {
			renamed = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	copySrc := srcPath
	if renamed {
		copySrc = stagingPath
	}

	var srcFile *os.File
	var openErr error
	for attempt := 0; attempt < 4; attempt++ {
		srcFile, openErr = os.Open(copySrc)
		if openErr == nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if openErr != nil {
		if renamed {
			_ = os.Remove(stagingPath)
		}
		return
	}

	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = srcFile.Close()
		if renamed {
			_ = os.Remove(stagingPath)
		}
		return
	}
	gw, gwErr := gzip.NewWriterLevel(tmpFile, gzip.DefaultCompression)
	if gwErr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		_ = srcFile.Close()
		if renamed {
			_ = os.Remove(stagingPath)
		}
		return
	}
	var copyBuf [4096]byte
	_, copyErr := io.CopyBuffer(gw, srcFile, copyBuf[:])
	closeGWErr := gw.Close()
	syncErr := tmpFile.Sync()
	closeTmpErr := tmpFile.Close()
	_ = srcFile.Close()

	if copyErr != nil || closeGWErr != nil || syncErr != nil || closeTmpErr != nil {
		_ = os.Remove(tmpPath)
		if renamed {
			_ = os.Remove(stagingPath)
		}
		return
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
	}
	if renamed {
		_ = os.Remove(stagingPath)
	} else {
		_ = os.Truncate(srcPath, 0)
	}
}

func (l *EventLogger) pruneArchivesLocked() {
	if !l.archiveEnabled || l.path == "" {
		return
	}
	archives := listArchiveFiles(filepath.Dir(l.path))
	if l.maxArchiveBytes > 0 {
		type archEntry struct {
			path string
			size int64
		}
		items := make([]archEntry, 0, len(archives))
		var totalArchBytes int64
		for _, p := range archives {
			if info, err := os.Stat(p); err == nil {
				items = append(items, archEntry{path: p, size: info.Size()})
				totalArchBytes += info.Size()
			}
		}
		for len(items) > 1 && totalArchBytes+l.written > l.maxArchiveBytes {
			oldest := items[0]
			if err := os.Remove(oldest.path); err == nil {
				totalArchBytes -= oldest.size
				items = items[1:]
			} else {
				break
			}
		}
		l.archiveCount.Store(int64(len(items)))
		return
	}
	l.archiveCount.Store(int64(len(archives)))
}

func (l *EventLogger) rotateLocked(bw **bufio.Writer) {
	if l.file == nil || l.path == "" || l.maxBytes <= 0 || l.written < l.maxBytes {
		return
	}
	if *bw != nil {
		_ = (*bw).Flush()
		l.flushCount.Add(1)
	}
	_ = l.file.Close()
	l.file = nil
	*bw = nil

	if !l.archiveEnabled {
		backup := l.path + ".1"
		_ = os.Remove(backup)
		_ = os.Rename(l.path, backup)
	} else {
		l.compressSegmentAtomic(l.path, time.Now().UTC())
	}

	nf, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		l.written = 0
		return
	}
	l.file = nf
	l.written = 0
	*bw = bufio.NewWriterSize(nf, loggerBufSize)
	if l.archiveEnabled {
		l.pruneArchivesLocked()
	}
}

func (l *EventLogger) writerLoop() {
	defer close(l.done)
	var bw *bufio.Writer
	if l.file != nil {
		bw = bufio.NewWriterSize(l.file, loggerBufSize)
	}

	flushTimer := time.NewTimer(l.flushCadence)
	if !flushTimer.Stop() {
		select {
		case <-flushTimer.C:
		default:
		}
	}
	defer flushTimer.Stop()

	dirty := false
	timerArmed := false
	var timerTargetDelay time.Duration

	stopFlush := func() {
		if timerArmed {
			if !flushTimer.Stop() {
				select {
				case <-flushTimer.C:
				default:
				}
			}
			timerArmed = false
			timerTargetDelay = 0
		}
	}

	armFlush := func(d time.Duration) {
		if d <= 0 {
			d = l.flushCadence
		}
		if timerArmed {
			if d >= timerTargetDelay {
				return
			}
			stopFlush()
		}
		flushTimer.Reset(d)
		timerArmed = true
		timerTargetDelay = d
	}

	activeClusters := make(map[string]*pendingCluster)

	emitRecord := func(rec LogRecord, notifyObserver bool) {
		if notifyObserver {
			if obs := l.observer.Load(); obs != nil && *obs != nil {
				(*obs)(rec)
			}
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
			armFlush(l.flushCadence)
		}
		if l.written >= l.maxBytes {
			l.rotateLocked(&bw)
			dirty = false
		}
	}

	flushCluster := func(c *pendingCluster, now time.Time) {
		if c == nil {
			return
		}
		delete(activeClusters, c.sig)
		if c.count <= 0 {
			return
		}
		nowUTC := now.UTC()
		clustered := LogRecord{
			SchemaVersion: logSchemaVersion,
			UnixMS:        nowUTC.UnixMilli(),
			Timestamp:     nowUTC.Format(time.RFC3339Nano),
			SessionID:     c.sessionID,
			Event:         c.event,
			Severity:      c.severity,
			ClusterSig:    c.sig,
			RepeatCount:   c.count,
			FirstUnixMS:   c.firstUnixMS,
			LastUnixMS:    c.lastUnixMS,
			Fields:        c.sampleFields,
		}
		// Avoid duplicating a 4th Terminal line for small <=3 bursts already visible live, while surfacing larger storms.
		emitRecord(clustered, c.count > uiImmediateBurstLimit-1)
	}

	flushExpiredClusters := func(now time.Time) {
		for _, c := range activeClusters {
			if now.Sub(c.firstAt) >= l.clusterWindow {
				flushCluster(c, now)
			}
		}
	}

	flushTunnelClusters := func(tunnelID string, now time.Time) {
		if tunnelID == "" {
			return
		}
		for _, c := range activeClusters {
			if c.tunnelID == tunnelID {
				flushCluster(c, now)
			}
		}
	}

	flushAllClusters := func(now time.Time) {
		for _, c := range activeClusters {
			flushCluster(c, now)
		}
	}

	evictOldestCluster := func(now time.Time) {
		var oldest *pendingCluster
		for _, c := range activeClusters {
			if oldest == nil || c.firstAt.Before(oldest.firstAt) {
				oldest = c
			}
		}
		if oldest != nil {
			flushCluster(oldest, now)
		}
	}

	nextClusterWakeDelay := func(now time.Time) (time.Duration, bool) {
		var minRem time.Duration
		found := false
		for _, c := range activeClusters {
			if c.count <= 0 {
				continue
			}
			rem := l.clusterWindow - now.Sub(c.firstAt)
			if rem < 10*time.Millisecond {
				rem = 10 * time.Millisecond
			}
			if !found || rem < minRem {
				minRem = rem
				found = true
			}
		}
		return minRem, found
	}

	scheduleNextWake := func(now time.Time) {
		if dirty {
			armFlush(l.flushCadence)
			return
		}
		if rem, ok := nextClusterWakeDelay(now); ok {
			armFlush(rem)
		}
	}

	processRecord := func(rec LogRecord) {
		now := time.Now().UTC()
		flushExpiredClusters(now)

		if !isClusterableEvent(rec.Event) {
			switch rec.Event {
			case "WORKER_BOOT_OK", "WORKER_RECOVERED":
				flushTunnelClusters(fieldString(rec.Fields, "tunnel_id"), now)
			case "SESSION_ROLLUP", "SHUTDOWN_COMPLETE", "SESSION_STOP":
				flushAllClusters(now)
			}
			emitRecord(rec, true)
			scheduleNextWake(now)
			return
		}

		tunnelID := fieldString(rec.Fields, "tunnel_id")
		sig := normalizeClusterSignature(rec.Event, tunnelID, extractClusterErrText(rec))
		c, exists := activeClusters[sig]
		if !exists {
			if len(activeClusters) >= maxActiveClusters {
				evictOldestCluster(now)
			}
			emitRecord(rec, true)
			activeClusters[sig] = &pendingCluster{
				sig:          sig,
				event:        rec.Event,
				severity:     rec.Severity,
				sessionID:    rec.SessionID,
				tunnelID:     tunnelID,
				firstAt:      now,
				lastAt:       now,
				uiForwarded:  1,
				sampleFields: rec.Fields,
			}
			scheduleNextWake(now)
			return
		}

		c.count++
		l.dedupedCount.Add(1)
		c.lastAt = now
		if c.firstUnixMS == 0 || rec.UnixMS < c.firstUnixMS {
			c.firstUnixMS = rec.UnixMS
		}
		if rec.UnixMS > c.lastUnixMS {
			c.lastUnixMS = rec.UnixMS
		}
		if c.uiForwarded < uiImmediateBurstLimit {
			c.uiForwarded++
			if obs := l.observer.Load(); obs != nil && *obs != nil {
				(*obs)(rec)
			}
		}
		if c.count >= maxClusterRepeatCount {
			flushCluster(c, now)
		}
		scheduleNextWake(now)
	}

	for {
		select {
		case rec := <-l.ch:
			processRecord(rec)
		case <-flushTimer.C:
			l.timerWakeCount.Add(1)
			timerArmed = false
			timerTargetDelay = 0
			now := time.Now().UTC()
			flushExpiredClusters(now)
			if bw != nil && dirty {
				_ = bw.Flush()
				l.flushCount.Add(1)
				dirty = false
			}
			scheduleNextWake(now)
		case <-l.quitCh:
			stopFlush()
			for {
				select {
				case rec := <-l.ch:
					processRecord(rec)
				default:
					flushAllClusters(time.Now().UTC())
					if bw != nil {
						if dirty {
							_ = bw.Flush()
							l.flushCount.Add(1)
							dirty = false
						} else {
							_ = bw.Flush()
						}
					}
					if l.archiveEnabled {
						l.pruneArchivesLocked()
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
	UnixMS    int64  `json:"unix_ms"`
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Text      string `json:"text"`
}

// TerminalRingBuffer provides O(1) bounded memory (2500 lines x <=384B) for mobile Terminal tab.
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
	if ts.IsZero() {
		ts = time.Now()
	}
	clean := truncateUTF8(text, TerminalMaxLineBytes)
	if clean == "" {
		return TerminalLine{}
	}
	entry := TerminalLine{
		UnixMS:    ts.UnixMilli(),
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

func formatCompactBytesGo(v any) string {
	var b float64
	switch n := v.(type) {
	case uint64:
		b = float64(n)
	case int64:
		if n > 0 {
			b = float64(n)
		}
	case int:
		if n > 0 {
			b = float64(n)
		}
	case float64:
		if n > 0 {
			b = n
		}
	}
	const (
		kb = 1024.0
		mb = kb * 1024.0
		gb = mb * 1024.0
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.2fGB", b/gb)
	case b >= mb:
		return fmt.Sprintf("%.1fMB", b/mb)
	case b >= kb:
		return fmt.Sprintf("%.0fKB", b/kb)
	default:
		return fmt.Sprintf("%.0fB", b)
	}
}

func formatCompactMSGo(v any) string {
	var ms float64
	switch n := v.(type) {
	case float64:
		ms = n
	case int64:
		ms = float64(n)
	case int:
		ms = float64(n)
	}
	if ms <= 0 {
		return "--"
	}
	return fmt.Sprintf("%.0fms", ms)
}

// FormatLogRecord converts an EventLogger record into a concise human-readable terminal line.
func FormatLogRecord(rec LogRecord) (LogSeverity, string) {
	sev, text := formatLogRecordBase(rec)
	if rec.RepeatCount > 0 && rec.ClusterSig != "" {
		text = fmt.Sprintf("%s (x%d clustered)", text, rec.RepeatCount)
	}
	return sev, text
}

func formatLogRecordBase(rec LogRecord) (LogSeverity, string) {
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
	case "POOL_SUMMARY":
		st := sf("state")
		if st == string(StateDegraded) {
			sev = LogWarn
		}
		var b strings.Builder
		fmt.Fprintf(&b, "[Summary] state=%s power=%s mode=%s", st, sf("power_state"), sf("routing_mode"))
		if pri := sf("primary_tunnel"); pri != "" {
			fmt.Fprintf(&b, " pri=%s", pri)
		}
		fmt.Fprintf(&b, " pool=%s/%s active=%s p50=%s underlay=%s",
			sf("healthy_workers"), sf("pool_size"), sf("active_conns"),
			formatCompactMSGo(f["aggregate_p50_ms"]), formatCompactMSGo(f["underlay_baseline_ms"]))
		if t1s := sf("t1_state"); t1s != "" {
			if t1s == string(TunnelHealthy) {
				fmt.Fprintf(&b, " t1=%s", formatCompactMSGo(f["t1_rtt_ms"]))
			} else {
				fmt.Fprintf(&b, " t1=%s", t1s)
			}
		}
		if t2s := sf("t2_state"); t2s != "" {
			if t2s == string(TunnelHealthy) {
				fmt.Fprintf(&b, " t2=%s", formatCompactMSGo(f["t2_rtt_ms"]))
			} else {
				fmt.Fprintf(&b, " t2=%s", t2s)
			}
		}
		upSrc := f["total_bytes_up"]
		if upSrc == nil {
			upSrc = f["bytes_up_window"]
		}
		downSrc := f["total_bytes_down"]
		if downSrc == nil {
			downSrc = f["bytes_down_window"]
		}
		wafMax5m := sf("waf_max_5m")
		if wafMax5m == "" {
			wafMax5m = "6"
		}
		fmt.Fprintf(&b, " up=%s down=%s waf=%s/%s",
			formatCompactBytesGo(upSrc), formatCompactBytesGo(downSrc), sf("waf_5m"), wafMax5m)
		return sev, b.String()
	case "SESSION_ROLLUP":
		return LogInfo, fmt.Sprintf("[Session] dur=%ss up=%s down=%s failovers=%s pri_sw=%s evicts=%s deduped=%s segs=%s reason=%s",
			sf("duration_sec"), formatCompactBytesGo(f["total_bytes_up"]), formatCompactBytesGo(f["total_bytes_down"]),
			sf("total_failovers"), sf("primary_switches"), sf("slow_lane_evictions"),
			sf("clustered_errors_deduped"), sf("archive_segments_count"), sf("stop_reason"))
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
	case "WORKER_SLOW_LANE_SOFT_DRAIN":
		return LogInfo, fmt.Sprintf("[Pool] %s soft-drained (active=%s rtt=%sms err=%s) — protecting live streams",
			sf("tunnel_id"), sf("active_conns"), sf("ewma_rtt_ms"), sf("stream_err_rate"))
	case "BOOT_QUALITY_SOLE_ACCEPT":
		return LogInfo, fmt.Sprintf("[Boot] %s accepted on slow link (reason=%s p50=%sms jitter=%sms)",
			sf("tunnel_id"), sf("reason"), sf("p50_ms"), sf("jitter_ms"))
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
	case "CREDENTIAL_INVALIDATED":
		return LogWarn, fmt.Sprintf("[Auth] invalidated stale tunnel=%s reason=%s (gen=%s)", sf("tunnel_id"), sf("reason"), sf("stale_gen"))
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
