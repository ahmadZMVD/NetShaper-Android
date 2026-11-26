package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	metricsSchemaVersion = "netshaper.metrics.v7.mobile"
	metricsChannelCap    = 1024
	metricsBufSize       = 16 * 1024
	metricsFlushCadence  = 2 * time.Second
)

type MetricRecord struct {
	Schema    string         `json:"schema"`
	Timestamp string         `json:"ts"`
	SessionID string         `json:"session_id"`
	Stream    string         `json:"stream"`
	Data      map[string]any `json:"data"`
}

type ConnMetric struct {
	TunnelID        string  `json:"tunnel_id"`
	TargetAddr      string  `json:"target_addr"`
	QueueWaitMS     float64 `json:"queue_wait_ms"`
	DialRTTMS       float64 `json:"dial_rtt_ms"`
	ActiveMS        float64 `json:"active_ms"`
	BytesUp         uint64  `json:"bytes_up"`
	BytesDown       uint64  `json:"bytes_down"`
	CloseReason     string  `json:"close_reason"`
	PressureReaped  bool    `json:"pressure_reaped"`
	CopyBufferBytes int     `json:"copy_buffer_bytes"`
}

type MetricsEmitter struct {
	sessionID string
	file      *os.File
	ch        chan MetricRecord
	quitCh    chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	emitted   atomic.Uint64
	dropped   atomic.Uint64
	closeOnce sync.Once
}

func NewMetricsEmitter(path, sessionID string) (*MetricsEmitter, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open metrics %q: %w", path, err)
	}
	if sessionID == "" {
		sessionID = fmt.Sprintf("mob%d-%d", os.Getpid(), time.Now().UTC().UnixNano())
	}
	m := &MetricsEmitter{
		sessionID: sessionID,
		file:      f,
		ch:        make(chan MetricRecord, metricsChannelCap),
		quitCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	safeGo(nil, "metrics_writer", m.writerLoop)
	return m, nil
}

func (m *MetricsEmitter) Emit(stream string, data map[string]any) {
	if m == nil || m.closed.Load() {
		return
	}
	rec := MetricRecord{
		Schema:    metricsSchemaVersion,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: m.sessionID,
		Stream:    stream,
		Data:      redactFields(data),
	}
	select {
	case <-m.quitCh:
		return
	default:
	}
	select {
	case m.ch <- rec:
		m.emitted.Add(1)
	case <-m.quitCh:
		return
	default:
		m.dropped.Add(1)
	}
}

func (m *MetricsEmitter) EmitConn(cm ConnMetric) {
	if m == nil || m.closed.Load() {
		return
	}
	m.Emit("conn", map[string]any{
		"tunnel_id":         cm.TunnelID,
		"target_addr":       cm.TargetAddr,
		"queue_wait_ms":     round2(cm.QueueWaitMS),
		"dial_rtt_ms":       round2(cm.DialRTTMS),
		"active_ms":         round2(cm.ActiveMS),
		"bytes_up":          cm.BytesUp,
		"bytes_down":        cm.BytesDown,
		"close_reason":      cm.CloseReason,
		"pressure_reaped":   cm.PressureReaped,
		"copy_buffer_bytes": cm.CopyBufferBytes,
	})
}

func (m *MetricsEmitter) writerLoop() {
	defer close(m.done)
	bw := bufio.NewWriterSize(m.file, metricsBufSize)
	flushTimer := time.NewTimer(metricsFlushCadence)
	if !flushTimer.Stop() {
		select {
		case <-flushTimer.C:
		default:
		}
	}
	defer flushTimer.Stop()
	dirty := false

	writeRec := func(rec MetricRecord) {
		b, err := json.Marshal(rec)
		if err != nil {
			return
		}
		_, _ = bw.Write(b)
		_ = bw.WriteByte('\n')
		if !dirty {
			dirty = true
			flushTimer.Reset(metricsFlushCadence)
		}
	}

	for {
		select {
		case rec := <-m.ch:
			writeRec(rec)
		case <-flushTimer.C:
			if dirty {
				_ = bw.Flush()
				dirty = false
			}
		case <-m.quitCh:
			for {
				select {
				case rec := <-m.ch:
					writeRec(rec)
				default:
					_ = bw.Flush()
					_ = m.file.Sync()
					_ = m.file.Close()
					return
				}
			}
		}
	}
}

func (m *MetricsEmitter) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		close(m.quitCh)
		<-m.done
	})
	return nil
}

func computeRTTStats(samples []float64) (minV, p50, p95, maxV float64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	sort.Float64s(samples)
	idx50 := int(math.Ceil(0.50*float64(len(samples)))) - 1
	idx95 := int(math.Ceil(0.95*float64(len(samples)))) - 1
	if idx50 < 0 {
		idx50 = 0
	}
	if idx95 < 0 {
		idx95 = 0
	}
	return samples[0], samples[idx50], samples[idx95], samples[len(samples)-1]
}

func round2(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*100) / 100
}
