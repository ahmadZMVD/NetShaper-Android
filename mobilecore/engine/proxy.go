package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	acceptBackoffMin        = 5 * time.Millisecond
	acceptBackoffMax        = 100 * time.Millisecond
	wanVerifiedMinDownBytes = 1 // direct-tcpip carries pure payload (SOCKS5 header already terminated locally)
)

type closeWriter interface {
	CloseWrite() error
}

type deadlineConn struct {
	net.Conn
	idleTimeout       time.Duration
	streamIdleTimeout time.Duration
	drainTimeout      time.Duration

	established    atomic.Bool
	draining       atomic.Bool
	pressureReaped atomic.Bool
	readUntilNS    atomic.Int64
	writeUntilNS   atomic.Int64
	readMu         sync.Mutex
	writeMu        sync.Mutex

	onReadBytes func(n int)
}

func (d *deadlineConn) baseIdleTimeout() time.Duration {
	if d.established.Load() && d.streamIdleTimeout > d.idleTimeout {
		return d.streamIdleTimeout
	}
	return d.idleTimeout
}

func (d *deadlineConn) activeTimeout() time.Duration {
	base := d.baseIdleTimeout()
	if d.draining.Load() && d.drainTimeout > 0 && d.drainTimeout < base {
		return d.drainTimeout
	}
	return base
}

func (d *deadlineConn) minRemainingNS(t time.Duration) int64 {
	if d.draining.Load() {
		return int64((t * 4) / 5)
	}
	return int64(t / 2)
}

func (d *deadlineConn) promoteToStreaming() {
	if !d.established.CompareAndSwap(false, true) {
		return
	}
	if d.streamIdleTimeout <= d.idleTimeout || d.pressureReaped.Load() || d.draining.Load() {
		return
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.pressureReaped.Load() || d.draining.Load() {
		return
	}
	target := time.Now().Add(d.streamIdleTimeout)
	if target.UnixNano() > d.readUntilNS.Load() {
		_ = d.Conn.SetReadDeadline(target)
		d.readUntilNS.Store(target.UnixNano())
	}
}

func (d *deadlineConn) refreshReadDeadline(now time.Time) {
	if d == nil || d.pressureReaped.Load() || d.draining.Load() {
		return
	}
	d.armReadDeadline(now)
}

func (d *deadlineConn) armReadDeadline(now time.Time) {
	if d.pressureReaped.Load() {
		return
	}
	t := d.activeTimeout()
	if t <= 0 {
		return
	}
	nowNS := now.UnixNano()
	minRemNS := d.minRemainingNS(t)
	cur := d.readUntilNS.Load()
	if cur > nowNS+minRemNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.pressureReaped.Load() {
		return
	}
	t = d.activeTimeout()
	if t <= 0 {
		return
	}
	minRemNS = d.minRemainingNS(t)
	cur = d.readUntilNS.Load()
	if cur > nowNS+minRemNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}
	target := now.Add(t)
	_ = d.Conn.SetReadDeadline(target)
	d.readUntilNS.Store(target.UnixNano())
}

func (d *deadlineConn) armWriteDeadline(now time.Time) {
	if d.pressureReaped.Load() {
		return
	}
	t := d.activeTimeout()
	if t <= 0 {
		return
	}
	nowNS := now.UnixNano()
	hystNS := int64(t / 2)
	cur := d.writeUntilNS.Load()
	if cur > nowNS+hystNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.pressureReaped.Load() {
		return
	}
	t = d.activeTimeout()
	if t <= 0 {
		return
	}
	hystNS = int64(t / 2)
	cur = d.writeUntilNS.Load()
	if cur > nowNS+hystNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}
	target := now.Add(t)
	_ = d.Conn.SetWriteDeadline(target)
	d.writeUntilNS.Store(target.UnixNano())
}

func (d *deadlineConn) shortenReadDeadline() {
	d.draining.Store(true)
	t := d.drainTimeout
	base := d.baseIdleTimeout()
	if t <= 0 || t > base {
		t = base
	}
	if t <= 0 {
		return
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	target := time.Now().Add(t)
	cur := d.readUntilNS.Load()
	if cur == 0 || target.UnixNano() < cur {
		_ = d.Conn.SetReadDeadline(target)
		d.readUntilNS.Store(target.UnixNano())
	}
}

func (d *deadlineConn) triggerPressureReap() {
	if !d.pressureReaped.CompareAndSwap(false, true) {
		return
	}
	d.readMu.Lock()
	now := time.Now()
	_ = d.Conn.SetReadDeadline(now)
	d.readUntilNS.Store(now.UnixNano())
	d.readMu.Unlock()
}

func (d *deadlineConn) Read(p []byte) (int, error) {
	d.armReadDeadline(time.Now())
	n, err := d.Conn.Read(p)
	if n > 0 {
		if d.onReadBytes != nil {
			d.onReadBytes(n)
		}
		if d.draining.Load() {
			d.armReadDeadline(time.Now())
		}
	}
	return n, err
}

func (d *deadlineConn) Write(p []byte) (int, error) {
	d.armWriteDeadline(time.Now())
	return d.Conn.Write(p)
}

type activeRelay struct {
	localDC        *deadlineConn
	remoteDC       *deadlineConn
	lastActivityNS atomic.Int64
	downBytes      atomic.Int64
	upBytes        atomic.Int64
	pressureReaped atomic.Bool
}

func (r *activeRelay) touchAt(now time.Time) { r.lastActivityNS.Store(now.UnixNano()) }

func (r *activeRelay) idleFor(now time.Time) time.Duration {
	ns := r.lastActivityNS.Load()
	if ns == 0 {
		return 0
	}
	d := now.Sub(time.Unix(0, ns))
	if d < 0 {
		return 0
	}
	return d
}

type ProxyAtomicSnapshot struct {
	ActiveConns      int64
	PeakConns        int64
	QueuedConns      int64
	SemaphoreRejects uint64
	TotalBytesUp     uint64
	TotalBytesDown   uint64
	PressureReaps    uint64
}

type ProxyWindowStats struct {
	ActiveConns      int64
	PeakConns        int64
	QueuedConns      int64
	SemaphoreRejects uint64
	BytesUpWindow    uint64
	BytesDownWindow  uint64
	TotalBytesUp     uint64
	TotalBytesDown   uint64
	TotalConnsWindow uint64
	DialOK           uint64
	DialFail         uint64
	HalfCloseClean   uint64
	DrainTimeouts    uint64
	IdleReaps        uint64
	PressureReaps    uint64
	AbruptErrors     uint64
}

// ProxyServer terminates RFC 1928 SOCKS5 on 127.0.0.1:1080 and multiplexes streams directly
// over in-process SSH channels with v6.4's exact 64/128 shaping, oldest-idle-first two-tier
// pressure reaper (20s < 25s deadlock-free), and adaptive 16 KiB / 8 KiB PMTU=576 pools.
type ProxyServer struct {
	cfg      Config
	selector UpstreamSelector
	logger   *EventLogger
	metrics  *MetricsEmitter

	copyBufSize    int
	pmtu576BufSize int
	copyBufPool    sync.Pool
	copyBufPool8K  sync.Pool

	sem          chan struct{}
	pressureWake chan struct{}
	activeConns  atomic.Int64
	peakConns    atomic.Int64
	queuedConns  atomic.Int64
	semRejects   atomic.Uint64
	lastSatLogNS atomic.Int64
	boundPort    atomic.Uint32

	totalDrainTimeouts   atomic.Uint64
	totalAbruptErrors    atomic.Uint64
	totalPressureReaps   atomic.Uint64
	lastBytesMovedNS     atomic.Int64
	bytesUpWindow        atomic.Uint64
	bytesDownWindow      atomic.Uint64
	totalBytesUp         atomic.Uint64
	totalBytesDown       atomic.Uint64
	totalConnsWindow     atomic.Uint64
	dialOKWindow         atomic.Uint64
	dialFailWindow       atomic.Uint64
	halfCloseCleanWindow atomic.Uint64
	drainTimeoutsWindow  atomic.Uint64
	idleReapsWindow      atomic.Uint64
	pressureReapsWindow  atomic.Uint64
	abruptErrorsWindow   atomic.Uint64

	relaysMu sync.Mutex
	relays   map[*activeRelay]struct{}

	mu         sync.Mutex
	ln         net.Listener
	stopCancel context.CancelFunc
	closing    bool
	conns      map[net.Conn]struct{}
	acceptWG   sync.WaitGroup
	connWG     sync.WaitGroup
}

func NewPooledProxyServer(cfg Config, selector UpstreamSelector, logger *EventLogger, metrics *MetricsEmitter) *ProxyServer {
	bufSz := cfg.CopyBufferSize
	if bufSz < 4096 {
		bufSz = DefaultCopyBufferSize
	}
	pmtuSz := cfg.PMTU576CopyBufSize
	if pmtuSz < 4096 || pmtuSz > bufSz {
		pmtuSz = DefaultPMTU576CopyBufSize
		if pmtuSz > bufSz {
			pmtuSz = bufSz
		}
	}
	maxActive := cfg.MaxActiveConns
	if maxActive < 1 {
		maxActive = DefaultMaxActiveConns
	}
	p := &ProxyServer{
		cfg:            cfg,
		selector:       selector,
		logger:         logger,
		metrics:        metrics,
		copyBufSize:    bufSz,
		pmtu576BufSize: pmtuSz,
		sem:            make(chan struct{}, maxActive),
		pressureWake:   make(chan struct{}, 1),
		conns:          make(map[net.Conn]struct{}),
		relays:         make(map[*activeRelay]struct{}),
	}
	p.copyBufPool = sync.Pool{New: func() any { b := make([]byte, bufSz); return &b }}
	p.copyBufPool8K = sync.Pool{New: func() any { b := make([]byte, pmtuSz); return &b }}
	return p
}

func (p *ProxyServer) Start(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", p.cfg.LocalAddr())
	if err != nil {
		return "", err
	}
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		p.boundPort.Store(uint32(tcpAddr.Port))
	}
	srvCtx, stopCancel := context.WithCancel(ctx)
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		stopCancel()
		_ = ln.Close()
		return "", errors.New("proxy server already closed")
	}
	p.ln = ln
	p.stopCancel = stopCancel
	p.mu.Unlock()

	p.acceptWG.Add(2)
	safeGo(p.logger, "proxy_accept", func() { p.acceptLoop(srvCtx, ln) })
	safeGo(p.logger, "proxy_pressure_reaper", func() { p.pressureReapLoop(srvCtx) })
	return ln.Addr().String(), nil
}

func (p *ProxyServer) BoundPort() uint16 {
	return uint16(p.boundPort.Load())
}

func (p *ProxyServer) effectiveCopyBufSize(usePMTU576 bool) int {
	if usePMTU576 && p.cfg.PMTU576SafeMode {
		return p.pmtu576BufSize
	}
	return p.copyBufSize
}

func (p *ProxyServer) effectivePressureIdleTimeout() time.Duration {
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	pi := p.cfg.PressureIdleTimeout
	if pi <= 0 || pi > idle {
		return idle
	}
	return pi
}

func (p *ProxyServer) effectiveStreamingIdleTimeout() time.Duration {
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	st := p.cfg.StreamingIdleTimeout
	if st <= idle {
		return idle
	}
	if idle < DefaultIdleTimeout && st == DefaultStreamingIdleTimeout {
		return idle
	}
	return st
}

func (p *ProxyServer) effectiveStreamingPressureIdleTimeout() time.Duration {
	pi := p.effectivePressureIdleTimeout()
	stIdle := p.effectiveStreamingIdleTimeout()
	sp := p.cfg.StreamingPressureIdleTimeout
	if sp <= pi {
		return pi
	}
	if sp > stIdle {
		return stIdle
	}
	return sp
}

func (p *ProxyServer) isUnderPressure() bool {
	if p.queuedConns.Load() > 0 {
		return true
	}
	maxC := p.cfg.MaxActiveConns
	if maxC <= 0 {
		return false
	}
	threshPct := p.cfg.PressureThresholdPct
	if threshPct <= 0 || threshPct > 100 {
		threshPct = DefaultPressureThresholdPct
	}
	thresh := (maxC*threshPct + 99) / 100
	if thresh < 1 {
		thresh = 1
	}
	return p.activeConns.Load() >= int64(thresh)
}

func (p *ProxyServer) pressureReapLoop(ctx context.Context) {
	defer p.acceptWG.Done()
	pi := p.effectivePressureIdleTimeout()
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	if pi >= idle {
		<-ctx.Done()
		return
	}
	tickInterval := pi / 4
	if tickInterval < 25*time.Millisecond {
		tickInterval = 25 * time.Millisecond
	}
	if tickInterval > 500*time.Millisecond {
		tickInterval = 500 * time.Millisecond
	}
	tm := time.NewTimer(tickInterval)
	if !tm.Stop() {
		select {
		case <-tm.C:
		default:
		}
	}
	defer tm.Stop()

	for {
		if !p.isUnderPressure() {
			// Zero wakeups/hour while below 75% slot pressure and zero queued waiters.
			select {
			case <-ctx.Done():
				return
			case <-p.pressureWake:
			}
			continue
		}
		tm.Reset(tickInterval)
		select {
		case <-ctx.Done():
			if !tm.Stop() {
				select {
				case <-tm.C:
				default:
				}
			}
			return
		case <-tm.C:
			p.sweepPressureIdleRelays()
		}
	}
}

func (p *ProxyServer) wakePressureReaper() {
	select {
	case p.pressureWake <- struct{}{}:
	default:
	}
}

type relayVictim struct {
	relay *activeRelay
	idle  time.Duration
}

// sweepPressureIdleRelays enforces oldest-idle-first bounded pressure reaping (lowWater = 65%).
func (p *ProxyServer) sweepPressureIdleRelays() {
	if !p.isUnderPressure() {
		return
	}
	stalledLimit := p.effectivePressureIdleTimeout()
	streamLimit := p.effectiveStreamingPressureIdleTimeout()
	stalledMaxBytes := int64(p.cfg.StalledHandshakeMaxDownBytes)
	if stalledMaxBytes < 0 {
		stalledMaxBytes = 0
	}
	maxC := p.cfg.MaxActiveConns
	if maxC <= 0 {
		maxC = DefaultMaxActiveConns
	}
	threshPct := p.cfg.PressureThresholdPct
	if threshPct <= 0 || threshPct > 100 {
		threshPct = DefaultPressureThresholdPct
	}
	thresh := int64((maxC*threshPct + 99) / 100)
	if thresh < 1 {
		thresh = 1
	}
	lowPct := threshPct - 10
	if lowPct < 0 {
		lowPct = 0
	}
	lowWater := int64((maxC * lowPct) / 100)
	if lowWater >= thresh && thresh > 0 {
		lowWater = thresh - 1
	}
	now := time.Now()

	p.relaysMu.Lock()
	active := p.activeConns.Load()
	queued := p.queuedConns.Load()
	var inFlightReaping int64
	var stalledVictims []relayVictim
	var streamVictims []relayVictim
	for r := range p.relays {
		if r.pressureReaped.Load() {
			inFlightReaping++
			continue
		}
		idle := r.idleFor(now)
		if r.downBytes.Load() <= stalledMaxBytes {
			if idle >= stalledLimit {
				stalledVictims = append(stalledVictims, relayVictim{relay: r, idle: idle})
			}
		} else {
			if idle >= streamLimit {
				streamVictims = append(streamVictims, relayVictim{relay: r, idle: idle})
			}
		}
	}
	p.relaysMu.Unlock()

	if len(stalledVictims) > 1 {
		sort.Slice(stalledVictims, func(i, j int) bool { return stalledVictims[i].idle > stalledVictims[j].idle })
	}
	var reaped int64
	for _, v := range stalledVictims {
		if v.relay.pressureReaped.CompareAndSwap(false, true) {
			v.relay.localDC.triggerPressureReap()
			v.relay.remoteDC.triggerPressureReap()
			reaped++
		}
	}

	need := (active + queued - inFlightReaping) - lowWater
	streamBudget := need - reaped
	if streamBudget <= 0 || len(streamVictims) == 0 {
		return
	}
	if len(streamVictims) > 1 {
		sort.Slice(streamVictims, func(i, j int) bool { return streamVictims[i].idle > streamVictims[j].idle })
	}
	var reapedStreams int64
	for _, v := range streamVictims {
		if reapedStreams >= streamBudget {
			break
		}
		if v.relay.pressureReaped.CompareAndSwap(false, true) {
			v.relay.localDC.triggerPressureReap()
			v.relay.remoteDC.triggerPressureReap()
			reapedStreams++
		}
	}
}

func (p *ProxyServer) AtomicTelemetry() ProxyAtomicSnapshot {
	if p == nil {
		return ProxyAtomicSnapshot{}
	}
	return ProxyAtomicSnapshot{
		ActiveConns:      p.activeConns.Load(),
		PeakConns:        p.peakConns.Load(),
		QueuedConns:      p.queuedConns.Load(),
		SemaphoreRejects: p.semRejects.Load(),
		TotalBytesUp:     p.totalBytesUp.Load(),
		TotalBytesDown:   p.totalBytesDown.Load(),
		PressureReaps:    p.totalPressureReaps.Load(),
	}
}

func (p *ProxyServer) TotalBytes() (uint64, uint64) {
	return p.totalBytesUp.Load(), p.totalBytesDown.Load()
}

func (p *ProxyServer) SnapshotWindow(reset bool) ProxyWindowStats {
	active := p.activeConns.Load()
	var peak int64
	if reset {
		peak = p.peakConns.Swap(active)
		if active > peak {
			peak = active
		}
	} else {
		peak = p.peakConns.Load()
	}
	var bytesUp, bytesDown, totalConns, dialOK, dialFail, hc, drainTO, idleR, pressR, abrupt uint64
	if reset {
		bytesUp = p.bytesUpWindow.Swap(0)
		bytesDown = p.bytesDownWindow.Swap(0)
		totalConns = p.totalConnsWindow.Swap(0)
		dialOK = p.dialOKWindow.Swap(0)
		dialFail = p.dialFailWindow.Swap(0)
		hc = p.halfCloseCleanWindow.Swap(0)
		drainTO = p.drainTimeoutsWindow.Swap(0)
		idleR = p.idleReapsWindow.Swap(0)
		pressR = p.pressureReapsWindow.Swap(0)
		abrupt = p.abruptErrorsWindow.Swap(0)
	} else {
		bytesUp = p.bytesUpWindow.Load()
		bytesDown = p.bytesDownWindow.Load()
		totalConns = p.totalConnsWindow.Load()
		dialOK = p.dialOKWindow.Load()
		dialFail = p.dialFailWindow.Load()
		hc = p.halfCloseCleanWindow.Load()
		drainTO = p.drainTimeoutsWindow.Load()
		idleR = p.idleReapsWindow.Load()
		pressR = p.pressureReapsWindow.Load()
		abrupt = p.abruptErrorsWindow.Load()
	}
	return ProxyWindowStats{
		ActiveConns:      active,
		PeakConns:        peak,
		QueuedConns:      p.queuedConns.Load(),
		SemaphoreRejects: p.semRejects.Load(),
		BytesUpWindow:    bytesUp,
		BytesDownWindow:  bytesDown,
		TotalBytesUp:     p.totalBytesUp.Load(),
		TotalBytesDown:   p.totalBytesDown.Load(),
		TotalConnsWindow: totalConns,
		DialOK:           dialOK,
		DialFail:         dialFail,
		HalfCloseClean:   hc,
		DrainTimeouts:    drainTO,
		IdleReaps:        idleR,
		PressureReaps:    pressR,
		AbruptErrors:     abrupt,
	}
}

func (p *ProxyServer) Stop(forceCloseActive bool) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		p.acceptWG.Wait()
		p.connWG.Wait()
		return
	}
	p.closing = true
	ln := p.ln
	p.ln = nil
	stopCancel := p.stopCancel
	p.stopCancel = nil
	var toClose []net.Conn
	if forceCloseActive {
		toClose = make([]net.Conn, 0, len(p.conns))
		for c := range p.conns {
			toClose = append(toClose, c)
		}
	}
	p.mu.Unlock()

	if forceCloseActive && stopCancel != nil {
		stopCancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	if !forceCloseActive && stopCancel != nil {
		stopCancel()
	}
	p.acceptWG.Wait()

	if forceCloseActive {
		for _, c := range toClose {
			_ = c.Close()
		}
		p.mu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
	}
	p.connWG.Wait()
}

func (p *ProxyServer) acceptLoop(ctx context.Context, ln net.Listener) {
	defer p.acceptWG.Done()
	backoff := acceptBackoffMin
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			isClosing := p.closing
			p.mu.Unlock()
			if isClosing || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > acceptBackoffMax {
				backoff = acceptBackoffMax
			}
			continue
		}
		backoff = acceptBackoffMin

		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		p.connWG.Add(1)
		p.mu.Unlock()
		safeGo(p.logger, "proxy_client", func() { p.handleClient(ctx, conn) })
	}
}

func (p *ProxyServer) trackConn(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *ProxyServer) untrackConn(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *ProxyServer) acquireSemaphore(ctx context.Context) (bool, time.Duration, string) {
	select {
	case p.sem <- struct{}{}:
		return true, 0, ""
	default:
	}
	wait := p.cfg.SemaphoreWaitTimeout
	if wait <= 0 {
		return false, 0, "queue_disabled"
	}
	if maxQ := p.cfg.MaxQueuedConns; maxQ > 0 {
		if p.queuedConns.Add(1) > int64(maxQ) {
			p.queuedConns.Add(-1)
			return false, 0, "queue_full"
		}
	} else {
		p.queuedConns.Add(1)
	}
	defer p.queuedConns.Add(-1)

	p.wakePressureReaper()
	p.sweepPressureIdleRelays()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	queuedAt := time.Now()
	select {
	case p.sem <- struct{}{}:
		return true, time.Since(queuedAt), ""
	case <-timer.C:
		return false, time.Since(queuedAt), "queue_timeout"
	case <-ctx.Done():
		return false, time.Since(queuedAt), "shutdown"
	}
}

func (p *ProxyServer) recordActiveDelta(delta int64) {
	cur := p.activeConns.Add(delta)
	if delta > 0 {
		for {
			prev := p.peakConns.Load()
			if cur <= prev || p.peakConns.CompareAndSwap(prev, cur) {
				break
			}
		}
		if p.isUnderPressure() {
			p.wakePressureReaper()
		}
	}
}

func (p *ProxyServer) tuneLocalTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	ka := p.cfg.TCPKeepAlivePeriod
	if ka <= 0 {
		ka = DefaultTCPKeepAlivePeriod
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(ka)
}

func (p *ProxyServer) handleClient(ctx context.Context, localConn net.Conn) {
	defer p.connWG.Done()
	defer localConn.Close()

	acquired, queueWait, rejectReason := p.acquireSemaphore(ctx)
	if !acquired {
		if ctx.Err() == nil {
			p.semRejects.Add(1)
			if p.metrics != nil {
				p.metrics.EmitConn(ConnMetric{
					QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
					CloseReason:     rejectReason,
					CopyBufferBytes: p.copyBufSize,
				})
			}
		}
		return
	}
	defer func() { <-p.sem }()

	p.totalConnsWindow.Add(1)
	p.recordActiveDelta(1)
	defer p.recordActiveDelta(-1)

	if !p.trackConn(localConn) {
		return
	}
	defer p.untrackConn(localConn)
	p.tuneLocalTCPConn(localConn)

	// Terminate RFC 1928 SOCKS5 handshake locally (UDP->0x07, self-loop->0x02, preserves domain).
	req, hsErr := PerformSOCKS5ServerHandshake(localConn, p.BoundPort(), p.cfg.SOCKS5HandshakeTimeout)
	if hsErr != nil {
		return
	}
	targetAddr := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))

	if p.selector == nil {
		writeSOCKS5Reply(localConn, socks5RepGeneralFailure)
		return
	}
	lease, leaseErr := p.selector.AcquireEndpoint(ctx)
	if leaseErr != nil {
		p.dialFailWindow.Add(1)
		writeSOCKS5Reply(localConn, socks5RepNetUnreachable)
		if p.metrics != nil {
			p.metrics.EmitConn(ConnMetric{
				TargetAddr:      targetAddr,
				QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
				CloseReason:     "no_healthy_tunnel",
				CopyBufferBytes: p.copyBufSize,
			})
		}
		return
	}
	defer lease.Release()

	effBufSz := p.effectiveCopyBufSize(lease.PMTU576Safe)
	dialStart := time.Now()
	dialCtx, cancelDial := context.WithTimeout(ctx, p.cfg.DialTimeout)
	remoteConn, err := lease.DialTarget(dialCtx, req.Host, req.Port)
	cancelDial()
	dialDur := time.Since(dialStart)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		p.dialFailWindow.Add(1)
		p.selector.NotifyDialFailure(lease.TunnelID, err)
		writeSOCKS5Reply(localConn, mapDialErrorToSOCKS5Rep(err))
		if p.metrics != nil {
			p.metrics.EmitConn(ConnMetric{
				TunnelID:        lease.TunnelID,
				TargetAddr:      targetAddr,
				QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
				DialRTTMS:       float64(dialDur.Microseconds()) / 1000.0,
				CloseReason:     "dial_fail",
				CopyBufferBytes: effBufSz,
			})
		}
		return
	}
	p.dialOKWindow.Add(1)
	p.selector.NotifyDialSuccess(lease.TunnelID, dialDur)
	defer remoteConn.Close()

	if !p.trackConn(remoteConn) {
		return
	}
	defer p.untrackConn(remoteConn)

	writeSOCKS5Reply(localConn, socks5RepSucceeded)

	activeStart := time.Now()
	bytesUp, bytesDown, closeReason, pressureReaped := p.relayBidirectional(localConn, remoteConn, lease.TunnelID, lease.PMTU576Safe)
	if p.metrics != nil {
		p.metrics.EmitConn(ConnMetric{
			TunnelID:        lease.TunnelID,
			TargetAddr:      targetAddr,
			QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
			DialRTTMS:       float64(dialDur.Microseconds()) / 1000.0,
			ActiveMS:        float64(time.Since(activeStart).Microseconds()) / 1000.0,
			BytesUp:         bytesUp,
			BytesDown:       bytesDown,
			CloseReason:     closeReason,
			PressureReaped:  pressureReaped,
			CopyBufferBytes: effBufSz,
		})
	}
}

func (p *ProxyServer) relayBidirectional(localConn, remoteConn net.Conn, tunnelID string, usePMTU576 bool) (uint64, uint64, string, bool) {
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	streamIdle := p.effectiveStreamingIdleTimeout()
	drain := p.cfg.HalfCloseDrainTimeout
	if drain <= 0 || drain > idle {
		drain = idle
	}
	stalledMaxBytes := int64(p.cfg.StalledHandshakeMaxDownBytes)
	if stalledMaxBytes < 0 {
		stalledMaxBytes = 0
	}

	var connUpBytes atomic.Uint64
	var connDownBytes atomic.Int64
	relay := &activeRelay{}
	relay.touchAt(time.Now())

	var (
		wg              sync.WaitGroup
		upClean         atomic.Bool
		downClean       atomic.Bool
		recordedOutcome atomic.Bool
		closeReasonMu   sync.Mutex
		closeReason     = "half_close_clean"
	)

	var localDC, remoteDC *deadlineConn
	localDC = &deadlineConn{
		Conn:              localConn,
		idleTimeout:       idle,
		streamIdleTimeout: streamIdle,
		drainTimeout:      drain,
		onReadBytes: func(n int) {
			now := time.Now()
			relay.touchAt(now)
			relay.upBytes.Add(int64(n))
			connUpBytes.Add(uint64(n))
			p.bytesUpWindow.Add(uint64(n))
			p.totalBytesUp.Add(uint64(n))
			if !downClean.Load() {
				remoteDC.refreshReadDeadline(now)
			}
		},
	}
	remoteDC = &deadlineConn{
		Conn:              remoteConn,
		idleTimeout:       idle,
		streamIdleTimeout: streamIdle,
		drainTimeout:      drain,
		onReadBytes: func(n int) {
			now := time.Now()
			relay.touchAt(now)
			totDown := connDownBytes.Add(int64(n))
			relay.downBytes.Store(totDown)
			p.bytesDownWindow.Add(uint64(n))
			p.totalBytesDown.Add(uint64(n))
			if totDown > stalledMaxBytes {
				localDC.promoteToStreaming()
				remoteDC.promoteToStreaming()
			}
			if !upClean.Load() {
				localDC.refreshReadDeadline(now)
			}
			if totDown >= wanVerifiedMinDownBytes {
				p.lastBytesMovedNS.Store(now.UnixNano())
				if p.selector != nil {
					p.selector.NotifyWANBytes(tunnelID, uint64(n))
				}
			}
		},
	}
	relay.localDC = localDC
	relay.remoteDC = remoteDC

	p.relaysMu.Lock()
	p.relays[relay] = struct{}{}
	p.relaysMu.Unlock()
	defer func() {
		p.relaysMu.Lock()
		delete(p.relays, relay)
		p.relaysMu.Unlock()
	}()

	classifyErr := func(dc *deadlineConn, err error) {
		if !recordedOutcome.CompareAndSwap(false, true) {
			return
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if relay.pressureReaped.Load() || dc.pressureReaped.Load() {
				p.pressureReapsWindow.Add(1)
				p.totalPressureReaps.Add(1)
				closeReasonMu.Lock()
				closeReason = "pressure_idle_reap"
				closeReasonMu.Unlock()
				return
			}
			if dc.draining.Load() {
				p.drainTimeoutsWindow.Add(1)
				p.totalDrainTimeouts.Add(1)
				closeReasonMu.Lock()
				closeReason = "drain_timeout"
				closeReasonMu.Unlock()
			} else {
				p.idleReapsWindow.Add(1)
				closeReasonMu.Lock()
				closeReason = "idle_reap"
				closeReasonMu.Unlock()
			}
			return
		}
		p.abruptErrorsWindow.Add(1)
		p.totalAbruptErrors.Add(1)
		closeReasonMu.Lock()
		closeReason = "abrupt_error"
		closeReasonMu.Unlock()
	}

	bufPool := &p.copyBufPool
	if usePMTU576 && p.cfg.PMTU576SafeMode {
		bufPool = &p.copyBufPool8K
	}

	wg.Add(2)
	safeGo(p.logger, "relay_up", func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		_, err := io.CopyBuffer(remoteDC, localDC, *bufPtr)
		if err == nil {
			upClean.Store(true)
			if cw, ok := remoteConn.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			remoteDC.shortenReadDeadline()
		} else {
			classifyErr(localDC, err)
			_ = localConn.Close()
			_ = remoteConn.Close()
		}
	})
	safeGo(p.logger, "relay_down", func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		_, err := io.CopyBuffer(localDC, remoteDC, *bufPtr)
		if err == nil {
			downClean.Store(true)
			if cw, ok := localConn.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			localDC.shortenReadDeadline()
		} else {
			classifyErr(remoteDC, err)
			_ = remoteConn.Close()
			_ = localConn.Close()
		}
	})
	wg.Wait()

	if upClean.Load() && downClean.Load() {
		p.halfCloseCleanWindow.Add(1)
	}
	down := connDownBytes.Load()
	if down < 0 {
		down = 0
	}
	closeReasonMu.Lock()
	cr := closeReason
	closeReasonMu.Unlock()
	return connUpBytes.Load(), uint64(down), cr, relay.pressureReaped.Load()
}
