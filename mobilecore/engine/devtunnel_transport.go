package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
)

const (
	devTunnelsAPIVersion      = "2023-09-27-preview"
	codespaceRPCPort          = uint32(16634)
	startSSHServerGRPCPath    = "/Codespaces.Grpc.SshServerHostService.v1.SshServerHost/StartRemoteServerAsync"
	devTunnelWSProtoV1        = "tunnel-relay-client"
	devTunnelWSProtoV2        = "tunnel-relay-client-v2"
	devTunnelWSProtoV2Dev     = "tunnel-relay-client-v2-dev"
	devTunnelV2StreamChanType = "client-ssh-session-stream"
)

// WorkerSession represents one live multiplexed in-process SSH tunnel session.
type WorkerSession interface {
	DialTarget(ctx context.Context, host string, port uint16) (net.Conn, error)
	SendKeepalive(ctx context.Context) error
	WANRemote() string
	PMTU576Active() bool
	Done() <-chan error
	Close() error
}

// WorkerTransport establishes independent WAN 5-tuple WorkerSessions for TunnelPool workers.
type WorkerTransport interface {
	Connect(ctx context.Context, workerID string) (WorkerSession, error)
}

// HeartbeatCoordinator phase-locks keepalive ticks across PoolSize=2 workers into a single
// radio wake window to halve LTE/5G RRC state transitions while keeping CG-NAT mappings alive.
type HeartbeatCoordinator struct {
	interval time.Duration
	mu       sync.Mutex
	subs     map[chan struct{}]struct{}
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewHeartbeatCoordinator(interval time.Duration) *HeartbeatCoordinator {
	if interval <= 0 {
		interval = time.Duration(DefaultSSHAliveInterval) * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	hc := &HeartbeatCoordinator{
		interval: interval,
		subs:     make(map[chan struct{}]struct{}),
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	safeGo(nil, "heartbeat_coordinator", func() {
		defer close(hc.done)
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				hc.Broadcast()
			}
		}
	})
	return hc
}

func (h *HeartbeatCoordinator) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (h *HeartbeatCoordinator) Broadcast() {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

func (h *HeartbeatCoordinator) Close() {
	if h == nil {
		return
	}
	h.cancel()
	<-h.done
}

// DevTunnelSSHTransport implements the complete pure-Go Codespaces Dev Tunnels wire stack:
//  1. Singleflight CredentialManager -> GitHub Codespaces API (TunnelProperties JWT)
//  2. Dev Tunnels REST API GET /tunnels/{id}?includePorts=true&api-version=... -> clientRelayUri + hostPublicKeys
//  3. Dual-stack AntiPoisonResolver TCP + TLS + WebSocket (`tunnel-relay-client` v1 for production, plus v2 for loopback tests)
//     with <= 8 KiB chunked binary framing when PMTU=576 VIP (20.120.56.11 / NAT64) is detected
//  4. Outer Dev Tunnels SSH (ssh.NewClientConn directly, accepting host `tcpip-forward` requests)
//  5. Zero-grpc h2c HTTP/2 unary protobuf RPC on port 16634 (`StartRemoteServerAsync`) with ephemeral Ed25519 keypair
//  6. Ensure <sshdPort> registered via PUT /tunnels/{id}/ports/{port} + `RefreshPorts` when needed
//  7. Inner `x/crypto/ssh` session with arch-optimal ciphers, `direct-tcpip` remote DNS, and keepalive watchdog.
type DevTunnelSSHTransport struct {
	cfg          Config
	creds        *CredentialManager
	resolver     *AntiPoisonResolver
	hb           *HeartbeatCoordinator
	logger       *EventLogger
	directClient *http.Client

	zombieMu       sync.Mutex
	zombieGen      uint64
	zombieRPCCount int
}

func NewDevTunnelSSHTransport(cfg Config, creds *CredentialManager, resolver *AntiPoisonResolver, hb *HeartbeatCoordinator, logger *EventLogger) *DevTunnelSSHTransport {
	if resolver == nil {
		resolver = NewAntiPoisonResolver(nil, nil)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return resolver.DialContext(ctx, network, addr, 10*time.Second, cfg.TCPKeepAlivePeriod, cfg.TCPUserTimeout)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &DevTunnelSSHTransport{
		cfg:          cfg,
		creds:        creds,
		resolver:     resolver,
		hb:           hb,
		logger:       logger,
		directClient: &http.Client{Transport: tr, Timeout: 25 * time.Second},
	}
}

func (t *DevTunnelSSHTransport) CloseIdleConnections() {
	if t == nil || t.directClient == nil {
		return
	}
	if tr, ok := t.directClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func (t *DevTunnelSSHTransport) recordStageRPCFailure(gen uint64) int {
	t.zombieMu.Lock()
	if t.zombieGen != gen {
		t.zombieGen = gen
		t.zombieRPCCount = 0
	}
	t.zombieRPCCount++
	cnt := t.zombieRPCCount
	t.zombieMu.Unlock()
	return cnt
}

func (t *DevTunnelSSHTransport) resetStageRPCFailure(gen uint64) {
	t.zombieMu.Lock()
	if t.zombieGen == gen {
		t.zombieRPCCount = 0
	}
	t.zombieMu.Unlock()
}

func isStaleDevTunnelHTTPStatus(status int) bool {
	return status == http.StatusUnauthorized ||
		status == http.StatusForbidden ||
		status == http.StatusNotFound ||
		status == http.StatusGone
}

func isDeadVMStartServerError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "StartRemoteServerAsync rejected:")
}

func isZombieRPCDeadlineError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	low := strings.ToLower(err.Error())
	for _, tok := range []string{
		"grpc status 4",
		"deadline exceeded",
		"context deadline exceeded",
		"client.timeout",
		"rpc http 5",
		"eof",
		"connect failed",
		"unknown channel type",
		"prohibited",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func extractRelayEndpoint(doc devTunnelRESTDoc) (relayURI, epMode string, hostPubKeys []string) {
	for _, ep := range doc.Endpoints {
		if strings.EqualFold(ep.ConnectionMode, "TunnelRelay") && ep.ClientRelayURI != "" {
			return ep.ClientRelayURI, ep.ConnectionMode, ep.HostPublicKeys
		}
	}
	if len(doc.Endpoints) > 0 {
		return doc.Endpoints[0].ClientRelayURI, doc.Endpoints[0].ConnectionMode, doc.Endpoints[0].HostPublicKeys
	}
	return "", "", nil
}

func (t *DevTunnelSSHTransport) logStage(workerID, stage, detail string) {
	if t == nil || t.logger == nil {
		return
	}
	t.logger.Log("WORKER_BOOT_STAGE", map[string]any{
		"tunnel_id": workerID,
		"stage":     stage,
		"detail":    RedactSecrets(detail),
	})
}

type devTunnelRESTDoc struct {
	TunnelID  string `json:"tunnelId"`
	ClusterID string `json:"clusterId"`
	Endpoints []struct {
		ID             string   `json:"id"`
		ConnectionMode string   `json:"connectionMode"`
		ClientRelayURI string   `json:"clientRelayUri"`
		HostPublicKeys []string `json:"hostPublicKeys"`
	} `json:"endpoints"`
	Ports []struct {
		PortNumber uint16 `json:"portNumber"`
		Protocol   string `json:"protocol"`
	} `json:"ports"`
}

// normalizeDevTunnelsAPIBase normalizes ServiceURI per microsoft/dev-tunnels `Manager.buildUri`:
// canonical service routes live at `/tunnels/{id}` (NOT `/api/v1/tunnels/{id}` which returns HTTP 405
// with api-version=2023-09-27-preview), and `global.*` hosts route to `<clusterId>.*` when known.
func normalizeDevTunnelsAPIBase(serviceURI, clusterID string) string {
	s := strings.TrimRight(strings.TrimSpace(serviceURI), "/")
	s = strings.TrimSuffix(s, "/api/v1")
	s = strings.TrimRight(s, "/")
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return s
	}
	clusterID = strings.TrimSpace(clusterID)
	hostname := u.Hostname()
	port := u.Port()
	if clusterID != "" &&
		hostname != "localhost" &&
		hostname != "127.0.0.1" &&
		hostname != "::1" &&
		hostname != "tunnels.local.api.visualstudio.com" &&
		!strings.HasPrefix(strings.ToLower(hostname), strings.ToLower(clusterID)+".") {
		newHost := clusterID + "." + hostname
		newHost = strings.Replace(newHost, "global.", "", 1)
		if port != "" {
			u.Host = net.JoinHostPort(newHost, port)
		} else {
			u.Host = newHost
		}
	}
	cleanPath := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	u.Path = strings.TrimRight(cleanPath, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func isLoopbackRelayURI(rawURI string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return strings.EqualFold(u.Scheme, "ws") && (h == "127.0.0.1" || h == "localhost" || h == "::1")
}

func safeURIHost(rawURI string) string {
	u, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host
}

func (t *DevTunnelSSHTransport) newDirectHTTPClient() *http.Client {
	if t.directClient != nil {
		return t.directClient
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.resolver.DialContext(ctx, network, addr, 10*time.Second, t.cfg.TCPKeepAlivePeriod, t.cfg.TCPUserTimeout)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}
}

func (t *DevTunnelSSHTransport) fetchDevTunnel(ctx context.Context, props TunnelProperties) (devTunnelRESTDoc, int, error) {
	if strings.TrimSpace(props.ServiceURI) == "" {
		return devTunnelRESTDoc{}, 0, errors.New("devtunnels serviceUri is empty")
	}
	base := normalizeDevTunnelsAPIBase(props.ServiceURI, props.ClusterID)
	u := fmt.Sprintf("%s/tunnels/%s?includePorts=true&api-version=%s", base, url.PathEscape(props.TunnelID), devTunnelsAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return devTunnelRESTDoc{}, 0, err
	}
	req.Header.Set("Authorization", "tunnel "+props.ConnectAccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NetShaper-Mobile/7.0")

	hc := t.newDirectHTTPClient()
	resp, err := hc.Do(req)
	if err != nil {
		return devTunnelRESTDoc{}, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return devTunnelRESTDoc{}, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return devTunnelRESTDoc{}, resp.StatusCode, fmt.Errorf("devtunnels GET %s HTTP %d: %s", safeURIHost(base), resp.StatusCode, RedactSecrets(string(raw)))
	}
	var doc devTunnelRESTDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return devTunnelRESTDoc{}, resp.StatusCode, fmt.Errorf("devtunnels decode: %w", err)
	}
	return doc, resp.StatusCode, nil
}

func (t *DevTunnelSSHTransport) ensureDevTunnelPort(ctx context.Context, props TunnelProperties, clusterFallback string, port uint16) (int, error) {
	tok := props.ManagePortsAccessToken
	if tok == "" {
		tok = props.ConnectAccessToken
	}
	cluster := props.ClusterID
	if cluster == "" {
		cluster = clusterFallback
	}
	base := normalizeDevTunnelsAPIBase(props.ServiceURI, cluster)
	u := fmt.Sprintf("%s/tunnels/%s/ports/%d?api-version=%s", base, url.PathEscape(props.TunnelID), port, devTunnelsAPIVersion)
	payload, err := json.Marshal(struct {
		PortNumber uint16   `json:"portNumber"`
		Protocol   string   `json:"protocol"`
		Labels     []string `json:"labels,omitempty"`
	}{
		PortNumber: port,
		Protocol:   "http",
		Labels:     []string{"InternalPort"},
	})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "tunnel "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-None-Match", "*")
	req.Header.Set("User-Agent", "NetShaper-Mobile/7.0")

	hc := t.newDirectHTTPClient()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) ||
		resp.StatusCode == http.StatusConflict ||
		resp.StatusCode == http.StatusPreconditionFailed {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, fmt.Errorf("devtunnels PUT port %d HTTP %d: %s", port, resp.StatusCode, RedactSecrets(strings.TrimSpace(string(body))))
}

func preferredInnerSSHCiphers() []string {
	if runtime.GOARCH == "arm" {
		// 32-bit ARMv7 lacks hardware AES-NI; ChaCha20-Poly1305 is 3-4x faster and cooler.
		return []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-gcm@openssh.com",
		}
	}
	// ARM64 (ARMv8 Crypto Extensions) & AMD64 prefer hardware-accelerated AES-128-GCM.
	return []string{
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
	}
}

func buildOuterHostKeyCallback(hostKeys []string) (ssh.HostKeyCallback, int) {
	var parsed []ssh.PublicKey
	for _, raw := range hostKeys {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw)); err == nil {
			parsed = append(parsed, pk)
			continue
		}
		// Upstream Microsoft Dev Tunnels encodes `hostPublicKeys` as raw Base64 of SSH wire key bytes.
		matchedB64 := false
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if wire, derr := enc.DecodeString(raw); derr == nil && len(wire) > 0 {
				if pk, err := ssh.ParsePublicKey(wire); err == nil {
					parsed = append(parsed, pk)
					matchedB64 = true
					break
				}
			}
		}
		if matchedB64 {
			continue
		}
		if pk, err := ssh.ParsePublicKey([]byte(raw)); err == nil {
			parsed = append(parsed, pk)
		}
	}
	if len(parsed) == 0 {
		return ssh.InsecureIgnoreHostKey(), 0
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := key.Marshal()
		for _, pk := range parsed {
			if bytes.Equal(got, pk.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("outer devtunnel host key mismatch (type=%s)", key.Type())
	}, len(parsed)
}

// Connect establishes a brand-new independent outer WAN TCP + TLS + WSS + Outer SSH + Inner SSH session.
func (t *DevTunnelSSHTransport) Connect(ctx context.Context, workerID string) (WorkerSession, error) {
	t.logStage(workerID, "1/7", "resolving codespace DevTunnels JWT")
	props, credGen, err := t.creds.GetWithGen(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("[1/7 codespace creds] %w", err)
	}
	t.logStage(workerID, "1/7", fmt.Sprintf("tunnel_id=%s cluster=%s", props.TunnelID, props.ClusterID))

	t.logStage(workerID, "2/7", fmt.Sprintf("GET %s/tunnels", safeURIHost(normalizeDevTunnelsAPIBase(props.ServiceURI, props.ClusterID))))
	doc, status, err := t.fetchDevTunnel(ctx, props)
	var relayURI, epMode string
	var hostPubKeys []string
	if err == nil {
		relayURI, epMode, hostPubKeys = extractRelayEndpoint(doc)
	}
	staleReason := ""
	if ctx.Err() == nil {
		if err != nil && isStaleDevTunnelHTTPStatus(status) {
			staleReason = fmt.Sprintf("http_%d", status)
		} else if err == nil && relayURI == "" {
			staleReason = "empty_endpoints"
		}
	}
	if staleReason != "" {
		staleID := props.TunnelID
		invalidated, coolRem := t.creds.InvalidateIfMatch(credGen, staleReason)
		if invalidated {
			if err != nil {
				t.logStage(workerID, "2/7", fmt.Sprintf("HTTP %d (stale tunnel_id=%s) — refreshing Codespace & DevTunnels JWT", status, staleID))
			} else {
				t.logStage(workerID, "2/7", fmt.Sprintf("empty relay endpoints (stale tunnel_id=%s) — refreshing Codespace & DevTunnels JWT", staleID))
			}
			props, credGen, err = t.creds.GetWithGen(ctx, true)
			if err != nil {
				return nil, fmt.Errorf("[2/7 devtunnel jwt refresh] %w", err)
			}
			t.logStage(workerID, "2/7", fmt.Sprintf("GET %s/tunnels", safeURIHost(normalizeDevTunnelsAPIBase(props.ServiceURI, props.ClusterID))))
			doc, _, err = t.fetchDevTunnel(ctx, props)
			if err == nil {
				relayURI, epMode, hostPubKeys = extractRelayEndpoint(doc)
			}
		} else if coolRem == 0 {
			t.logStage(workerID, "2/7", fmt.Sprintf("stale tunnel_id=%s superseded by newer credential gen — retrying with fresh creds", staleID))
			props, credGen, err = t.creds.GetWithGen(ctx, false)
			if err != nil {
				return nil, fmt.Errorf("[2/7 devtunnel jwt refresh] %w", err)
			}
			doc, _, err = t.fetchDevTunnel(ctx, props)
			if err == nil {
				relayURI, epMode, hostPubKeys = extractRelayEndpoint(doc)
			}
		} else {
			t.logStage(workerID, "2/7", fmt.Sprintf("stale tunnel_id=%s refresh throttled for %s (WAF guard)", staleID, coolRem.Round(time.Millisecond)))
			if err == nil {
				return nil, errors.New("[2/7 devtunnel GET] endpoint missing clientRelayUri (refresh throttled)")
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("[2/7 devtunnel GET] %w", err)
	}
	if relayURI == "" {
		return nil, errors.New("[2/7 devtunnel GET] endpoint missing clientRelayUri")
	}
	if len(hostPubKeys) == 0 {
		hostPubKeys = props.HostPublicKeys
	}
	t.logStage(workerID, "2/7", fmt.Sprintf("mode=%s endpoints=%d ports=%d relay=%s", epMode, len(doc.Endpoints), len(doc.Ports), safeURIHost(relayURI)))

	// 1. Dial WebSocket Relay via custom dual-stack AntiPoisonResolver capturing exact WAN remote IP.
	var wanRemoteAtomic atomic.Value
	wsHTTP := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				conn, derr := t.resolver.DialContext(dctx, network, addr, 12*time.Second, t.cfg.TCPKeepAlivePeriod, t.cfg.TCPUserTimeout)
				if derr == nil && conn != nil && conn.RemoteAddr() != nil {
					wanRemoteAtomic.Store(conn.RemoteAddr().String())
				}
				return conn, derr
			},
			TLSHandshakeTimeout: 12 * time.Second,
			DisableKeepAlives:   true,
		},
	}

	hdr := http.Header{}
	hdr.Set("Authorization", "tunnel "+props.ConnectAccessToken)
	hdr.Set("User-Agent", "NetShaper-Mobile/7.0")

	subprotocols := []string{devTunnelWSProtoV1}
	if isLoopbackRelayURI(relayURI) {
		subprotocols = []string{devTunnelWSProtoV1, devTunnelWSProtoV2}
	}
	wsConn, wsResp, err := websocket.Dial(ctx, relayURI, &websocket.DialOptions{
		HTTPClient:   wsHTTP,
		HTTPHeader:   hdr,
		Subprotocols: subprotocols,
	})
	if err != nil {
		if ctx.Err() != nil {
			t.CloseIdleConnections()
			return nil, fmt.Errorf("[3/7 wss dial] %w", err)
		}
		if wsResp != nil && isStaleDevTunnelHTTPStatus(wsResp.StatusCode) {
			t.creds.InvalidateIfMatch(credGen, fmt.Sprintf("wss_http_%d", wsResp.StatusCode))
		}
		httpCode := 0
		if wsResp != nil {
			httpCode = wsResp.StatusCode
		}
		return nil, fmt.Errorf("[3/7 wss dial http=%d] %w", httpCode, err)
	}
	wsConn.SetReadLimit(-1) // Disable 32 KiB default read limit so full SSH packets never drop.

	wanRemote, _ := wanRemoteAtomic.Load().(string)
	pmtu576 := t.cfg.PMTU576SafeMode && IsPMTU576RelayIP(wanRemote)
	maxChunk := t.cfg.CopyBufferSize
	if pmtu576 && t.cfg.PMTU576CopyBufSize > 0 {
		maxChunk = t.cfg.PMTU576CopyBufSize
	}
	t.logStage(workerID, "3/7", fmt.Sprintf("wss connected subproto=%s wan=%s pmtu576=%v", wsConn.Subprotocol(), wanRemote, pmtu576))

	// Long-lived session context (decoupled from short boot ctx once Connect succeeds!).
	// During boot, bind ctx cancellation directly to wsNetConn.Close() so SSH/RefreshPorts stalls abort in <50ms.
	sessCtx, sessCancel := context.WithCancel(context.Background())
	wsNetConn := &wsBinaryConn{
		Conn:     websocket.NetConn(sessCtx, wsConn, websocket.MessageBinary),
		maxChunk: maxChunk,
	}
	stopBootWatch := context.AfterFunc(ctx, func() {
		_ = wsNetConn.Close()
		sessCancel()
	})
	defer func() { _ = stopBootWatch() }()

	cleanupOnErr := func(closers ...io.Closer) {
		_ = stopBootWatch()
		sessCancel()
		for _, cl := range closers {
			if cl != nil {
				_ = cl.Close()
			}
		}
	}

	// 2. Support v1 (direct Host SSH) in production AND v2 on loopback test relays.
	var hostTransport net.Conn = wsNetConn
	var relaySSHConn ssh.Conn
	subproto := wsConn.Subprotocol()
	if strings.HasPrefix(subproto, devTunnelWSProtoV2) && isLoopbackRelayURI(relayURI) {
		rConn, rChans, rReqs, rErr := ssh.NewClientConn(wsNetConn, relayURI, &ssh.ClientConfig{
			User:            "tunnel",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		})
		if rErr != nil {
			cleanupOnErr(wsNetConn)
			return nil, fmt.Errorf("[3/7 v2 relay ssh] %w", rErr)
		}
		relaySSHConn = rConn
		safeGo(t.logger, workerID+"_v2_reqs", func() { ssh.DiscardRequests(rReqs) })
		safeGo(t.logger, workerID+"_v2_chans", func() {
			for nc := range rChans {
				_ = nc.Reject(ssh.Prohibited, "not supported")
			}
		})
		streamCh, streamReqs, chErr := rConn.OpenChannel(devTunnelV2StreamChanType, nil)
		if chErr != nil {
			cleanupOnErr(relaySSHConn, wsNetConn)
			return nil, fmt.Errorf("[3/7 v2 open %s] %w", devTunnelV2StreamChanType, chErr)
		}
		safeGo(t.logger, workerID+"_v2_stream_reqs", func() { ssh.DiscardRequests(streamReqs) })
		hostTransport = NewDeadlineSSHConn(streamCh, "devtunnel-v2-host")
	}

	// 3. Outer Dev Tunnels SSH session — MUST use ssh.NewClientConn directly so we accept host `tcpip-forward`!
	hostKeyCB, verifiedKeys := buildOuterHostKeyCallback(hostPubKeys)
	outerCfg := &ssh.ClientConfig{
		User:            "tunnel",
		HostKeyCallback: hostKeyCB,
		Timeout:         15 * time.Second,
	}
	outerConn, outerChans, outerReqs, err := ssh.NewClientConn(hostTransport, relayURI, outerCfg)
	if err != nil {
		cleanupOnErr(hostTransport, relaySSHConn, wsNetConn)
		if ctx.Err() == nil && strings.Contains(err.Error(), "outer devtunnel host key mismatch") {
			t.creds.InvalidateIfMatch(credGen, "outer_host_key_mismatch")
		}
		return nil, fmt.Errorf("[4/7 outer ssh] %w", err)
	}
	t.logStage(workerID, "4/7", fmt.Sprintf("outer ssh connected (host_keys=%d)", verifiedKeys))

	outer := &outerDevTunnelSSH{
		conn:           outerConn,
		forwardedPorts: make(map[uint32]string),
		portSignal:     make(chan struct{}, 16),
	}
	safeGo(t.logger, workerID+"_outer_reqs", func() { outer.handleGlobalRequests(outerReqs) })
	safeGo(t.logger, workerID+"_outer_chans", func() {
		for nc := range outerChans {
			_ = nc.Reject(ssh.Prohibited, "unexpected channel")
		}
	})

	// Wait for host to advertise port 16634 via tcpip-forward (or request RefreshPorts).
	rpcReady := outer.waitForPort(ctx, codespaceRPCPort, 2500*time.Millisecond)
	if !rpcReady && ctx.Err() == nil {
		_, _, _ = outerConn.SendRequest("RefreshPorts", true, nil)
		rpcReady = outer.waitForPort(ctx, codespaceRPCPort, 5000*time.Millisecond)
	}
	t.logStage(workerID, "4/7", fmt.Sprintf("port 16634 advertised=%v", rpcReady))

	// 4. Generate ephemeral RAM-only Ed25519 keypair (never written to disk!).
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		cleanupOnErr(outerConn, hostTransport, relaySSHConn, wsNetConn)
		return nil, fmt.Errorf("[5/7 keygen] %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		cleanupOnErr(outerConn, hostTransport, relaySSHConn, wsNetConn)
		return nil, fmt.Errorf("[5/7 signer] %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		cleanupOnErr(outerConn, hostTransport, relaySSHConn, wsNetConn)
		return nil, fmt.Errorf("[5/7 pubkey] %w", err)
	}
	pubKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	// 5. Invoke zero-grpc h2c HTTP/2 StartRemoteServerAsync on port 16634 (with 1 cold-start retry).
	sshdPort, sshUser, err := invokeStartSSHServerH2C(ctx, func(dctx context.Context) (net.Conn, error) {
		return outer.openPortStream(dctx, codespaceRPCPort)
	}, pubKeyLine)
	if err != nil && ctx.Err() == nil {
		t.logStage(workerID, "5/7", fmt.Sprintf("StartRemoteServerAsync retry after transient error: %s", err.Error()))
		retryWait := 1500 * time.Millisecond
		if isLoopbackRelayURI(relayURI) {
			retryWait = 40 * time.Millisecond
		}
		tm := time.NewTimer(retryWait)
		select {
		case <-ctx.Done():
			tm.Stop()
		case <-tm.C:
			_, _, _ = outerConn.SendRequest("RefreshPorts", true, nil)
			_ = outer.waitForPort(ctx, codespaceRPCPort, 2000*time.Millisecond)
			sshdPort, sshUser, err = invokeStartSSHServerH2C(ctx, func(dctx context.Context) (net.Conn, error) {
				return outer.openPortStream(dctx, codespaceRPCPort)
			}, pubKeyLine)
		}
	}
	if err != nil {
		cleanupOnErr(outerConn, hostTransport, relaySSHConn, wsNetConn)
		if ctx.Err() == nil {
			if isDeadVMStartServerError(err) {
				if inv, _ := t.creds.InvalidateIfMatch(credGen, "rpc_start_server_rejected"); inv {
					t.logStage(workerID, "5/7", "VM SSH host rejected RPC — invalidated stale tunnel credentials for Codespace wake/refresh")
				}
				t.resetStageRPCFailure(credGen)
			} else if !rpcReady || isZombieRPCDeadlineError(err) {
				if cnt := t.recordStageRPCFailure(credGen); cnt >= 2 {
					if inv, _ := t.creds.InvalidateIfMatch(credGen, "rpc_consecutive_zombie_failures"); inv {
						t.logStage(workerID, "5/7", fmt.Sprintf("consecutive zombie RPC failures (count=%d) — invalidated stale tunnel credentials", cnt))
					}
					t.resetStageRPCFailure(credGen)
				}
			}
		}
		return nil, fmt.Errorf("[5/7 rpc StartRemoteServerAsync] %w", err)
	}
	t.resetStageRPCFailure(credGen)
	if sshUser == "" {
		sshUser = "codespace"
	}
	t.logStage(workerID, "5/7", fmt.Sprintf("StartRemoteServerAsync ok sshd_port=%d user=%s", sshdPort, sshUser))

	// 6. Ensure <sshdPort> is exposed on the Dev Tunnel and advertised via RefreshPorts.
	var putErr error
	if !outer.hasPort(uint32(sshdPort)) {
		portInDoc := false
		for _, p := range doc.Ports {
			if p.PortNumber == sshdPort {
				portInDoc = true
				break
			}
		}
		if !portInDoc {
			var putStatus int
			putStatus, putErr = t.ensureDevTunnelPort(ctx, props, doc.ClusterID, sshdPort)
			if putErr != nil {
				t.logStage(workerID, "6/7", fmt.Sprintf("PUT port %d warning: %s", sshdPort, putErr.Error()))
				if ctx.Err() == nil && isStaleDevTunnelHTTPStatus(putStatus) {
					t.creds.InvalidateIfMatch(credGen, fmt.Sprintf("port_put_http_%d", putStatus))
				}
			}
		}
		_, _, _ = outerConn.SendRequest("RefreshPorts", true, nil)
		sshdAdvertised := outer.waitForPort(ctx, uint32(sshdPort), 6000*time.Millisecond)
		t.logStage(workerID, "6/7", fmt.Sprintf("sshd port %d exposed advertised=%v", sshdPort, sshdAdvertised))
	} else {
		t.logStage(workerID, "6/7", fmt.Sprintf("sshd port %d already forwarded", sshdPort))
	}

	// 7. Open stream to <sshdPort> over Outer SSH and establish Inner Codespace SSH session.
	sshdStream, err := outer.openPortStream(ctx, uint32(sshdPort))
	if err != nil {
		cleanupOnErr(outerConn, hostTransport, relaySSHConn, wsNetConn)
		if putErr != nil {
			return nil, fmt.Errorf("[6/7 expose+open sshd port %d] open=%w (put=%v)", sshdPort, err, putErr)
		}
		return nil, fmt.Errorf("[7/7 open sshd port %d] %w", sshdPort, err)
	}

	innerCfg := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Authenticated inside outer TLS + outer SSH hostPublicKeys
		Timeout:         15 * time.Second,
		Config: ssh.Config{
			Ciphers: preferredInnerSSHCiphers(),
		},
	}
	innerConn, innerChans, innerReqs, err := ssh.NewClientConn(sshdStream, fmt.Sprintf("codespace-sshd:%d", sshdPort), innerCfg)
	if err != nil {
		cleanupOnErr(sshdStream, outerConn, hostTransport, relaySSHConn, wsNetConn)
		return nil, fmt.Errorf("[7/7 inner sshd handshake user=%s port=%d] %w", sshUser, sshdPort, err)
	}
	innerClient := ssh.NewClient(innerConn, innerChans, innerReqs)
	t.logStage(workerID, "7/7", fmt.Sprintf("inner ssh ready user=%s port=%d", sshUser, sshdPort))

	if !stopBootWatch() {
		_ = innerClient.Close()
		cleanupOnErr(sshdStream, outerConn, hostTransport, relaySSHConn, wsNetConn)
		if ctx.Err() != nil {
			return nil, fmt.Errorf("devtunnel boot canceled: %w", ctx.Err())
		}
		return nil, context.Canceled
	}

	t.creds.MarkTunnelHealthy(credGen)

	s := &devTunnelSession{
		workerID:      workerID,
		cfg:           t.cfg,
		wanRemote:     wanRemote,
		pmtu576:       pmtu576,
		sessCtx:       sessCtx,
		sessCancel:    sessCancel,
		wsNetConn:     wsNetConn,
		relaySSHConn:  relaySSHConn,
		hostTransport: hostTransport,
		outerSSHConn:  outerConn,
		sshdStream:    sshdStream,
		innerClient:   innerClient,
		hb:            t.hb,
		logger:        t.logger,
		doneCh:        make(chan error, 1),
	}
	s.startWatchdogs()
	return s, nil
}

// wsBinaryConn enforces PMTU=576-safe write chunking (<= 8 KiB) over the WebSocket binary stream.
type wsBinaryConn struct {
	net.Conn
	maxChunk int
}

func (w *wsBinaryConn) Write(p []byte) (int, error) {
	if w.maxChunk <= 0 || len(p) <= w.maxChunk {
		return w.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		n := w.maxChunk
		if len(p) < n {
			n = len(p)
		}
		written, err := w.Conn.Write(p[:n])
		total += written
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

type tcpipForwardPayload struct {
	BindAddr string
	BindPort uint32
}

type forwardedTCPIPPayload struct {
	ConnectedAddr string
	ConnectedPort uint32
	OriginAddr    string
	OriginPort    uint32
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type outerDevTunnelSSH struct {
	conn           ssh.Conn
	mu             sync.RWMutex
	forwardedPorts map[uint32]string
	portSignal     chan struct{}
}

func (o *outerDevTunnelSSH) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var p tcpipForwardPayload
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				o.mu.Lock()
				o.forwardedPorts[p.BindPort] = p.BindAddr
				o.mu.Unlock()
				select {
				case o.portSignal <- struct{}{}:
				default:
				}
				if req.WantReply {
					_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{p.BindPort}))
				}
			} else if req.WantReply {
				_ = req.Reply(false, nil)
			}
		case "cancel-tcpip-forward":
			var p tcpipForwardPayload
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				o.mu.Lock()
				delete(o.forwardedPorts, p.BindPort)
				o.mu.Unlock()
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (o *outerDevTunnelSSH) hasPort(port uint32) bool {
	o.mu.RLock()
	_, ok := o.forwardedPorts[port]
	o.mu.RUnlock()
	return ok
}

func (o *outerDevTunnelSSH) waitForPort(ctx context.Context, port uint32, timeout time.Duration) bool {
	if o.hasPort(port) {
		return true
	}
	tm := time.NewTimer(timeout)
	defer tm.Stop()
	for {
		select {
		case <-o.portSignal:
			if o.hasPort(port) {
				return true
			}
		case <-tm.C:
			return o.hasPort(port)
		case <-ctx.Done():
			return false
		}
	}
}

func (o *outerDevTunnelSSH) openPortStream(ctx context.Context, port uint32) (net.Conn, error) {
	o.mu.RLock()
	bindAddr, hasBind := o.forwardedPorts[port]
	o.mu.RUnlock()
	if !hasBind {
		bindAddr = "127.0.0.1"
	}

	type openRes struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	resCh := make(chan openRes, 1)
	safeGo(nil, "outer_open_port", func() {
		payload := ssh.Marshal(forwardedTCPIPPayload{
			ConnectedAddr: bindAddr,
			ConnectedPort: port,
			OriginAddr:    "127.0.0.1",
			OriginPort:    0,
		})
		ch, reqs, err := o.conn.OpenChannel("forwarded-tcpip", payload)
		if err != nil && bindAddr != "127.0.0.1" {
			fallbackPayload := ssh.Marshal(forwardedTCPIPPayload{
				ConnectedAddr: "127.0.0.1",
				ConnectedPort: port,
				OriginAddr:    "127.0.0.1",
				OriginPort:    0,
			})
			ch, reqs, err = o.conn.OpenChannel("forwarded-tcpip", fallbackPayload)
		}
		if err != nil {
			var openErr *ssh.OpenChannelError
			if errors.As(err, &openErr) && openErr.Reason == ssh.UnknownChannelType {
				// Defensive fallback for hosts expecting direct-tcpip.
				dPayload := ssh.Marshal(directTCPIPPayload{
					DestAddr:   "127.0.0.1",
					DestPort:   port,
					OriginAddr: "127.0.0.1",
					OriginPort: 0,
				})
				ch, reqs, err = o.conn.OpenChannel("direct-tcpip", dPayload)
			}
		}
		resCh <- openRes{ch: ch, reqs: reqs, err: err}
	})

	select {
	case <-ctx.Done():
		safeGo(nil, "outer_open_port_drain", func() {
			r := <-resCh
			if r.ch != nil {
				_ = r.ch.Close()
			}
		})
		return nil, ctx.Err()
	case r := <-resCh:
		if r.err != nil {
			return nil, r.err
		}
		safeGo(nil, "outer_port_reqs", func() { ssh.DiscardRequests(r.reqs) })
		return NewDeadlineSSHConn(r.ch, fmt.Sprintf("devtunnel-port:%d", port)), nil
	}
}

// devTunnelSession wraps an established Inner *ssh.Client + Outer Dev Tunnels transport + keepalive watchdog.
type devTunnelSession struct {
	workerID      string
	cfg           Config
	wanRemote     string
	pmtu576       bool
	sessCtx       context.Context
	sessCancel    context.CancelFunc
	wsNetConn     io.Closer
	relaySSHConn  io.Closer
	hostTransport io.Closer
	outerSSHConn  io.Closer
	sshdStream    io.Closer
	innerClient   *ssh.Client
	hb            *HeartbeatCoordinator
	logger        *EventLogger

	doneCh    chan error
	doneOnce  sync.Once
	closeOnce sync.Once
}

func (s *devTunnelSession) WANRemote() string   { return s.wanRemote }
func (s *devTunnelSession) PMTU576Active() bool { return s.pmtu576 }
func (s *devTunnelSession) Done() <-chan error  { return s.doneCh }

func (s *devTunnelSession) signalDone(err error) {
	s.doneOnce.Do(func() {
		s.doneCh <- err
		close(s.doneCh)
	})
}

func (s *devTunnelSession) Close() error {
	s.closeOnce.Do(func() {
		s.sessCancel()
		if s.innerClient != nil {
			_ = s.innerClient.Close()
		}
		if s.sshdStream != nil {
			_ = s.sshdStream.Close()
		}
		if s.outerSSHConn != nil {
			_ = s.outerSSHConn.Close()
		}
		if s.hostTransport != nil && s.hostTransport != s.wsNetConn {
			_ = s.hostTransport.Close()
		}
		if s.relaySSHConn != nil {
			_ = s.relaySSHConn.Close()
		}
		if s.wsNetConn != nil {
			_ = s.wsNetConn.Close()
		}
		s.signalDone(net.ErrClosed)
	})
	return nil
}

// DialTarget opens an RFC 4254 `direct-tcpip` channel directly inside the Inner Codespace SSH session
// WITHOUT performing local DNS resolution (eliminating Iranian ISP 10.10.34.x DNS poisoning).
func (s *devTunnelSession) DialTarget(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if s.sessCtx.Err() != nil {
		return nil, net.ErrClosed
	}
	payload := ssh.Marshal(directTCPIPPayload{
		DestAddr:   host,
		DestPort:   uint32(port),
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	})

	type res struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	chRes := make(chan res, 1)
	safeGo(s.logger, s.workerID+"_open_direct", func() {
		ch, reqs, err := s.innerClient.OpenChannel("direct-tcpip", payload)
		chRes <- res{ch: ch, reqs: reqs, err: err}
	})

	select {
	case <-ctx.Done():
		safeGo(s.logger, s.workerID+"_open_direct_cancel", func() {
			r := <-chRes
			if r.ch != nil {
				_ = r.ch.Close()
			}
		})
		return nil, ctx.Err()
	case <-s.sessCtx.Done():
		return nil, net.ErrClosed
	case r := <-chRes:
		if r.err != nil {
			return nil, r.err
		}
		safeGo(s.logger, s.workerID+"_direct_reqs", func() { ssh.DiscardRequests(r.reqs) })
		return NewDeadlineSSHConn(r.ch, net.JoinHostPort(host, strconv.Itoa(int(port)))), nil
	}
}

// SendKeepalive sends one deadline-bounded `keepalive@openssh.com` global request over Inner SSH.
func (s *devTunnelSession) SendKeepalive(ctx context.Context) error {
	if s.sessCtx.Err() != nil {
		return net.ErrClosed
	}
	errCh := make(chan error, 1)
	safeGo(s.logger, s.workerID+"_keepalive_req", func() {
		_, _, err := s.innerClient.SendRequest("keepalive@openssh.com", true, nil)
		errCh <- err
	})
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.sessCtx.Done():
		return net.ErrClosed
	}
}

func (s *devTunnelSession) startWatchdogs() {
	// Goroutine 1: Wait for inner SSH transport exit.
	safeGo(s.logger, s.workerID+"_ssh_wait", func() {
		err := s.innerClient.Wait()
		s.signalDone(err)
		_ = s.Close()
	})

	// Goroutine 2: ServerAliveInterval (10s) x ServerAliveCountMax (3) keepalive watchdog,
	// phase-locked via HeartbeatCoordinator when available.
	aliveSec := s.cfg.SSHServerAliveInterval
	if aliveSec <= 0 {
		aliveSec = DefaultSSHAliveInterval
	}
	maxMisses := s.cfg.SSHServerAliveCountMax
	if maxMisses <= 0 {
		maxMisses = DefaultSSHAliveCountMax
	}
	aliveInterval := time.Duration(aliveSec) * time.Second

	safeGo(s.logger, s.workerID+"_keepalive_loop", func() {
		var tickCh <-chan struct{}
		var unsub func()
		var localTicker *time.Ticker
		if s.hb != nil {
			tickCh, unsub = s.hb.Subscribe()
			defer unsub()
		} else {
			localTicker = time.NewTicker(aliveInterval)
			defer localTicker.Stop()
		}

		misses := 0
		for {
			if tickCh != nil {
				select {
				case <-s.sessCtx.Done():
					return
				case <-tickCh:
				}
			} else {
				select {
				case <-s.sessCtx.Done():
					return
				case <-localTicker.C:
				}
			}
			kCtx, kCancel := context.WithTimeout(s.sessCtx, aliveInterval)
			err := s.SendKeepalive(kCtx)
			kCancel()
			if err == nil {
				misses = 0
				continue
			}
			if s.sessCtx.Err() != nil {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				misses++
				if misses >= maxMisses {
					s.signalDone(fmt.Errorf("ssh keepalive timeout (%d consecutive misses)", misses))
					_ = s.Close()
					return
				}
				continue
			}
			// Hard transport error -> fail immediately.
			s.signalDone(fmt.Errorf("ssh keepalive failed: %w", err))
			_ = s.Close()
			return
		}
	})
}

// -----------------------------------------------------------------------------
// Zero-gRPC h2c HTTP/2 Unary Protobuf Codec for Codespaces Port 16634 RPC
// -----------------------------------------------------------------------------

func encodeProtobufVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func decodeProtobufVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("invalid protobuf varint")
}

// EncodeStartRemoteServerRequest encodes StartRemoteServerRequest{ string UserPublicKey = 1 }.
func EncodeStartRemoteServerRequest(userPublicKey string) []byte {
	if userPublicKey == "" {
		return nil
	}
	out := make([]byte, 0, len(userPublicKey)+8)
	out = append(out, (1<<3)|2) // field 1, wire type 2 (bytes/string)
	out = encodeProtobufVarint(out, uint64(len(userPublicKey)))
	out = append(out, userPublicKey...)
	return out
}

// DecodeStartRemoteServerResponse decodes StartRemoteServerResponse:
//
//	bool   Result     = 1 (wire type 0)
//	string ServerPort = 2 (wire type 2 — with defensive fallback for wire type 0 varint)
//	string User       = 3 (wire type 2)
//	string Message    = 4 (wire type 2)
func DecodeStartRemoteServerResponse(b []byte) (ok bool, serverPort uint16, user string, message string, err error) {
	pos := 0
	for pos < len(b) {
		tag, n, terr := decodeProtobufVarint(b[pos:])
		if terr != nil {
			return false, 0, "", "", terr
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 0x07

		switch wireType {
		case 0: // varint
			val, vn, verr := decodeProtobufVarint(b[pos:])
			if verr != nil {
				return false, 0, "", "", verr
			}
			pos += vn
			switch fieldNum {
			case 1:
				ok = val != 0
			case 2:
				if val > 0 && val <= 65535 {
					serverPort = uint16(val)
				}
			}
		case 2: // length-delimited
			l, ln, lerr := decodeProtobufVarint(b[pos:])
			if lerr != nil || pos+ln+int(l) > len(b) {
				return false, 0, "", "", errors.New("truncated protobuf string field")
			}
			pos += ln
			s := string(b[pos : pos+int(l)])
			pos += int(l)
			switch fieldNum {
			case 2:
				if p, perr := strconv.Atoi(strings.TrimSpace(s)); perr == nil && p > 0 && p <= 65535 {
					serverPort = uint16(p)
				}
			case 3:
				user = s
			case 4:
				message = s
			}
		case 1: // 64-bit skip
			if pos+8 > len(b) {
				return false, 0, "", "", errors.New("truncated 64-bit field")
			}
			pos += 8
		case 5: // 32-bit skip
			if pos+4 > len(b) {
				return false, 0, "", "", errors.New("truncated 32-bit field")
			}
			pos += 4
		default:
			return false, 0, "", "", fmt.Errorf("unsupported protobuf wire type %d", wireType)
		}
	}
	return ok, serverPort, user, message, nil
}

func FrameGRPCMessage(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = 0x00 // uncompressed
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func invokeStartSSHServerH2C(ctx context.Context, dialStream func(context.Context) (net.Conn, error), userPubKey string) (uint16, string, error) {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(dctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return dialStream(dctx)
		},
	}
	defer tr.CloseIdleConnections()

	framedReq := FrameGRPCMessage(EncodeStartRemoteServerRequest(userPubKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:16634"+startSSHServerGRPCPath, bytes.NewReader(framedReq))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Timeout", "20S")

	client := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return 0, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("rpc HTTP %d", resp.StatusCode)
	}
	grpcStatus := resp.Trailer.Get("Grpc-Status")
	if grpcStatus == "" {
		grpcStatus = resp.Header.Get("Grpc-Status")
	}
	if grpcStatus != "" && grpcStatus != "0" {
		grpcMsg := resp.Trailer.Get("Grpc-Message")
		if grpcMsg == "" {
			grpcMsg = resp.Header.Get("Grpc-Message")
		}
		return 0, "", fmt.Errorf("grpc status %s: %s", grpcStatus, grpcMsg)
	}
	if len(body) < 5 {
		return 0, "", errors.New("rpc response missing 5-byte gRPC frame header")
	}
	msgLen := int(binary.BigEndian.Uint32(body[1:5]))
	if 5+msgLen > len(body) {
		return 0, "", errors.New("rpc response gRPC frame truncated")
	}
	ok, port, user, msg, err := DecodeStartRemoteServerResponse(body[5 : 5+msgLen])
	if err != nil {
		return 0, "", err
	}
	if !ok {
		return 0, "", fmt.Errorf("StartRemoteServerAsync rejected: %s", msg)
	}
	if port == 0 {
		return 0, "", errors.New("StartRemoteServerAsync returned empty/zero ServerPort")
	}
	return port, user, nil
}
