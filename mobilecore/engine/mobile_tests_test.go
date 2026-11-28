package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
)

// =============================================================================
// Protocol-Faithful In-Process Mock Dev Tunnels + Outer SSH + h2c gRPC (16634) + Inner SSH Server
// =============================================================================

type mockDevTunnelStack struct {
	srv                *httptest.Server
	outerHostKey       ssh.Signer
	outerHostPubLine   string
	innerHostKey       ssh.Signer
	subprotocolMode    string // devTunnelWSProtoV1 or devTunnelWSProtoV2
	connectToken       string
	manageToken        string
	sshdPort           uint16
	tcpipForwardOK      atomic.Bool
	tcpipForwardReplyOk atomic.Bool
	portPutCalled       atomic.Bool
	portPutIfNoneMatch  atomic.Bool
	portPutProtocolHTTP atomic.Bool
	rpcAuthBearerSeen   atomic.Bool
	useRawB64HostKey    atomic.Bool
	keepalivesReceived  atomic.Int64
	blackholeKeepalive atomic.Bool

	mu               sync.Mutex
	authorizedPubs   map[string]bool
	portExposed      bool
	observedDestHost []string
	activeConns      []io.Closer
	restStatusFn     func(tunnelID string) int
	rpcFaultFn       func(attempt int) (grpcStatus string, grpcMsg string, rejectMsg string)
	rpcCalls         atomic.Int32
	wg               sync.WaitGroup
}

func startMockDevTunnelStack(t *testing.T, subprotocolMode string, preExposeSSHD bool) *mockDevTunnelStack {
	t.Helper()
	_, oPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("outer keygen: %v", err)
	}
	oSigner, _ := ssh.NewSignerFromKey(oPriv)
	_, iPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("inner keygen: %v", err)
	}
	iSigner, _ := ssh.NewSignerFromKey(iPriv)

	st := &mockDevTunnelStack{
		outerHostKey:     oSigner,
		outerHostPubLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(oSigner.PublicKey()))),
		innerHostKey:     iSigner,
		subprotocolMode:  subprotocolMode,
		connectToken:     makeMockJWT(time.Now().Add(2 * time.Hour)),
		manageToken:      "mock-manage-token-xyz",
		sshdPort:         2222,
		authorizedPubs:   make(map[string]bool),
		portExposed:      preExposeSSHD,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/ports/") {
			if r.Header.Get("Authorization") != "tunnel "+st.manageToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("If-None-Match") == "*" {
				st.portPutIfNoneMatch.Store(true)
			}
			putRaw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if strings.Contains(string(putRaw), `"protocol":"http"`) {
				st.portPutProtocolHTTP.Store(true)
			}
			st.portPutCalled.Store(true)
			st.mu.Lock()
			st.portExposed = true
			st.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"portNumber":2222,"protocol":"http"}`))
			return
		}
		if r.Header.Get("Authorization") != "tunnel "+st.connectToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reqTunnelID := strings.TrimPrefix(r.URL.Path, "/tunnels/")
		if idx := strings.IndexByte(reqTunnelID, '/'); idx >= 0 {
			reqTunnelID = reqTunnelID[:idx]
		}
		st.mu.Lock()
		statusFn := st.restStatusFn
		st.mu.Unlock()
		if statusFn != nil {
			if code := statusFn(reqTunnelID); code != 0 && code != http.StatusOK {
				w.WriteHeader(code)
				_, _ = fmt.Fprintf(w, `{"title":"Error %d","status":%d}`, code, code)
				return
			}
		}
		wsURL := "ws" + strings.TrimPrefix(st.srv.URL, "http") + "/relay"
		hostPub := st.outerHostPubLine
		if st.useRawB64HostKey.Load() {
			hostPub = base64.StdEncoding.EncodeToString(st.outerHostKey.PublicKey().Marshal())
		}
		doc := map[string]any{
			"tunnelId":  "tun-mock-1",
			"clusterId": "euw",
			"endpoints": []map[string]any{
				{
					"id":             "ep-1",
					"connectionMode": "TunnelRelay",
					"clientRelayUri": wsURL,
					"hostPublicKeys": []string{hostPub},
				},
			},
			"ports": []map[string]any{{"portNumber": 16634}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "tunnel "+st.connectToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:       []string{st.subprotocolMode},
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		wsConn.SetReadLimit(-1)
		netConn := websocket.NetConn(r.Context(), wsConn, websocket.MessageBinary)
		st.mu.Lock()
		st.activeConns = append(st.activeConns, netConn)
		st.mu.Unlock()
		defer netConn.Close()

		if st.subprotocolMode == devTunnelWSProtoV2 {
			st.serveRelayV2(netConn)
			return
		}
		st.serveOuterSSH(netConn)
	})

	st.srv = httptest.NewServer(mux)
	return st
}

func (st *mockDevTunnelStack) DropAllSessions() {
	st.mu.Lock()
	conns := st.activeConns
	st.activeConns = nil
	st.mu.Unlock()
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (st *mockDevTunnelStack) Close() {
	st.DropAllSessions()
	st.srv.Close()
	st.wg.Wait()
}

func (st *mockDevTunnelStack) TunnelProperties() TunnelProperties {
	return TunnelProperties{
		ConnectAccessToken:     st.connectToken,
		ManagePortsAccessToken: st.manageToken,
		ServiceURI:             st.srv.URL,
		TunnelID:               "tun-mock-1",
		ClusterID:              "euw",
		Domain:                 "euw.devtunnels.ms",
	}
}

func (st *mockDevTunnelStack) serveRelayV2(conn net.Conn) {
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(st.outerHostKey)
	sConn, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
	if err != nil {
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != devTunnelV2StreamChanType {
			_ = nc.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		st.wg.Add(1)
		go func() {
			defer st.wg.Done()
			st.serveOuterSSH(NewDeadlineSSHConn(ch, "v2-stream"))
		}()
	}
}

func (st *mockDevTunnelStack) serveOuterSSH(conn net.Conn) {
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(st.outerHostKey)
	sConn, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
	if err != nil {
		return
	}
	defer sConn.Close()

	// Send Dev Tunnels host-initiated `tcpip-forward` for port 16634 and verify client replies true!
	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		ok, replyBytes, err := sConn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardPayload{
			BindAddr: "127.0.0.1",
			BindPort: codespaceRPCPort,
		}))
		if err == nil && ok {
			st.tcpipForwardOK.Store(true)
			if len(replyBytes) == 4 && binary.BigEndian.Uint32(replyBytes) == codespaceRPCPort {
				st.tcpipForwardReplyOk.Store(true)
			}
		}
	}()

	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		for req := range reqs {
			if req.Type == "RefreshPorts" {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				st.mu.Lock()
				exp := st.portExposed
				st.mu.Unlock()
				if exp {
					_, _, _ = sConn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardPayload{
						BindAddr: "127.0.0.1",
						BindPort: uint32(st.sshdPort),
					}))
				}
				continue
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	for nc := range chans {
		if nc.ChannelType() != "forwarded-tcpip" {
			_ = nc.Reject(ssh.UnknownChannelType, "expected forwarded-tcpip")
			continue
		}
		var p forwardedTCPIPPayload
		if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
			_ = nc.Reject(ssh.Prohibited, "bad payload")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		switch p.ConnectedPort {
		case codespaceRPCPort:
			st.wg.Add(1)
			go func() {
				defer st.wg.Done()
				st.serveH2CGRPC(NewDeadlineSSHConn(ch, "rpc:16634"))
			}()
		case uint32(st.sshdPort):
			st.wg.Add(1)
			go func() {
				defer st.wg.Done()
				st.serveInnerSSHD(NewDeadlineSSHConn(ch, "inner-sshd"))
			}()
		default:
			_ = ch.Close()
		}
	}
}

func (st *mockDevTunnelStack) serveH2CGRPC(conn net.Conn) {
	defer conn.Close()
	h2s := &http2.Server{}
	h2s.ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != startSSHServerGRPCPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Header.Get("Authorization") == "Bearer token" {
				st.rpcAuthBearerSeen.Store(true)
			}
			raw, _ := io.ReadAll(r.Body)
			if len(raw) < 5 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mLen := int(binary.BigEndian.Uint32(raw[1:5]))
			if 5+mLen <= len(raw) {
				// Decode field 1 (UserPublicKey) from StartRemoteServerRequest.
				msg := raw[5 : 5+mLen]
				if len(msg) > 2 && msg[0] == ((1<<3)|2) {
					strLen, n, err := decodeProtobufVarint(msg[1:])
					if err == nil && 1+n+int(strLen) <= len(msg) {
						pubLine := string(msg[1+n : 1+n+int(strLen)])
						if pk, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(pubLine)); perr == nil {
							st.mu.Lock()
							st.authorizedPubs[string(pk.Marshal())] = true
							st.mu.Unlock()
						}
					}
				}
			}
			rpcAttempt := int(st.rpcCalls.Add(1))
			st.mu.Lock()
			rfn := st.rpcFaultFn
			st.mu.Unlock()
			if rfn != nil {
				gStatus, gMsg, rejMsg := rfn(rpcAttempt)
				if gStatus != "" {
					w.Header().Set("Content-Type", "application/grpc")
					w.Header().Set("Grpc-Status", gStatus)
					w.Header().Set("Grpc-Message", gMsg)
					w.WriteHeader(http.StatusOK)
					return
				}
				if rejMsg != "" {
					var rejPB []byte
					rejPB = append(rejPB, (1<<3)|0, 0) // Result = false
					rejPB = append(rejPB, (4<<3)|2)
					rejPB = encodeProtobufVarint(rejPB, uint64(len(rejMsg)))
					rejPB = append(rejPB, rejMsg...)
					w.Header().Set("Content-Type", "application/grpc")
					w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(FrameGRPCMessage(rejPB))
					w.Header().Set("Grpc-Status", "0")
					return
				}
			}
			// Encode StartRemoteServerResponse{ Result=true (1), ServerPort="2222" (2, string!), User="codespace" (3) }.
			var respPB []byte
			respPB = append(respPB, (1<<3)|0, 1) // Result = true
			portStr := strconv.Itoa(int(st.sshdPort))
			respPB = append(respPB, (2<<3)|2)
			respPB = encodeProtobufVarint(respPB, uint64(len(portStr)))
			respPB = append(respPB, portStr...)
			userStr := "codespace"
			respPB = append(respPB, (3<<3)|2)
			respPB = encodeProtobufVarint(respPB, uint64(len(userStr)))
			respPB = append(respPB, userStr...)

			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(FrameGRPCMessage(respPB))
			w.Header().Set("Grpc-Status", "0")
		}),
	})
}

func (st *mockDevTunnelStack) serveInnerSSHD(conn net.Conn) {
	defer conn.Close()
	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			st.mu.Lock()
			ok := st.authorizedPubs[string(pubKey.Marshal())]
			st.mu.Unlock()
			if !ok {
				return nil, errors.New("unauthorized ephemeral key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	srvCfg.AddHostKey(st.innerHostKey)
	sConn, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
	if err != nil {
		return
	}
	defer sConn.Close()

	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				st.keepalivesReceived.Add(1)
				if st.blackholeKeepalive.Load() {
					// Simulate CG-NAT silent blackhole: never reply!
					continue
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				continue
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			_ = nc.Reject(ssh.UnknownChannelType, "expected direct-tcpip")
			continue
		}
		var p directTCPIPPayload
		if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
			_ = nc.Reject(ssh.Prohibited, "bad direct-tcpip")
			continue
		}
		st.mu.Lock()
		st.observedDestHost = append(st.observedDestHost, p.DestAddr)
		st.mu.Unlock()
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		st.wg.Add(1)
		go func(c ssh.Channel) {
			defer st.wg.Done()
			defer c.Close()
			buf := make([]byte, 16*1024)
			for {
				n, rerr := c.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					_ = c.CloseWrite()
					return
				}
			}
		}(ch)
	}
}

func makeMockJWT(exp time.Time) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return hdr + "." + pay + ".mocksignature"
}

func makeTestPayload(size int, seed byte) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i*31 + int(seed)) & 0xff)
	}
	return b
}

func performSOCKS5DomainEcho(proxyAddr, domain string, port uint16, payload []byte, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return err
	}
	if m[0] != 0x05 || m[1] != 0x00 {
		return fmt.Errorf("bad socks5 method %x", m)
	}
	req := make([]byte, 0, 7+len(domain))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	req = append(req, domain...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return fmt.Errorf("socks5 connect rejected rep=0x%02x", rep[1])
	}
	if _, err := c.Write(payload); err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if len(got) != len(payload) || sha256.Sum256(got) != sha256.Sum256(payload) {
		return fmt.Errorf("echo mismatch got=%d want=%d", len(got), len(payload))
	}
	return nil
}

func waitUntilCond(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	dl := time.Now().Add(timeout)
	for time.Now().Before(dl) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}

func assertGoroutinesClean(t *testing.T, base int, tol int) {
	t.Helper()
	dl := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(dl) {
		runtime.GC()
		if runtime.NumGoroutine() <= base+tol {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutine leak detected: baseline=%d current=%d (tol=%d)", base, runtime.NumGoroutine(), tol)
}

// =============================================================================
// MT-01: Full In-Process Dev Tunnels Mock (v1 & v2) + Outer SSH + h2c gRPC 16634 + Inner SSH + SOCKS5
// =============================================================================
func TestMT01_InProcessDevTunnelMockEndToEndSOCKS5(t *testing.T) {
	for _, proto := range []string{devTunnelWSProtoV1, devTunnelWSProtoV2} {
		t.Run(proto, func(t *testing.T) {
			baseG := runtime.NumGoroutine()
			stack := startMockDevTunnelStack(t, proto, false)
			defer stack.Close()

			ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"name":  "mt01-space",
					"state": "Available",
					"connection": map[string]any{
						"tunnel_properties": stack.TunnelProperties(),
					},
				})
			}))
			defer ghSrv.Close()

			cfg := DefaultConfig()
			cfg.CodespaceName = "mt01-space"
			cfg.GitHubToken = "gho_mocktoken_mt01_secret"
			cfg.GitHubAPIBaseURL = ghSrv.URL
			cfg.LocalPort = 0
			cfg.PoolSize = 2
			cfg.BootQualitySamples = 2
			cfg.BootMicroPayloadCheck = true
			cfg.StopOnExit = false
			cfg.GitHubMinCallSpacing = 0

			resolver := NewAntiPoisonResolver(nil, nil)
			guard := NewGitHubGuard(cfg, nil, nil)
			api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, resolver, guard)
			creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
			hb := NewHeartbeatCoordinator(2 * time.Second)
			defer hb.Close()
			tr := NewDevTunnelSSHTransport(cfg, creds, resolver, hb, nil)

			sup := NewSupervisor(cfg, nil, SupervisorDeps{
				Transport:   tr,
				GitHubGuard: guard,
				PoolHooks: PoolHooks{
					SampleDelay: 10 * time.Millisecond,
					RetryDelay:  20 * time.Millisecond,
				},
			})

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- sup.Run(ctx) }()

			waitUntilCond(t, 5*time.Second, "MT-01 pool 2/2 healthy", func() bool {
				return sup.State() == StateHealthy && sup.AtomicPoolSnapshot().HealthyWorkers == 2
			})

			if !stack.tcpipForwardOK.Load() {
				t.Fatal("MT-01 outer Dev Tunnels SSH did not reply true to host tcpip-forward")
			}
			if !stack.portPutCalled.Load() {
				t.Fatal("MT-01 expected PUT /tunnels/{id}/ports/2222 for unexposed sshd port")
			}

			// Verify remote DNS domain preservation through SOCKS5 ATYP=0x03 -> direct-tcpip!
			payload := makeTestPayload(48*1024, 0x42)
			if err := performSOCKS5DomainEcho(sup.AtomicBoundLocalAddr(), "blocked-domain.example.com", 443, payload, 4*time.Second); err != nil {
				cancel()
				<-done
				t.Fatalf("MT-01 SOCKS5 echo failed: %v", err)
			}

			stack.mu.Lock()
			sawDomain := false
			for _, h := range stack.observedDestHost {
				if h == "blocked-domain.example.com" {
					sawDomain = true
				}
			}
			stack.mu.Unlock()
			if !sawDomain {
				cancel()
				<-done
				t.Fatalf("MT-01 domain name was resolved locally instead of sent verbatim in direct-tcpip: %v", stack.observedDestHost)
			}

			cancel()
			<-done
			hb.Close()
			stack.Close()
			ghSrv.Close()
			assertGoroutinesClean(t, baseG, 10)
		})
	}
}

// =============================================================================
// MT-02: 64-Stream Channel Saturation + PMTU=576 (8 KiB) + 20s<25s Deadlock Freedom
// =============================================================================
func TestMT02_ChannelSaturation64StreamsAndPMTU576AndDeadlockFreedom(t *testing.T) {
	baseG := runtime.NumGoroutine()
	stack := startMockDevTunnelStack(t, devTunnelWSProtoV1, true)
	defer stack.Close()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt02-space",
			"state": "Available",
			"connection": map[string]any{
				"tunnel_properties": stack.TunnelProperties(),
			},
		})
	}))
	defer ghSrv.Close()

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt02-space"
	cfg.GitHubToken = "gho_mt02"
	cfg.GitHubAPIBaseURL = ghSrv.URL
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.MaxActiveConns = 64
	cfg.PerTunnelMaxConns = 32
	cfg.MaxQueuedConns = 128
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.GitHubMinCallSpacing = 0

	// Verify PMTU=576 NAT64 + IPv4 detection & deadlock inequality.
	if !IsPMTU576RelayIP("20.120.56.11:443") || !IsPMTU576RelayIP("[::ffff:20.120.56.11]:443") || !IsPMTU576RelayIP("[64:ff9b::1478:380b]:443") {
		t.Fatal("MT-02 IsPMTU576RelayIP failed NAT64/IPv4-mapped detection")
	}
	if cfg.StreamingPressureIdleTimeout >= cfg.SemaphoreWaitTimeout {
		t.Fatal("MT-02 deadlock-freedom invariant violated")
	}

	resolver := NewAntiPoisonResolver(nil, nil)
	guard := NewGitHubGuard(cfg, nil, nil)
	api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, resolver, guard)
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	tr := NewDevTunnelSSHTransport(cfg, creds, resolver, nil, nil)

	dir := t.TempDir()
	metricsPath := filepath.Join(dir, "mt02_metrics.ndjson")
	metrics, err := NewMetricsEmitter(metricsPath, "mt02")
	if err != nil {
		t.Fatalf("MT-02 metrics: %v", err)
	}

	// Wrap transport so WANRemote reports NAT64 PMTU=576 address -> activates 8 KiB copy buffer pool!
	pmtuTr := &pmtuOverrideTransport{inner: tr, wan: "[64:ff9b::1478:380b]:443"}
	sup := NewSupervisor(cfg, nil, SupervisorDeps{
		Transport:   pmtuTr,
		Metrics:     metrics,
		GitHubGuard: guard,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntilCond(t, 5*time.Second, "MT-02 2/2 pool healthy", func() bool {
		return sup.State() == StateHealthy && sup.AtomicPoolSnapshot().HealthyWorkers == 2
	})

	addr := sup.AtomicBoundLocalAddr()
	const totalClients = 64
	payload := makeTestPayload(16*1024, 0x55)
	var okCnt atomic.Int64
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < totalClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-gate
			if err := performSOCKS5DomainEcho(addr, fmt.Sprintf("h%d.example.com", id), 443, payload, 10*time.Second); err == nil {
				okCnt.Add(1)
			}
		}(i)
	}
	close(gate)
	wg.Wait()

	if okCnt.Load() != totalClients {
		cancel()
		<-done
		t.Fatalf("MT-02 expected 64/64 multiplexed SSH channels OK, got %d/64", okCnt.Load())
	}

	cancel()
	<-done
	_ = metrics.Close()

	// Verify 8192B PMTU=576 copy buffer path activated in metrics.
	rawMetrics, _ := os.ReadFile(metricsPath)
	if !strings.Contains(string(rawMetrics), `"copy_buffer_bytes":8192`) {
		t.Fatalf("MT-02 expected adaptive 8192B PMTU=576 copy buffer in metrics")
	}

	stack.Close()
	ghSrv.Close()
	assertGoroutinesClean(t, baseG, 12)
}

type pmtuOverrideTransport struct {
	inner WorkerTransport
	wan   string
}

func (p *pmtuOverrideTransport) Connect(ctx context.Context, workerID string) (WorkerSession, error) {
	s, err := p.inner.Connect(ctx, workerID)
	if err != nil {
		return nil, err
	}
	return &pmtuOverrideSession{WorkerSession: s, wan: p.wan}, nil
}

type pmtuOverrideSession struct {
	WorkerSession
	wan string
}

func (s *pmtuOverrideSession) WANRemote() string   { return s.wan }
func (s *pmtuOverrideSession) PMTU576Active() bool { return IsPMTU576RelayIP(s.wan) }

// =============================================================================
// MT-03: Generation-Guarded DeadlineSSHConn (-race stress + stale timer safety)
// =============================================================================
func TestMT03_DeadlineSSHConnRaceAndGenerationGuard(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// 1. Direct generation-guard proof: stale onReadTimeout(oldGen) racing with extended deadline MUST NOT close stream!
	fch := newFakeSSHChannel()
	dc := NewDeadlineSSHConn(fch, "test:443")

	_ = dc.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	dc.mu.Lock()
	staleGen := dc.readGen
	dc.mu.Unlock()

	// Extend deadline to 10s (bumps readGen -> staleGen+1), then manually fire stale callback!
	_ = dc.SetReadDeadline(time.Now().Add(10 * time.Second))
	dc.onReadTimeout(staleGen)

	if fch.closed.Load() {
		t.Fatal("MT-03 stale readGen timer callback closed freshly extended stream!")
	}
	// Stream must still read data cleanly.
	fch.inCh <- []byte("alive-after-stale-timer")
	buf := make([]byte, 32)
	n, err := dc.Read(buf)
	if err != nil || string(buf[:n]) != "alive-after-stale-timer" {
		t.Fatalf("MT-03 read after stale timer failed: n=%d err=%v", n, err)
	}

	// 2. Concurrent -race storm: SetReadDeadline / SetWriteDeadline / Read / Write / CloseWrite / Close.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			_ = dc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_ = dc.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if i%50 == 0 {
				_ = dc.SetDeadline(time.Time{})
			}
		}
		close(stop)
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = dc.Write([]byte("ping"))
			}
		}
	}()
	go func() {
		defer wg.Done()
		var tmp [16]byte
		for {
			select {
			case <-stop:
				return
			default:
				select {
				case fch.inCh <- []byte("pong"):
				default:
				}
				_, _ = dc.Read(tmp[:])
			}
		}
	}()
	wg.Wait()
	_ = dc.CloseWrite()
	if !fch.eofSent.Load() {
		t.Fatal("MT-03 CloseWrite did not propagate SSH_MSG_CHANNEL_EOF")
	}
	_ = dc.Close()

	// 3. Real timeout returns net.Error with Timeout()==true.
	fch2 := newFakeSSHChannel()
	dc2 := NewDeadlineSSHConn(fch2, "timeout:443")
	_ = dc2.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, rErr := dc2.Read(buf)
	var ne net.Error
	if !errors.As(rErr, &ne) || !ne.Timeout() {
		t.Fatalf("MT-03 expected net.Error Timeout()=true, got %v", rErr)
	}
	_ = dc2.Close()

	assertGoroutinesClean(t, baseG, 4)
}

type fakeSSHChannel struct {
	inCh    chan []byte
	closeCh chan struct{}
	closed  atomic.Bool
	eofSent atomic.Bool
	once    sync.Once
}

func newFakeSSHChannel() *fakeSSHChannel {
	return &fakeSSHChannel{
		inCh:    make(chan []byte, 16),
		closeCh: make(chan struct{}),
	}
}

func (f *fakeSSHChannel) Read(b []byte) (int, error) {
	select {
	case data := <-f.inCh:
		return copy(b, data), nil
	case <-f.closeCh:
		return 0, io.EOF
	}
}

func (f *fakeSSHChannel) Write(b []byte) (int, error) {
	if f.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return len(b), nil
}

func (f *fakeSSHChannel) Close() error {
	f.once.Do(func() {
		f.closed.Store(true)
		close(f.closeCh)
	})
	return nil
}

func (f *fakeSSHChannel) CloseWrite() error {
	f.eofSent.Store(true)
	return nil
}

func (f *fakeSSHChannel) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (f *fakeSSHChannel) Stderr() io.ReadWriter                          { return bytes.NewBuffer(nil) }

// =============================================================================
// MT-04: SOCKS5 Instant UDP/BIND Reject (0x07) & Self-Loop Protection (0x02)
// =============================================================================
func TestMT04_SOCKS5UDPRejectAndSelfLoopProtection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.CodespaceName = "mt04-space"

	px := NewPooledProxyServer(cfg, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, err := px.Start(ctx)
	if err != nil {
		t.Fatalf("MT-04 proxy start: %v", err)
	}
	defer px.Stop(true)
	boundPort := px.BoundPort()

	sendRawReq := func(cmd byte, hostIP [4]byte, port uint16) byte {
		c, derr := net.DialTimeout("tcp", addr, time.Second)
		if derr != nil {
			t.Fatalf("MT-04 dial: %v", derr)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte{0x05, 0x01, 0x00})
		var m [2]byte
		_, _ = io.ReadFull(c, m[:])
		req := []byte{0x05, cmd, 0x00, 0x01, hostIP[0], hostIP[1], hostIP[2], hostIP[3], byte(port >> 8), byte(port)}
		_, _ = c.Write(req)
		var rep [10]byte
		if _, rerr := io.ReadFull(c, rep[:]); rerr != nil {
			t.Fatalf("MT-04 read reply: %v", rerr)
		}
		return rep[1]
	}

	// UDP ASSOCIATE (0x03) -> instant REP=0x07
	start := time.Now()
	if rep := sendRawReq(socks5CmdUDPAssoc, [4]byte{1, 1, 1, 1}, 443); rep != socks5RepCmdNotSupported {
		t.Fatalf("MT-04 UDP ASSOCIATE expected REP=0x07, got 0x%02x", rep)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("MT-04 UDP reject too slow: %s", time.Since(start))
	}
	// BIND (0x02) -> instant REP=0x07
	if rep := sendRawReq(socks5CmdBind, [4]byte{1, 1, 1, 1}, 443); rep != socks5RepCmdNotSupported {
		t.Fatalf("MT-04 BIND expected REP=0x07, got 0x%02x", rep)
	}
	// Self-loop 127.0.0.1:<boundPort> -> instant REP=0x02
	if rep := sendRawReq(socks5CmdConnect, [4]byte{127, 0, 0, 1}, boundPort); rep != socks5RepNotAllowed {
		t.Fatalf("MT-04 self-loop expected REP=0x02, got 0x%02x", rep)
	}
}

// =============================================================================
// Lightweight In-Memory Mock WorkerTransport for Pool/Handover/Idle/Hysteresis Chaos Tests
// =============================================================================

type mockTransport struct {
	connects atomic.Int64
	mu       sync.Mutex
	onConn   func(workerID string, seq int64) (*mockWorkerSession, error)
}

func (m *mockTransport) Connect(ctx context.Context, workerID string) (WorkerSession, error) {
	n := m.connects.Add(1)
	m.mu.Lock()
	fn := m.onConn
	m.mu.Unlock()
	if fn != nil {
		return fn(workerID, n)
	}
	return newMockWorkerSession("20.93.53.155:443"), nil
}

type mockWorkerSession struct {
	wan       string
	doneCh    chan error
	once      sync.Once
	keepalive func(ctx context.Context) error
}

func newMockWorkerSession(wan string) *mockWorkerSession {
	return &mockWorkerSession{
		wan:    wan,
		doneCh: make(chan error, 1),
	}
}

func (s *mockWorkerSession) DialTarget(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		defer ln.Close()
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", ln.Addr().String())
}

func (s *mockWorkerSession) SendKeepalive(ctx context.Context) error {
	if s.keepalive != nil {
		return s.keepalive(ctx)
	}
	return nil
}

func (s *mockWorkerSession) WANRemote() string   { return s.wan }
func (s *mockWorkerSession) PMTU576Active() bool { return IsPMTU576RelayIP(s.wan) }
func (s *mockWorkerSession) Done() <-chan error  { return s.doneCh }
func (s *mockWorkerSession) Close() error {
	s.once.Do(func() {
		s.doneCh <- net.ErrClosed
		close(s.doneCh)
	})
	return nil
}

// =============================================================================
// MT-05: Network Handover Flap Storm + Trailing-Edge Debounce + PAUSED_OFFLINE
// =============================================================================
func TestMT05_NetworkHandoverFlapStormAndPausedOffline(t *testing.T) {
	baseG := runtime.NumGoroutine()
	tr := &mockTransport{}

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt05-space"
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.NetworkDebounceInterval = 120 * time.Millisecond
	cfg.BackoffMin = 30 * time.Millisecond
	cfg.BackoffMax = 60 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	ctrl := NewSessionController(cfg, ControllerCallbacks{}, ControllerOverrides{
		TransportFactory: func(_ Config, _ *CredentialManager, _ *AntiPoisonResolver, _ *HeartbeatCoordinator, _ *EventLogger) WorkerTransport {
			return tr
		},
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 120 * time.Millisecond, nil
			},
		},
		SnapshotInterval: 50 * time.Millisecond,
	})
	ctrl.Start()
	defer ctrl.StopAndWait(4 * time.Second)

	waitUntilCond(t, 4*time.Second, "MT-05 RUNNING 2/2", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2
	})

	// Fire 15 rapid network flap callbacks within 30ms ending in "none" -> debouncer collapses to 1 PAUSED_OFFLINE!
	for i := 0; i < 14; i++ {
		if i%2 == 0 {
			ctrl.NotifyNetworkChange("wifi", false)
		} else {
			ctrl.NotifyNetworkChange("cellular", true)
		}
	}
	ctrl.NotifyNetworkChange("none", false)

	waitUntilCond(t, 2*time.Second, "MT-05 enters PAUSED_OFFLINE", func() bool {
		return ctrl.Snapshot().State == CtrlPausedOffline
	})
	connCountOffline := tr.connects.Load()
	time.Sleep(250 * time.Millisecond)
	if tr.connects.Load() != connCountOffline {
		t.Fatalf("MT-05 workers attempted reconnects while PAUSED_OFFLINE: before=%d after=%d", connCountOffline, tr.connects.Load())
	}

	// Restore on cellular -> cleanly resumes to 2/2 HEALTHY with GuardCalls5Min <= 6!
	ctrl.NotifyNetworkChange("cellular", true)
	waitUntilCond(t, 4*time.Second, "MT-05 recovers to RUNNING 2/2 on cellular", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && s.NetworkType == "cellular"
	})
	if gs := ctrl.Guard().CachedSnapshot(); gs.CallsLast5Min > 6 {
		t.Fatalf("MT-05 WAF budget exceeded: %d > 6", gs.CallsLast5Min)
	}

	ctrl.StopAndWait(4 * time.Second)
	assertGoroutinesClean(t, baseG, 10)
}

// =============================================================================
// MT-06: Adaptive Idle Scaling (ACTIVE -> IDLE_LIGHT -> IDLE_DEEP 2->1) & 0ms Wake-Up
// =============================================================================
func TestMT06_AdaptiveIdleScalingAndZeroMSWakeUp(t *testing.T) {
	baseG := runtime.NumGoroutine()
	tr := &mockTransport{}

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt06-space"
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.EnableIdleParking = true
	cfg.IdleLightAfter = 120 * time.Millisecond
	cfg.IdleDeepAfter = 300 * time.Millisecond
	cfg.IdleMinActiveDwell = 50 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	sup := NewSupervisor(cfg, nil, SupervisorDeps{
		Transport: tr,
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 110 * time.Millisecond, nil
			},
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntilCond(t, 4*time.Second, "MT-06 initial 2/2 HEALTHY", func() bool {
		return sup.State() == StateHealthy && sup.AtomicPoolSnapshot().HealthyWorkers == 2
	})

	// Wait for IDLE_DEEP -> worker #2 parks cleanly with 0 failovers & 0 slow-lane evictions!
	waitUntilCond(t, 3*time.Second, "MT-06 enters IDLE_DEEP and parks tunnel-2", func() bool {
		ps := sup.AtomicPoolSnapshot()
		return ps.PowerState == PowerIdleDeep && ps.HealthyWorkers == 1 && ps.ParkedWorkers == 1
	})
	psIdle := sup.AtomicPoolSnapshot()
	if psIdle.TotalFailovers != 0 || psIdle.SlowLaneEvictions != 0 {
		cancel()
		<-done
		t.Fatalf("MT-06 IDLE_DEEP parking falsely triggered failover/eviction: %+v", psIdle)
	}

	// First incoming SOCKS5 packet succeeds IMMEDIATELY (0ms wake-up) over tunnel-1 AND unparks tunnel-2!
	start := time.Now()
	if err := performSOCKS5DomainEcho(sup.AtomicBoundLocalAddr(), "wake.example.com", 443, []byte("hello-wake"), 2*time.Second); err != nil {
		cancel()
		<-done
		t.Fatalf("MT-06 wake-up transfer failed: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		cancel()
		<-done
		t.Fatalf("MT-06 wake-up transfer stalled (%s) instead of instant tunnel-1 burst", time.Since(start))
	}

	waitUntilCond(t, 4*time.Second, "MT-06 tunnel-2 unparked back to 2/2 HEALTHY", func() bool {
		ps := sup.AtomicPoolSnapshot()
		return ps.PowerState == PowerActive && ps.HealthyWorkers == 2 && ps.ParkedWorkers == 0
	})

	cancel()
	<-done
	assertGoroutinesClean(t, baseG, 10)
}

// =============================================================================
// MT-09: GitHub API Cold-Boot Adaptive Polling (<=4 calls) + Singleflight JWT Refresh + 403 Billing Isolation
// =============================================================================
func TestMT09_GitHubAPIColdBootAndSingleflightJWTRefresh(t *testing.T) {
	var getCalls atomic.Int32
	var startCalls atomic.Int32
	expTime := time.Now().Add(90 * time.Minute).Truncate(time.Second)
	jwt := makeMockJWT(expTime)

	// 1. Local zero-API JWT `exp` parser check.
	parsedExp, ok := ParseJWTExpiryLocally(jwt)
	if !ok || !parsedExp.Equal(expTime.UTC()) {
		t.Fatalf("MT-09 ParseJWTExpiryLocally mismatch: got=%v ok=%v want=%v", parsedExp, ok, expTime)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start"):
			startCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "cold-cs", "state": "Starting"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/user/codespaces/cold-cs"):
			n := getCalls.Add(1)
			state := "Shutdown"
			if n == 2 {
				state = "Starting"
			} else if n >= 3 {
				state = "Available"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":  "cold-cs",
				"state": state,
				"connection": map[string]any{
					"tunnel_properties": map[string]any{
						"connect_access_token": jwt,
						"tunnel_id":            "tun-cold",
						"service_uri":          "https://euw.rel.tunnels.api.visualstudio.com",
					},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/user/codespaces":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"codespaces": []map[string]any{{
					"name": "cold-cs", "state": "Available",
					"owner":   map[string]any{"login": "octo"},
					"machine": map[string]any{"name": "basic", "display_name": "2 cores", "cpus": 2, "memory_in_bytes": int64(8) << 30},
				}},
			})
		case strings.Contains(r.URL.Path, "/billing/usage"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration (missing billing scope)"}`))
		case r.URL.Path == "/login/device/code":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-1", "user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5})
		case r.URL.Path == "/login/oauth/access_token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gho_device_flow_ok", "token_type": "bearer", "scope": "codespace"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.CodespaceName = "cold-cs"
	cfg.GitHubMinCallSpacing = 0
	guard := NewGitHubGuard(cfg, nil, nil)
	api := NewGitHubAPIClient(srv.URL, srv.URL, NewAntiPoisonResolver(nil, nil), guard)
	api.SetColdPollDelays([]time.Duration{15 * time.Millisecond, 15 * time.Millisecond})

	// 2. Singleflight concurrent cold boot across 2 workers -> strictly <= 4 API calls total!
	creds := NewCredentialManager(api, "gho_test", "cold-cs")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := creds.Get(context.Background(), false)
			if err != nil || p.TunnelID != "tun-cold" {
				errs <- fmt.Errorf("creds.Get err=%v p=%+v", err, p)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	totalColdCalls := int(getCalls.Load() + startCalls.Load())
	if totalColdCalls > 4 || startCalls.Load() != 1 {
		t.Fatalf("MT-09 cold boot exceeded 4 calls or raced /start: get=%d start=%d", getCalls.Load(), startCalls.Load())
	}

	// Subsequent call hits cached valid JWT with 0 network calls!
	before := getCalls.Load()
	if _, err := creds.Get(context.Background(), false); err != nil || getCalls.Load() != before {
		t.Fatalf("MT-09 cached JWT triggered unexpected API call")
	}

	// 3. OAuth Device Flow + Quota 403 billing isolation (0 WAF cooldown).
	dStart, err := api.StartDeviceAuth(context.Background(), "cid-123")
	if err != nil || dStart.UserCode != "ABCD-1234" {
		t.Fatalf("MT-09 StartDeviceAuth failed: %+v err=%v", dStart, err)
	}
	dPoll, err := api.PollDeviceAuth(context.Background(), "cid-123", dStart.DeviceCode)
	if err != nil || dPoll.Status != "authorized" || dPoll.AccessToken != "gho_device_flow_ok" {
		t.Fatalf("MT-09 PollDeviceAuth failed: %+v err=%v", dPoll, err)
	}
	qInfo, err := api.CheckQuota(context.Background(), "gho_test", "cold-cs")
	if err != nil || qInfo.CPUs != 2 || qInfo.BillingAvailable || guard.CachedSnapshot().CooldownRemainingMS != 0 {
		t.Fatalf("MT-09 CheckQuota 403 isolation failed: q=%+v err=%v cooldown=%d", qInfo, err, guard.CachedSnapshot().CooldownRemainingMS)
	}
}

// =============================================================================
// MT-10: Anti-Poisoning DNS Resolver (10.10.34.x -> RFC 8484 DoH Fallback) & NAT64 PMTU
// =============================================================================
func TestMT10_DNSPoisoningDetectionAndDoHFallback(t *testing.T) {
	// Mock RFC 8484 wire-format DoH server returning clean public IP 140.82.121.4.
	var dohHits atomic.Int32
	dohSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dohHits.Add(1)
		q, _ := io.ReadAll(r.Body)
		if len(q) < 12 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Echo query header with QR=1, ANCOUNT=1 + answer A record 140.82.121.4.
		resp := append([]byte(nil), q...)
		resp[2] = 0x81
		resp[3] = 0x80
		binary.BigEndian.PutUint16(resp[6:8], 1)
		// Pointer to QNAME at offset 12 (0xC00C), TYPE=A(1), CLASS=IN(1), TTL=60, RDLEN=4, IP=140.82.121.4
		resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 140, 82, 121, 4)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer dohSrv.Close()

	// Poisoned system resolver returning Iranian sinkhole 10.10.34.35!
	poisonedSys := func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.10.34.35")}, nil
	}
	res := NewAntiPoisonResolver([]string{dohSrv.URL}, poisonedSys)
	ips, usedDoH, err := res.ResolveHost(context.Background(), "api.github.com")
	if err != nil || !usedDoH || dohHits.Load() < 1 {
		t.Fatalf("MT-10 expected DoH fallback on 10.10.34.35 poisoning: ips=%v usedDoH=%v hits=%d err=%v", ips, usedDoH, dohHits.Load(), err)
	}
	if len(ips) == 0 || ips[0].String() != "140.82.121.4" {
		t.Fatalf("MT-10 unexpected resolved IP: %v", ips)
	}

	// Verify NAT64 PMTU=576 matrix.
	for _, tc := range []struct {
		ep   string
		want bool
	}{
		{"20.120.56.11:443", true},
		{"[::ffff:20.120.56.11]:443", true},
		{"[64:ff9b::1478:380b]:443", true},
		{"1.1.1.1:443", false},
		{"[2606:4700:4700::1111]:443", false},
	} {
		if got := IsPMTU576RelayIP(tc.ep); got != tc.want {
			t.Fatalf("MT-10 IsPMTU576RelayIP(%q)=%v, want %v", tc.ep, got, tc.want)
		}
	}
}

// =============================================================================
// MT-11: SSH Keepalive Watchdog (Silent CG-NAT Blackhole) & Phase-Locked HeartbeatCoordinator
// =============================================================================
func TestMT11_SSHKeepaliveWatchdogAndPhaseLockedHeartbeat(t *testing.T) {
	baseG := runtime.NumGoroutine()
	stack := startMockDevTunnelStack(t, devTunnelWSProtoV1, true)
	defer stack.Close()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt11-space",
			"state": "Available",
			"connection": map[string]any{
				"tunnel_properties": stack.TunnelProperties(),
			},
		})
	}))
	defer ghSrv.Close()

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt11-space"
	cfg.GitHubToken = "gho_mt11"
	cfg.SSHServerAliveInterval = 1
	cfg.SSHServerAliveCountMax = 2
	cfg.GitHubMinCallSpacing = 0

	hb := NewHeartbeatCoordinator(150 * time.Millisecond)
	defer hb.Close()

	// Verify HeartbeatCoordinator phase-locks 2 subscribers within <25ms.
	ch1, unsub1 := hb.Subscribe()
	ch2, unsub2 := hb.Subscribe()
	defer unsub1()
	defer unsub2()
	var t1, t2 time.Time
	var pwg sync.WaitGroup
	pwg.Add(2)
	go func() { defer pwg.Done(); <-ch1; t1 = time.Now() }()
	go func() { defer pwg.Done(); <-ch2; t2 = time.Now() }()
	pwg.Wait()
	if diff := t1.Sub(t2); diff < -25*time.Millisecond || diff > 25*time.Millisecond {
		t.Fatalf("MT-11 HeartbeatCoordinator not phase-locked: delta=%s", diff)
	}

	// Verify keepalive@openssh.com watchdog detects silent CG-NAT blackhole and terminates session cleanly.
	resolver := NewAntiPoisonResolver(nil, nil)
	api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, resolver, NewGitHubGuard(cfg, nil, nil))
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	tr := NewDevTunnelSSHTransport(cfg, creds, resolver, hb, nil)

	sess, err := tr.Connect(context.Background(), "tunnel-1")
	if err != nil {
		t.Fatalf("MT-11 Connect: %v", err)
	}
	waitUntilCond(t, 2*time.Second, "MT-11 initial keepalive received", func() bool {
		return stack.keepalivesReceived.Load() >= 1
	})

	// Trigger silent CG-NAT blackhole (server stops replying to keepalives).
	stack.blackholeKeepalive.Store(true)
	select {
	case <-sess.Done():
	case <-time.After(4 * time.Second):
		_ = sess.Close()
		t.Fatal("MT-11 keepalive watchdog failed to detect silent CG-NAT blackhole")
	}
	_ = sess.Close()
	hb.Close()
	stack.Close()
	ghSrv.Close()
	assertGoroutinesClean(t, baseG, 8)
}

// =============================================================================
// MT-12: Schmitt-Trigger Hysteresis, Guard-Gated Slow-Lane Eviction & IsGitHubHost Guard
// =============================================================================
func TestMT12_SchmittHysteresisAndSlowLaneEvictionInProcess(t *testing.T) {
	if _, _, err := MeasureUnderlayBaseline(context.Background(), []string{"api.github.com:443"}, 100*time.Millisecond); err == nil {
		t.Fatal("MT-12 MeasureUnderlayBaseline allowed api.github.com")
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.HysteresisDwellWindow = 5 * time.Second
	cfg.HysteresisRelMargin = 0.30
	cfg.HysteresisAbsMargin = 100 * time.Millisecond
	cfg.SlowLaneEvictRatio = 3.5
	cfg.SlowLaneEvictWindow = 10 * time.Second
	cfg.GitHubMinCallSpacing = 0

	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	guard := NewGitHubGuard(cfg, nil, nil)
	guard.nowFn = func() time.Time { return now }

	pool := NewTunnelPool(cfg, &mockTransport{}, nil, nil, guard, PoolHooks{})
	pool.SetUnderlayBaselineMS(200.0)
	w1 := pool.workers[0]
	w2 := pool.workers[1]
	w1.setState(TunnelHealthy)
	w2.setState(TunnelDegraded) // BUG-05 parity: TunnelDegraded slow lanes must also be evicted!
	w1.SetEWMARTT(240 * time.Millisecond)
	w2.SetEWMARTT(4200 * time.Millisecond) // rho = 21.0x

	// Engage 429 cooldown -> CheckSlowLaneEviction MUST divert without destructive eviction!
	guard.RecordFailure("HTTP 429 Too Many Requests\nRetry-After: 60")
	pool.CheckSlowLaneEviction(now)
	if n := pool.CheckSlowLaneEviction(now.Add(15 * time.Second)); n != 0 || !w2.IsSlowLaneDegraded() || w2.IsEvictionTriggered() {
		t.Fatalf("MT-12 expected deferred eviction during 429 cooldown: n=%d slowFlag=%v trig=%v",
			n, w2.IsSlowLaneDegraded(), w2.IsEvictionTriggered())
	}

	// Advance past 429 cooldown -> deferred eviction fires cleanly!
	now = now.Add(75 * time.Second)
	if n := pool.CheckSlowLaneEviction(now); n != 1 || !w2.IsEvictionTriggered() {
		t.Fatalf("MT-12 expected deferred eviction to fire after cooldown: n=%d trig=%v", n, w2.IsEvictionTriggered())
	}

	// Verify Schmitt-trigger dwell anti-flapping.
	w2.setState(TunnelHealthy)
	w2.SetSlowLaneDegraded(false)
	w2.SetEWMARTT(1200 * time.Millisecond)
	pool.EvaluateRoutingMode(now)
	pool.EvaluateRoutingMode(now.Add(4 * time.Second))
	if m, _ := pool.RoutingMode(); m != "balanced" {
		t.Fatalf("MT-12 promoted primary before 5s dwell: %s", m)
	}
	pool.EvaluateRoutingMode(now.Add(6 * time.Second))
	if m, pri := pool.RoutingMode(); m != "primary_preferred" || pri != w1.ID() {
		t.Fatalf("MT-12 expected primary_preferred on %s, got mode=%s pri=%s", w1.ID(), m, pri)
	}
}

// =============================================================================
// MT-13: Android Doze Suspend-to-RAM Clock-Jump Detector (wallDelta - monoDelta > 14s)
// =============================================================================
func TestMT13_SuspendToRAMClockJumpDetection(t *testing.T) {
	baseG := runtime.NumGoroutine()
	var suspendProbeHit atomic.Int32
	var jumpInjected atomic.Bool

	tr := &mockTransport{
		onConn: func(workerID string, seq int64) (*mockWorkerSession, error) {
			s := newMockWorkerSession("20.93.53.155:443")
			s.keepalive = func(_ context.Context) error {
				if jumpInjected.Load() && seq <= 2 {
					suspendProbeHit.Add(1)
					return errors.New("cgnat dropped during suspend")
				}
				return nil
			}
			return s, nil
		},
	}

	var wallOffsetNS atomic.Int64
	cfg := DefaultConfig()
	cfg.CodespaceName = "mt13-space"
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.ProbeInterval = 30 * time.Second // Long normal interval proves suspend jump woke it early!
	cfg.SuspendJumpThreshold = 14 * time.Second
	cfg.BackoffMin = 30 * time.Millisecond
	cfg.BackoffMax = 60 * time.Millisecond

	sup := NewSupervisor(cfg, nil, SupervisorDeps{
		Transport: tr,
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 100 * time.Millisecond, nil
			},
			ClockHook: func() (time.Time, int64) {
				now := time.Now()
				return now, now.UnixNano() + wallOffsetNS.Load()
			},
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntilCond(t, 4*time.Second, "MT-13 initial 2/2 HEALTHY", func() bool {
		return sup.State() == StateHealthy && sup.AtomicPoolSnapshot().HealthyWorkers == 2
	})

	// Simulate 25-second Doze Suspend-to-RAM (wall clock jumps +25s while monotonic clock stays steady).
	jumpInjected.Store(true)
	wallOffsetNS.Store(int64(25 * time.Second))

	waitUntilCond(t, 3*time.Second, "MT-13 suspend clock-jump triggered immediate keepalive + reconnect on BOTH workers", func() bool {
		return suspendProbeHit.Load() >= 2 && tr.connects.Load() >= 4
	})

	cancel()
	<-done
	assertGoroutinesClean(t, baseG, 8)
}

// =============================================================================
// MT-14: Secret Token Redaction, Rotating Flash Log Cap & SetAppForeground Throttle
// =============================================================================
func TestMT14_TokenRedactionLogRotationAndAppForegroundThrottle(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rot.log")

	// Small 4 KiB rotation threshold to verify size-capped flash log rotation.
	logger, err := NewEventLogger(logPath, 4096)
	if err != nil {
		t.Fatalf("MT-14 NewEventLogger: %v", err)
	}
	rb := NewTerminalRingBuffer()
	logger.SetObserver(func(rec LogRecord) {
		sev, line := FormatLogRecord(rec)
		rb.Append(sev, line)
	})

	secrets := []string{
		"gho_SuperSecretToken1234567890",
		"ghp_AnotherSecretPAT0987654321",
		"github_pat_11ABCDEFGH_0123456789abcdef",
		"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5MDAwMDAwMDB9.SecretSignatureValue",
	}
	for i := 0; i < 60; i++ {
		logger.Log("TEST_REDACT", map[string]any{
			"error":         fmt.Sprintf("auth failed Bearer %s tunnel %s seq=%d", secrets[i%len(secrets)], secrets[(i+1)%len(secrets)], i),
			"connect_token": secrets[0],
		})
	}
	_ = logger.Close()

	// Verify 0 secret leakage in TerminalRingBuffer AND on disk (both active and rotated .1 file).
	for _, ln := range rb.Since(0) {
		for _, sec := range secrets {
			if strings.Contains(ln.Text, sec) {
				t.Fatalf("MT-14 secret leaked into TerminalRingBuffer: %s", ln.Text)
			}
		}
	}
	for _, p := range []string{logPath, logPath + ".1"} {
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			continue
		}
		for _, sec := range secrets {
			if strings.Contains(string(data), sec) {
				t.Fatalf("MT-14 secret leaked into disk log %s", p)
			}
		}
	}
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("MT-14 expected rotated backup file %s.1 to exist under 4KiB cap", logPath)
	}

	// Verify SetAppForeground(false) suppresses live OnLogLine JNI callbacks while still retaining ring buffer!
	var cbLogHits atomic.Int32
	cfg := DefaultConfig()
	cfg.CodespaceName = "mt14-space"
	cfg.LocalPort = 0
	ctrl := NewSessionController(cfg, ControllerCallbacks{
		OnLogLine: func(int64, string, string) { cbLogHits.Add(1) },
	}, ControllerOverrides{})

	ctrl.SetAppForeground(true)
	ctrl.Logs().Append(LogInfo, "fg-line-1")
	if cbLogHits.Load() != 1 {
		t.Fatalf("MT-14 expected 1 callback in foreground, got %d", cbLogHits.Load())
	}
	ctrl.SetAppForeground(false)
	ctrl.Logs().Append(LogInfo, "bg-line-2")
	if cbLogHits.Load() != 1 {
		t.Fatalf("MT-14 expected 0 callbacks while backgrounded, got %d", cbLogHits.Load())
	}
	if len(ctrl.Logs().Since(0)) != 2 {
		t.Fatalf("MT-14 expected ring buffer to still retain background lines for catch-up")
	}
}

// =============================================================================
// MT-19: Live GitHub camelCase `tunnelProperties`, Cold-Boot Budget <=5/6, & Singleflight Cache
// =============================================================================
func TestMT19_CamelCaseTunnelPropertiesColdBootBudgetAndCachedRetry(t *testing.T) {
	var getCalls, startCalls atomic.Int32
	expTime := time.Now().Add(45 * time.Minute).Truncate(time.Second)
	jwt := makeMockJWT(expTime)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start"):
			startCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "p5-camel-cs", "state": "Queued"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/user/codespaces/p5-camel-cs"):
			n := getCalls.Add(1)
			state := "Shutdown"
			switch {
			case n == 2:
				state = "Starting"
			case n == 3:
				state = "Starting"
			case n >= 4:
				state = "Available"
			}
			payload := map[string]any{
				"name":  "p5-camel-cs",
				"state": state,
			}
			if state == "Available" {
				payload["connection"] = map[string]any{
					"tunnelProperties": map[string]any{
						"connectAccessToken":     jwt,
						"managePortsAccessToken": "mgt_camel_secret",
						"serviceUri":             "https://global.rel.tunnels.api.visualstudio.com/",
						"tunnelId":               "camel-tun-99",
						"clusterId":              "usw2",
						"domain":                 "app.github.dev",
						"hostPublicKeys":         []string{"AAAAC3NzaC1lZDI1NTE5AAAAIMockKey"},
					},
				}
			}
			_ = json.NewEncoder(w).Encode(payload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.CodespaceName = "p5-camel-cs"
	cfg.GitHubToken = "gho_camel_secret_token"
	cfg.GitHubMinCallSpacing = 0
	guard := NewGitHubGuard(cfg, nil, nil)
	api := NewGitHubAPIClient(srv.URL, srv.URL, NewAntiPoisonResolver(nil, nil), guard)
	if len(api.coldPollWait) < 3 {
		t.Fatalf("MT-19 expected 3 adaptive coldPollWait intervals, got %d", len(api.coldPollWait))
	}
	api.SetColdPollDelays([]time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond})

	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := creds.Get(context.Background(), false)
			if err != nil {
				errs <- err
				return
			}
			if p.ConnectAccessToken != jwt || p.TunnelID != "camel-tun-99" || p.ClusterID != "usw2" || p.ServiceURI == "" {
				errs <- fmt.Errorf("unexpected camelCase TunnelProperties: %+v", p)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("MT-19: %v", err)
	}
	totalCalls := int(getCalls.Load() + startCalls.Load())
	if totalCalls > 5 || startCalls.Load() != 1 {
		t.Fatalf("MT-19 cold boot exceeded 5-call WAF budget or missed single start: get=%d start=%d", getCalls.Load(), startCalls.Load())
	}

	// Second worker calling Get(false) must consume 0 GitHub API calls while cached JWT is fresh.
	beforeGet := getCalls.Load()
	if _, err := creds.Get(context.Background(), false); err != nil || getCalls.Load() != beforeGet {
		t.Fatalf("MT-19 expected 0 extra API calls on cached JWT")
	}

	// Verify normalized cluster routing from global.rel -> <clusterId>.rel (dt_manager.go parity).
	gotClusterURL := normalizeDevTunnelsAPIBase("https://global.rel.tunnels.api.visualstudio.com/", "usw2")
	if gotClusterURL != "https://usw2.rel.tunnels.api.visualstudio.com" {
		t.Fatalf("MT-19 normalizeDevTunnelsAPIBase mismatch: got=%q", gotClusterURL)
	}
	gotExplicitURL := normalizeDevTunnelsAPIBase("https://euw.rel.tunnels.api.visualstudio.com/api/v1/", "euw")
	if gotExplicitURL != "https://euw.rel.tunnels.api.visualstudio.com" {
		t.Fatalf("MT-19 expected /api/v1 stripped cleanly, got=%q", gotExplicitURL)
	}
}

// =============================================================================
// MT-20: DevTunnels Canonical Paths, Base64 Wire hostPublicKeys, 16634 Bearer Auth, Stage Logs & Redaction
// =============================================================================
func TestMT20_DevTunnelBase64HostKeysAndStageDiagnosticsAndRedaction(t *testing.T) {
	baseG := runtime.NumGoroutine()
	stack := startMockDevTunnelStack(t, devTunnelWSProtoV1, false)
	stack.useRawB64HostKey.Store(true) // Real Microsoft Dev Tunnels format (no "ssh-ed25519 " prefix!)
	defer stack.Close()

	// Verify buildOuterHostKeyCallback rejects wrong keys and accepts raw base64 wire keys.
	_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
	badSigner, _ := ssh.NewSignerFromKey(badPriv)
	rawValidB64 := base64.StdEncoding.EncodeToString(stack.outerHostKey.PublicKey().Marshal())
	cb, parsedN := buildOuterHostKeyCallback([]string{rawValidB64})
	if parsedN != 1 {
		t.Fatalf("MT-20 expected 1 parsed raw base64 host key, got %d", parsedN)
	}
	if err := cb("relay", nil, stack.outerHostKey.PublicKey()); err != nil {
		t.Fatalf("MT-20 valid outer host key rejected: %v", err)
	}
	if err := cb("relay", nil, badSigner.PublicKey()); err == nil {
		t.Fatal("MT-20 expected mismatched outer host key to be rejected")
	}

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := stack.TunnelProperties()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt20-space",
			"state": "Available",
			"connection": map[string]any{
				"tunnelProperties": map[string]any{
					"connectAccessToken":     p.ConnectAccessToken,
					"managePortsAccessToken": p.ManagePortsAccessToken,
					"serviceUri":             p.ServiceURI,
					"tunnelId":               p.TunnelID,
					"clusterId":              p.ClusterID,
					"domain":                 p.Domain,
				},
			},
		})
	}))
	defer ghSrv.Close()

	dir := t.TempDir()
	logger, err := NewEventLogger(filepath.Join(dir, "events.jsonl"), 256*1024)
	if err != nil {
		t.Fatalf("MT-20 logger: %v", err)
	}
	rb := NewTerminalRingBuffer()
	logger.SetObserver(func(rec LogRecord) {
		sev, line := FormatLogRecord(rec)
		rb.Append(sev, line)
	})

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt20-space"
	cfg.GitHubToken = "gho_mt20_super_secret_oauth_token"
	cfg.GitHubAPIBaseURL = ghSrv.URL
	cfg.LocalPort = 0
	cfg.PoolSize = 1
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.GitHubMinCallSpacing = 0

	resolver := NewAntiPoisonResolver(nil, nil)
	guard := NewGitHubGuard(cfg, logger, nil)
	api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, resolver, guard)
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	creds.SetLogger(logger)
	hb := NewHeartbeatCoordinator(2 * time.Second)
	defer hb.Close()
	tr := NewDevTunnelSSHTransport(cfg, creds, resolver, hb, logger)

	sess, err := tr.Connect(context.Background(), "tunnel-1")
	if err != nil {
		_ = logger.Close()
		t.Fatalf("MT-20 Connect failed: %v", err)
	}
	defer sess.Close()

	if !stack.tcpipForwardReplyOk.Load() {
		t.Fatal("MT-20 expected 4-byte PortForwardSuccess uint32 reply to tcpip-forward")
	}
	if !stack.rpcAuthBearerSeen.Load() {
		t.Fatal("MT-20 expected Authorization: Bearer token on port 16634 h2c gRPC call")
	}
	if !stack.portPutCalled.Load() || !stack.portPutIfNoneMatch.Load() || !stack.portPutProtocolHTTP.Load() {
		t.Fatalf("MT-20 expected PUT /tunnels/.../ports/2222 with If-None-Match:* & protocol=http (called=%v inm=%v proto=%v)",
			stack.portPutCalled.Load(), stack.portPutIfNoneMatch.Load(), stack.portPutProtocolHTTP.Load())
	}

	_ = sess.Close()
	hb.Close()
	_ = logger.Close()

	lines := rb.Since(0)
	var sawStages [8]bool
	secrets := []string{cfg.GitHubToken, stack.connectToken, stack.manageToken}
	for _, ln := range lines {
		for _, sec := range secrets {
			if sec != "" && strings.Contains(ln.Text, sec) {
				t.Fatalf("MT-20 secret leaked in terminal log: %s", ln.Text)
			}
		}
		for s := 1; s <= 7; s++ {
			if strings.Contains(ln.Text, fmt.Sprintf("[Boot %d/7]", s)) {
				sawStages[s] = true
			}
		}
	}
	for s := 1; s <= 7; s++ {
		if !sawStages[s] {
			t.Fatalf("MT-20 missing stage log [Boot %d/7] in ring buffer", s)
		}
	}
	// Verify RedactSecrets handles camelCase JSON secret fields & URL query token params.
	rawSample := `{"connectAccessToken":"tokSecret99"}&access_token=abc12345678&token=xyzSecret000 tunnel ` + stack.connectToken
	redacted := RedactSecrets(rawSample)
	if strings.Contains(redacted, "tokSecret99") || strings.Contains(redacted, "abc12345678") ||
		strings.Contains(redacted, "xyzSecret000") || strings.Contains(redacted, stack.connectToken) {
		t.Fatalf("MT-20 RedactSecrets failed to scrub camelCase/query/tunnel secrets: %s", redacted)
	}

	stack.Close()
	ghSrv.Close()
	assertGoroutinesClean(t, baseG, 10)
}

// =============================================================================
// MT-21: Available Empty `tunnelProperties` Fail-Fast + Sole Cellular Gate + Failure Logs
// =============================================================================
func TestMT21_EmptyTunnelPropertiesFailFastAndNoSilentConnectErrors(t *testing.T) {
	baseG := runtime.NumGoroutine()
	var getCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/user/codespaces/empty-props-cs") {
			getCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":       "empty-props-cs",
				"state":      "Available",
				"connection": map[string]any{"tunnelProperties": map[string]any{}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	logger, _ := NewEventLogger(filepath.Join(t.TempDir(), "mt21.jsonl"), 128*1024)
	rb := NewTerminalRingBuffer()
	logger.SetObserver(func(rec LogRecord) {
		sev, line := FormatLogRecord(rec)
		rb.Append(sev, line)
	})

	cfg := DefaultConfig()
	cfg.CodespaceName = "empty-props-cs"
	cfg.GitHubToken = "ghp_limited_pat_secret_123456"
	cfg.GitHubMinCallSpacing = 0
	guard := NewGitHubGuard(cfg, logger, nil)
	api := NewGitHubAPIClient(srv.URL, srv.URL, NewAntiPoisonResolver(nil, nil), guard)
	api.SetColdPollDelays([]time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond})
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	creds.SetLogger(logger)

	_, err := creds.Get(context.Background(), false)
	var fatalErr *FatalBootError
	if !errors.As(err, &fatalErr) || fatalErr.Code != "missing_tunnel_props" {
		t.Fatalf("MT-21 expected FatalBootError(missing_tunnel_props), got err=%v", err)
	}
	if getCalls.Load() != 2 {
		t.Fatalf("MT-21 expected strictly 2 API calls (initial + 1 verify) on empty Available props, got %d", getCalls.Load())
	}

	// Verify sole cellular worker (underlay=101ms, RTT=380ms -> rho=3.76 > 3.5, peerMedian=0)
	// accepts on attempt 1 WITHOUT discarding valid tunnels twice, AND non-fatal Connect errors log WORKER_BOOT_FAIL.
	var connectAttempts atomic.Int32
	tr := &mockTransport{
		onConn: func(workerID string, seq int64) (*mockWorkerSession, error) {
			if connectAttempts.Add(1) == 1 {
				return nil, errors.New("[3/7 wss dial http=502] simulated bad gateway tunnel " + "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5MDAwMDAwMDB9.LeakTestSig")
			}
			return newMockWorkerSession("20.120.56.11:443"), nil
		},
	}
	bootCfg := DefaultConfig()
	bootCfg.BootQualitySamples = 2
	bootCfg.BootQualityMaxRetries = 2
	bootCfg.BootQualityMaxRTT = 1000 * time.Millisecond
	bootCfg.BootMicroPayloadCheck = true
	ti := NewTunnelInstance(
		"tunnel-1",
		bootCfg,
		tr,
		func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error) {
			return 380 * time.Millisecond, nil // rho = 380 / 101 = 3.76 > 3.5!
		},
		func(context.Context, WorkerSession, string, time.Duration) (time.Duration, error) {
			return 385 * time.Millisecond, nil
		},
		logger,
		nil,
		guard,
	)
	ti.sampleDel = time.Millisecond
	ti.retryDel = time.Millisecond
	if _, _, err := ti.BootAndQualify(context.Background(), func(string) float64 { return 0 }, func() float64 { return 101.0 }); err == nil {
		t.Fatal("MT-21 expected attempt 1 Connect error to surface and log")
	}
	sess, rep, err := ti.BootAndQualify(context.Background(), func(string) float64 { return 0 }, func() float64 { return 101.0 })
	if err != nil {
		t.Fatalf("MT-21 sole cellular worker failed instead of accepting on attempt 1: %v", err)
	}
	_ = sess.Close()
	if connectAttempts.Load() != 2 {
		t.Fatalf("MT-21 expected 1 failed + 1 sole cellular accept (2 Connect calls), got %d (P50=%dms rho=%.2f)", connectAttempts.Load(), rep.P50MS, rep.RelativeRho)
	}

	_ = logger.Close()
	var sawPropsMissing, sawBootFail, sawBootOK bool
	for _, ln := range rb.Since(0) {
		if strings.Contains(ln.Text, "LeakTestSig") || strings.Contains(ln.Text, cfg.GitHubToken) {
			t.Fatalf("MT-21 secret leaked in log: %s", ln.Text)
		}
		if strings.Contains(ln.Text, "missing tunnelProperties") {
			sawPropsMissing = true
		}
		if strings.Contains(ln.Text, "[Boot] tunnel-1 failed:") {
			sawBootFail = true
		}
		if strings.Contains(ln.Text, "[Boot] tunnel-1 online") {
			sawBootOK = true
		}
	}
	if !sawPropsMissing || !sawBootFail || !sawBootOK {
		t.Fatalf("MT-21 missing expected diagnostics: props=%v fail=%v ok=%v", sawPropsMissing, sawBootFail, sawBootOK)
	}
	srv.Close()
	assertGoroutinesClean(t, baseG, 8)
}

// =============================================================================
// MT-22: Stale tunnel_id HTTP 404 Auto-Wake + Singleflight + Zero-Clobber Epoch CAS
// =============================================================================
func TestMT22_StaleTunnelHTTP404AutoWakeAndZeroClobber(t *testing.T) {
	baseG := runtime.NumGoroutine()
	stack := startMockDevTunnelStack(t, devTunnelWSProtoV1, true)
	defer stack.Close()

	var currentTID atomic.Value
	currentTID.Store("old-tunnel-A")
	var vmShutdown atomic.Bool
	var vmStarting atomic.Bool
	var startCalls atomic.Int32
	var getCalls atomic.Int32
	jwt := makeMockJWT(time.Now().Add(2 * time.Hour))

	stack.mu.Lock()
	stack.restStatusFn = func(tid string) int {
		if vmShutdown.Load() && tid == "old-tunnel-A" {
			return http.StatusNotFound
		}
		return http.StatusOK
	}
	stack.mu.Unlock()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start"):
			startCalls.Add(1)
			vmStarting.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "mt22-space", "state": "Starting"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/user/codespaces/mt22-space"):
			getCalls.Add(1)
			state := "Available"
			if vmShutdown.Load() {
				if vmStarting.Swap(false) {
					vmShutdown.Store(false)
					currentTID.Store("new-tunnel-B")
					state = "Available"
				} else {
					state = "Shutdown"
				}
			}
			tid := currentTID.Load().(string)
			payload := map[string]any{
				"name":  "mt22-space",
				"state": state,
			}
			if state == "Available" {
				payload["connection"] = map[string]any{
					"tunnelProperties": map[string]any{
						"connectAccessToken":     stack.connectToken,
						"managePortsAccessToken": stack.manageToken,
						"serviceUri":             stack.srv.URL,
						"tunnelId":               tid,
						"clusterId":              "euw",
						"domain":                 "euw.devtunnels.ms",
					},
				}
			}
			_ = json.NewEncoder(w).Encode(payload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	// Part A: Direct Epoch-CAS Zero-Clobber check (delayed worker 2 carrying gen=1 MUST NOT clobber gen=2).
	var partAGet atomic.Int32
	var partATID atomic.Value
	partATID.Store("old-tunnel-A")
	partASrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		partAGet.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt22-cas",
			"state": "Available",
			"connection": map[string]any{
				"tunnelProperties": map[string]any{
					"connectAccessToken": jwt,
					"serviceUri":         "https://euw.rel.tunnels.api.visualstudio.com",
					"tunnelId":           partATID.Load().(string),
					"clusterId":          "euw",
				},
			},
		})
	}))
	defer partASrv.Close()

	casCfg := DefaultConfig()
	casCfg.CodespaceName = "mt22-cas"
	casCfg.GitHubMinCallSpacing = 0
	casAPI := NewGitHubAPIClient(partASrv.URL, partASrv.URL, NewAntiPoisonResolver(nil, nil), NewGitHubGuard(casCfg, nil, nil))
	casCreds := NewCredentialManager(casAPI, "gho_cas", "mt22-cas")
	casCreds.SetMinInvalidateCooldown(10 * time.Millisecond)

	p1, g1, err := casCreds.GetWithGen(context.Background(), false)
	if err != nil || p1.TunnelID != "old-tunnel-A" || g1 != 1 {
		t.Fatalf("MT-22A initial GetWithGen failed: tid=%s gen=%d err=%v", p1.TunnelID, g1, err)
	}
	inv1, _ := casCreds.InvalidateIfMatch(g1, "http_404")
	if !inv1 {
		t.Fatal("MT-22A expected gen=1 invalidation to succeed")
	}
	partATID.Store("new-tunnel-B")
	p2, g2, err := casCreds.GetWithGen(context.Background(), true)
	if err != nil || p2.TunnelID != "new-tunnel-B" || g2 != 2 {
		t.Fatalf("MT-22A refresh GetWithGen failed: tid=%s gen=%d err=%v", p2.TunnelID, g2, err)
	}
	// Delayed worker 2 arrives late with stale gen=1!
	if invLate, coolLate := casCreds.InvalidateIfMatch(g1, "http_404"); invLate || coolLate != 0 {
		t.Fatalf("MT-22A delayed worker clobbered gen=2! inv=%v cool=%s", invLate, coolLate)
	}
	beforeGet := partAGet.Load()
	pCur, gCur, err := casCreds.GetWithGen(context.Background(), false)
	if err != nil || pCur.TunnelID != "new-tunnel-B" || gCur != 2 || partAGet.Load() != beforeGet {
		t.Fatalf("MT-22A expected cached new-tunnel-B gen=2 with 0 API calls, got tid=%s gen=%d callsDelta=%d",
			pCur.TunnelID, gCur, partAGet.Load()-beforeGet)
	}

	// Part B: Full Supervisor 2/2 recovery replay of 10.txt / 18.txt HTTP 404 stale tunnel.
	cfg := DefaultConfig()
	cfg.CodespaceName = "mt22-space"
	cfg.GitHubToken = "gho_mt22_secret"
	cfg.GitHubAPIBaseURL = ghSrv.URL
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.BackoffMin = 25 * time.Millisecond
	cfg.BackoffMax = 60 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	res := NewAntiPoisonResolver(nil, nil)
	guard := NewGitHubGuard(cfg, nil, nil)
	api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, res, guard)
	api.SetColdPollDelays([]time.Duration{15 * time.Millisecond, 15 * time.Millisecond, 15 * time.Millisecond})
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	creds.SetMinInvalidateCooldown(25 * time.Millisecond)
	hb := NewHeartbeatCoordinator(2 * time.Second)
	defer hb.Close()
	tr := NewDevTunnelSSHTransport(cfg, creds, res, hb, nil)

	sup := NewSupervisor(cfg, nil, SupervisorDeps{
		Transport:   tr,
		GitHubGuard: guard,
		PoolHooks:   PoolHooks{SampleDelay: 5 * time.Millisecond, RetryDelay: 10 * time.Millisecond},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntilCond(t, 5*time.Second, "MT-22 initial 2/2 healthy on old-tunnel-A", func() bool {
		return sup.State() == StateHealthy && sup.AtomicPoolSnapshot().HealthyWorkers == 2
	})

	// Simulate Windows shutting down the Codespace while Android is connected.
	getCalls.Store(0)
	startCalls.Store(0)
	vmShutdown.Store(true)
	stack.DropAllSessions()

	waitUntilCond(t, 6*time.Second, "MT-22 auto-wake recovery to 2/2 healthy on new-tunnel-B", func() bool {
		return currentTID.Load().(string) == "new-tunnel-B" &&
			sup.State() == StateHealthy &&
			sup.AtomicPoolSnapshot().HealthyWorkers == 2
	})

	if startCalls.Load() != 1 {
		cancel()
		<-done
		t.Fatalf("MT-22 expected exactly 1 singleflight POST /start during dual-worker 404 storm, got %d", startCalls.Load())
	}
	if gs := guard.CachedSnapshot(); gs.CallsLast5Min > 6 {
		cancel()
		<-done
		t.Fatalf("MT-22 WAF 5m budget exceeded: %d > 6", gs.CallsLast5Min)
	}
	if err := performSOCKS5DomainEcho(sup.AtomicBoundLocalAddr(), "recovered-mt22.example.com", 443, []byte("mt22-ok"), 3*time.Second); err != nil {
		cancel()
		<-done
		t.Fatalf("MT-22 post-recovery SOCKS5 echo failed: %v", err)
	}

	cancel()
	<-done
	hb.Close()
	stack.Close()
	ghSrv.Close()
	assertGoroutinesClean(t, baseG, 10)
}

// =============================================================================
// MT-23: Dead-VM StartRemoteServerAsync Rejected + Consecutive Deadline Exceeded + WAN Negative Guard
// =============================================================================
func TestMT23_DeadVMRPCRejectionAndConsecutiveDeadlineInvalidation(t *testing.T) {
	baseG := runtime.NumGoroutine()
	stack := startMockDevTunnelStack(t, devTunnelWSProtoV1, true)
	defer stack.Close()

	var currentTID atomic.Value
	currentTID.Store("rpc-dead-A")
	var ghGetCalls atomic.Int32

	stack.mu.Lock()
	stack.rpcFaultFn = func(_ int) (string, string, string) {
		switch currentTID.Load().(string) {
		case "rpc-dead-A":
			return "", "", "Please check if an SSH server is installed in the container."
		case "rpc-zombie-C":
			return "4", "Deadline Exceeded", ""
		default:
			return "", "", ""
		}
	}
	stack.mu.Unlock()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghGetCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt23-space",
			"state": "Available",
			"connection": map[string]any{
				"tunnelProperties": map[string]any{
					"connectAccessToken":     stack.connectToken,
					"managePortsAccessToken": stack.manageToken,
					"serviceUri":             stack.srv.URL,
					"tunnelId":               currentTID.Load().(string),
					"clusterId":              "euw",
					"domain":                 "euw.devtunnels.ms",
				},
			},
		})
	}))
	defer ghSrv.Close()

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt23-space"
	cfg.GitHubToken = "gho_mt23"
	cfg.GitHubMinCallSpacing = 0

	res := NewAntiPoisonResolver(nil, nil)
	guard := NewGitHubGuard(cfg, nil, nil)
	api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, res, guard)
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	creds.SetMinInvalidateCooldown(0)
	tr := NewDevTunnelSSHTransport(cfg, creds, res, nil, nil)

	// Part A: StartRemoteServerAsync rejected -> invalidates gen=1 immediately -> next Connect refreshes to rpc-fresh-B.
	if _, err := tr.Connect(context.Background(), "tunnel-1"); err == nil || !strings.Contains(err.Error(), "StartRemoteServerAsync rejected") {
		t.Fatalf("MT-23A expected StartRemoteServerAsync rejected, got: %v", err)
	}
	currentTID.Store("rpc-fresh-B")
	sessB, err := tr.Connect(context.Background(), "tunnel-1")
	if err != nil {
		t.Fatalf("MT-23A expected recovery on rpc-fresh-B, got: %v", err)
	}
	_ = sessB.Close()

	// Part B: Consecutive grpc status 4: Deadline Exceeded -> 1st failure does NOT invalidate; 2nd DOES invalidate.
	creds2 := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	creds2.SetMinInvalidateCooldown(0)
	tr2 := NewDevTunnelSSHTransport(cfg, creds2, res, nil, nil)
	currentTID.Store("rpc-zombie-C")
	ghBefore := ghGetCalls.Load()

	if _, err := tr2.Connect(context.Background(), "tunnel-1"); err == nil || !strings.Contains(err.Error(), "grpc status 4") {
		t.Fatalf("MT-23B attempt 1 expected grpc status 4, got: %v", err)
	}
	if _, gAfter1, _ := creds2.GetWithGen(context.Background(), false); gAfter1 != 1 || ghGetCalls.Load() != ghBefore+1 {
		t.Fatalf("MT-23B expected gen=1 preserved after single Deadline Exceeded, got gen=%d calls=%d", gAfter1, ghGetCalls.Load()-ghBefore)
	}

	if _, err := tr2.Connect(context.Background(), "tunnel-2"); err == nil || !strings.Contains(err.Error(), "grpc status 4") {
		t.Fatalf("MT-23B attempt 2 expected grpc status 4, got: %v", err)
	}
	currentTID.Store("rpc-fresh-D")
	sessD, err := tr2.Connect(context.Background(), "tunnel-1")
	if err != nil {
		t.Fatalf("MT-23B expected recovery after 2nd consecutive Deadline Exceeded, got: %v", err)
	}
	_ = sessD.Close()
	if _, gFinal, _ := creds2.GetWithGen(context.Background(), false); gFinal != 2 {
		t.Fatalf("MT-23B expected credential generation advanced to 2, got %d", gFinal)
	}

	// Part C (Negative Guard): Local WAN connection-refused / dial errors NEVER invalidate credentials!
	deadPortLn, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := deadPortLn.Addr().String()
	_ = deadPortLn.Close()
	ghDeadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghGetCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt23-wan",
			"state": "Available",
			"connection": map[string]any{
				"tunnelProperties": map[string]any{
					"connectAccessToken": stack.connectToken,
					"serviceUri":         "http://" + deadAddr,
					"tunnelId":           "wan-only-tun",
					"clusterId":          "euw",
				},
			},
		})
	}))
	defer ghDeadSrv.Close()
	apiDead := NewGitHubAPIClient(ghDeadSrv.URL, ghDeadSrv.URL, res, NewGitHubGuard(cfg, nil, nil))
	credsWAN := NewCredentialManager(apiDead, cfg.GitHubToken, "mt23-wan")
	credsWAN.SetMinInvalidateCooldown(0)
	trWAN := NewDevTunnelSSHTransport(cfg, credsWAN, res, nil, nil)

	callsBeforeWAN := ghGetCalls.Load()
	for i := 0; i < 3; i++ {
		if _, err := trWAN.Connect(context.Background(), "tunnel-1"); err == nil {
			t.Fatal("MT-23C expected local WAN dial failure")
		}
	}
	if delta := ghGetCalls.Load() - callsBeforeWAN; delta != 1 {
		t.Fatalf("MT-23C local WAN error caused %d GitHub API calls (want strictly 1 initial fetch, 0 invalidations)", delta)
	}

	stack.Close()
	ghSrv.Close()
	assertGoroutinesClean(t, baseG, 10)
}

// =============================================================================
// MT-24: Iranian CSFB Phone Call (Brief Dropout + Same-Type Refresh + Hung Boot Abort + Broadcast Wake)
// =============================================================================
func TestMT24_PhoneCallCSFBAndBriefDropoutHandoverRecovery(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// Part A & B: Brief <150ms dropout inside debounce window AND same-type "cellular"->"cellular" refresh.
	tr := &mockTransport{}
	cfg := DefaultConfig()
	cfg.CodespaceName = "mt24-csfb"
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.NetworkDebounceInterval = 90 * time.Millisecond
	cfg.BackoffMin = 20 * time.Millisecond
	cfg.BackoffMax = 40 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	ctrl := NewSessionController(cfg, ControllerCallbacks{}, ControllerOverrides{
		TransportFactory: func(_ Config, _ *CredentialManager, _ *AntiPoisonResolver, _ *HeartbeatCoordinator, _ *EventLogger) WorkerTransport {
			return tr
		},
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 110 * time.Millisecond, nil
			},
		},
		SnapshotInterval: 40 * time.Millisecond,
	})
	ctrl.Start()

	ctrl.NotifyNetworkChange("cellular", true)
	waitUntilCond(t, 4*time.Second, "MT-24 initial 2/2 on cellular", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && s.NetworkType == "cellular"
	})
	if got := tr.connects.Load(); got != 2 {
		ctrl.StopAndWait(4 * time.Second)
		t.Fatalf("MT-24 initial NotifyNetworkChange must NOT trigger spurious handover reconnect: connects=%d", got)
	}

	// Part A: Brief dropout "none" -> 30ms -> "cellular" coalesced inside 90ms debounce!
	beforeA := tr.connects.Load()
	ctrl.NotifyNetworkChange("none", false)
	time.Sleep(30 * time.Millisecond)
	ctrl.NotifyNetworkChange("cellular", true)
	waitUntilCond(t, 3*time.Second, "MT-24A both workers reconnect after brief dropout", func() bool {
		s := ctrl.Snapshot()
		return tr.connects.Load() >= beforeA+2 && s.State == CtrlRunning && s.HealthyWorkers == 2
	})

	// Part B: Same-type interface refresh ("cellular" -> "cellular" from Android networkHandle/IP swap).
	beforeB := tr.connects.Load()
	ctrl.NotifyNetworkChange("cellular", true)
	waitUntilCond(t, 3*time.Second, "MT-24B both workers reconnect on same-type CSFB cellular refresh", func() bool {
		s := ctrl.Snapshot()
		return tr.connects.Load() >= beforeB+2 && s.State == CtrlRunning && s.HealthyWorkers == 2
	})
	if ctrl.Guard().CachedSnapshot().CallsLast5Min != 0 {
		ctrl.StopAndWait(4 * time.Second)
		t.Fatalf("MT-24A/B handovers must consume 0 GitHub API calls, got %d", ctrl.Guard().CachedSnapshot().CallsLast5Min)
	}
	ctrl.StopAndWait(4 * time.Second)

	// Part C: Hung 60s boot abort (<500ms) on tunnel-1 + 15s backoff broadcast wake on tunnel-2.
	var phase atomic.Int32 // 0=initial ok, 1=tunnel-1 hangs & tunnel-2 fails into 15s backoff, 2=wifi handover ok
	hungEntered := make(chan struct{}, 4)
	t2FailedOnce := make(chan struct{}, 4)
	var t1Once, t2Once sync.Once

	trC := &mockTransport{
		onConn: func(workerID string, seq int64) (*mockWorkerSession, error) {
			if phase.Load() == 1 {
				if workerID == "tunnel-1" {
					t1Once.Do(func() { close(hungEntered) })
					return nil, errors.New("unreachable")
				}
				t2Once.Do(func() { close(t2FailedOnce) })
				return nil, errors.New("simulated cellular drop into backoff")
			}
			return newMockWorkerSession("20.93.53.155:443"), nil
		},
	}
	// Wrap mockTransport so tunnel-1 blocks on ctx.Done() in phase 1!
	hungTr := &ctxAwareFuncTransport{
		fn: func(ctx context.Context, workerID string) (WorkerSession, error) {
			if phase.Load() == 1 && workerID == "tunnel-1" {
				t1Once.Do(func() { close(hungEntered) })
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return trC.Connect(ctx, workerID)
		},
	}

	cfgC := DefaultConfig()
	cfgC.CodespaceName = "mt24-hung"
	cfgC.LocalPort = 0
	cfgC.PoolSize = 2
	cfgC.BootQualitySamples = 1
	cfgC.BootMicroPayloadCheck = false
	cfgC.StopOnExit = false
	cfgC.NetworkDebounceInterval = 60 * time.Millisecond
	cfgC.BackoffMin = 15 * time.Second
	cfgC.BackoffMax = 30 * time.Second
	cfgC.GitHubMinCallSpacing = 0

	ctrlC := NewSessionController(cfgC, ControllerCallbacks{}, ControllerOverrides{
		TransportFactory: func(_ Config, _ *CredentialManager, _ *AntiPoisonResolver, _ *HeartbeatCoordinator, _ *EventLogger) WorkerTransport {
			return hungTr
		},
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 95 * time.Millisecond, nil
			},
		},
		SnapshotInterval: 30 * time.Millisecond,
	})
	ctrlC.NotifyNetworkChange("cellular", true)
	ctrlC.Start()
	defer ctrlC.StopAndWait(4 * time.Second)

	waitUntilCond(t, 4*time.Second, "MT-24C initial 2/2 healthy", func() bool {
		s := ctrlC.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && s.NetworkType == "cellular"
	})

	// Trigger phase 1 via CSFB cellular glitch handover: tunnel-1 hangs in dial, tunnel-2 fails and sleeps in 15s backoff.
	phase.Store(1)
	ctrlC.NotifyNetworkChange("cellular", true)
	select {
	case <-hungEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("MT-24C tunnel-1 did not enter hung Connect")
	}
	select {
	case <-t2FailedOnce:
	case <-time.After(3 * time.Second):
		t.Fatal("MT-24C tunnel-2 did not fail into 15s backoff")
	}
	time.Sleep(80 * time.Millisecond) // Ensure tunnel-2 is asleep inside 15s backoff timer.

	// Trigger handover to Wi-Fi! Both hung tunnel-1 AND 15s-sleeping tunnel-2 MUST recover in <2.5s!
	tHandover := time.Now()
	phase.Store(2)
	ctrlC.NotifyNetworkChange("wifi", false)
	waitUntilCond(t, 2500*time.Millisecond, "MT-24C BOTH hung boot + 15s backoff wake and recover to 2/2", func() bool {
		s := ctrlC.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && s.NetworkType == "wifi"
	})
	if elapsed := time.Since(tHandover); elapsed > 2500*time.Millisecond {
		t.Fatalf("MT-24C recovery took %s (>2.5s)", elapsed)
	}

	ctrlC.StopAndWait(4 * time.Second)
	assertGoroutinesClean(t, baseG, 10)
}

type ctxAwareFuncTransport struct {
	fn func(ctx context.Context, workerID string) (WorkerSession, error)
}

func (f *ctxAwareFuncTransport) Connect(ctx context.Context, workerID string) (WorkerSession, error) {
	return f.fn(ctx, workerID)
}

// =============================================================================
// MT-25: Persistent 404 WAF Budget Protection & Exponential Same-Tunnel Cooldown
// =============================================================================
func TestMT25_Persistent404WAFBudgetProtectionAndSameTunnelBackoff(t *testing.T) {
	baseG := runtime.NumGoroutine()
	stack := startMockDevTunnelStack(t, devTunnelWSProtoV1, true)
	defer stack.Close()

	var azureOutage atomic.Bool
	azureOutage.Store(true)
	var devTunnel404Hits atomic.Int32
	var ghCalls atomic.Int32

	stack.mu.Lock()
	stack.restStatusFn = func(tid string) int {
		if azureOutage.Load() {
			devTunnel404Hits.Add(1)
			return http.StatusNotFound
		}
		return http.StatusOK
	}
	stack.mu.Unlock()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  "mt25-space",
			"state": "Available",
			"connection": map[string]any{
				"tunnelProperties": map[string]any{
					"connectAccessToken":     stack.connectToken,
					"managePortsAccessToken": stack.manageToken,
					"serviceUri":             stack.srv.URL,
					"tunnelId":               "stuck-same-id",
					"clusterId":              "euw",
					"domain":                 "euw.devtunnels.ms",
				},
			},
		})
	}))
	defer ghSrv.Close()

	cfg := DefaultConfig()
	cfg.CodespaceName = "mt25-space"
	cfg.GitHubToken = "gho_mt25"
	cfg.GitHubAPIBaseURL = ghSrv.URL
	cfg.LocalPort = 0
	cfg.PoolSize = 2
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.StopOnExit = false
	cfg.BackoffMin = 15 * time.Millisecond
	cfg.BackoffMax = 25 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	res := NewAntiPoisonResolver(nil, nil)
	guard := NewGitHubGuard(cfg, nil, nil)
	api := NewGitHubAPIClient(ghSrv.URL, ghSrv.URL, res, guard)
	creds := NewCredentialManager(api, cfg.GitHubToken, cfg.CodespaceName)
	creds.SetMinInvalidateCooldown(180 * time.Millisecond)
	tr := NewDevTunnelSSHTransport(cfg, creds, res, nil, nil)

	sup := NewSupervisor(cfg, nil, SupervisorDeps{
		Transport:   tr,
		GitHubGuard: guard,
		PoolHooks:   PoolHooks{SampleDelay: 5 * time.Millisecond, RetryDelay: 10 * time.Millisecond},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// Wait through >= 12 persistent 404 failures; same-tunnel backoff MUST keep GitHub calls <= 5!
	waitUntilCond(t, 5*time.Second, "MT-25 >= 12 DevTunnels 404 errors observed", func() bool {
		return devTunnel404Hits.Load() >= 12
	})
	gs := guard.CachedSnapshot()
	if gs.CallsLast5Min > 6 || gs.CooldownRemainingMS != 0 {
		cancel()
		<-done
		t.Fatalf("MT-25 WAF budget violated or hit cooldown during persistent 404: 5m=%d cooldown=%d", gs.CallsLast5Min, gs.CooldownRemainingMS)
	}
	if ghCalls.Load() >= devTunnel404Hits.Load() {
		cancel()
		<-done
		t.Fatalf("MT-25 expected same-tunnel cooldown to throttle GitHub calls (%d) well below 404 hits (%d)", ghCalls.Load(), devTunnel404Hits.Load())
	}

	// Recover Azure DevTunnels -> pool reaches 2/2 HEALTHY and resets sameTunnelInvalidateStreak via MarkTunnelHealthy.
	azureOutage.Store(false)
	waitUntilCond(t, 5*time.Second, "MT-25 recovers to 2/2 healthy once Azure 404 clears", func() bool {
		return sup.State() == StateHealthy && sup.AtomicPoolSnapshot().HealthyWorkers == 2
	})

	_, gen, gerr := creds.GetWithGen(context.Background(), false)
	if gerr != nil || gen == 0 {
		cancel()
		<-done
		t.Fatalf("MT-25 GetWithGen post-recovery failed: gen=%d err=%v", gen, gerr)
	}
	if invNow, remNow := creds.InvalidateIfMatch(gen, "http_404"); !invNow || remNow != 0 {
		cancel()
		<-done
		t.Fatalf("MT-25 MarkTunnelHealthy did not clear cooldown streak: inv=%v rem=%s", invNow, remNow)
	}

	cancel()
	<-done
	stack.Close()
	ghSrv.Close()
	assertGoroutinesClean(t, baseG, 10)
}

// =============================================================================
// MT-26: Zero Duplicate WORKER_BOOT_FAIL Logs + Immediate CtrlPausedOffline Exit
// =============================================================================
func TestMT26_ZeroDuplicateWorkerBootFailLogsAndCleanOfflineExit(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// Part A: Force 3 consecutive boot failures on tunnel-1 -> MUST emit EXACTLY 3 WORKER_BOOT_FAIL lines (not 6!).
	var attemptsA atomic.Int32
	trA := &ctxAwareFuncTransport{
		fn: func(_ context.Context, _ string) (WorkerSession, error) {
			if attemptsA.Add(1) <= 3 {
				return nil, errors.New("simulated dial fail")
			}
			return newMockWorkerSession("20.93.53.155:443"), nil
		},
	}
	cfgA := DefaultConfig()
	cfgA.CodespaceName = "mt26-logs"
	cfgA.LocalPort = 0
	cfgA.PoolSize = 1
	cfgA.BootQualitySamples = 1
	cfgA.BootMicroPayloadCheck = false
	cfgA.StopOnExit = false
	cfgA.BackoffMin = 15 * time.Millisecond
	cfgA.BackoffMax = 25 * time.Millisecond
	cfgA.GitHubMinCallSpacing = 0

	ctrlA := NewSessionController(cfgA, ControllerCallbacks{}, ControllerOverrides{
		TransportFactory: func(_ Config, _ *CredentialManager, _ *AntiPoisonResolver, _ *HeartbeatCoordinator, _ *EventLogger) WorkerTransport {
			return trA
		},
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 90 * time.Millisecond, nil
			},
		},
		SnapshotInterval: 40 * time.Millisecond,
	})
	ctrlA.Start()
	waitUntilCond(t, 4*time.Second, "MT-26A reaches RUNNING after 3 failed boots", func() bool {
		return ctrlA.Snapshot().State == CtrlRunning && ctrlA.Snapshot().HealthyWorkers == 1
	})
	ctrlA.StopAndWait(4 * time.Second)

	failLogCount := 0
	for _, ln := range ctrlA.Logs().Since(0) {
		if strings.Contains(ln.Text, "[Boot] tunnel-1 failed:") {
			failLogCount++
		}
	}
	if failLogCount != 3 {
		t.Fatalf("MT-26A expected EXACTLY 3 [Boot] tunnel-1 failed: lines (zero duplicates), got %d", failLogCount)
	}

	// Part B: Verify immediate exit out of CtrlPausedOffline before workers even finish booting.
	var gateActive atomic.Bool
	restoreGate := make(chan struct{})
	trB := &ctxAwareFuncTransport{
		fn: func(ctx context.Context, _ string) (WorkerSession, error) {
			if gateActive.Load() {
				select {
				case <-restoreGate:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return newMockWorkerSession("20.93.53.155:443"), nil
		},
	}
	cfgB := DefaultConfig()
	cfgB.CodespaceName = "mt26-offline"
	cfgB.LocalPort = 0
	cfgB.PoolSize = 2
	cfgB.BootQualitySamples = 1
	cfgB.BootMicroPayloadCheck = false
	cfgB.StopOnExit = false
	cfgB.NetworkDebounceInterval = 60 * time.Millisecond
	cfgB.BackoffMin = 20 * time.Millisecond
	cfgB.BackoffMax = 40 * time.Millisecond
	cfgB.GitHubMinCallSpacing = 0

	ctrlB := NewSessionController(cfgB, ControllerCallbacks{}, ControllerOverrides{
		TransportFactory: func(_ Config, _ *CredentialManager, _ *AntiPoisonResolver, _ *HeartbeatCoordinator, _ *EventLogger) WorkerTransport {
			return trB
		},
		PoolHooks: PoolHooks{
			ProbeFunc: func(_ context.Context, _ WorkerSession, _ string, _ time.Duration) (time.Duration, error) {
				return 95 * time.Millisecond, nil
			},
		},
		SnapshotInterval: 30 * time.Millisecond,
	})
	ctrlB.Start()
	defer ctrlB.StopAndWait(4 * time.Second)

	waitUntilCond(t, 4*time.Second, "MT-26B initial 2/2 running", func() bool {
		s := ctrlB.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2
	})

	ctrlB.NotifyNetworkChange("none", false)
	waitUntilCond(t, 2*time.Second, "MT-26B enters PAUSED_OFFLINE", func() bool {
		return ctrlB.Snapshot().State == CtrlPausedOffline
	})

	gateActive.Store(true)
	ctrlB.NotifyNetworkChange("wifi", false)
	waitUntilCond(t, 1*time.Second, "MT-26B exits PAUSED_OFFLINE immediately while workers still booting", func() bool {
		return ctrlB.Snapshot().State != CtrlPausedOffline
	})

	close(restoreGate)
	waitUntilCond(t, 4*time.Second, "MT-26B recovers fully to CtrlRunning 2/2", func() bool {
		s := ctrlB.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2
	})

	ctrlB.StopAndWait(4 * time.Second)
	assertGoroutinesClean(t, baseG, 10)
}
