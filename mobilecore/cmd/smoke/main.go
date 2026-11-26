package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"netshaper/mobilecore/engine"
)

// Standalone CLI to verify the pure-Go Dev Tunnels + port 16634 RPC + Inner x/crypto/ssh + :1080 SOCKS5
// stack against a REAL GitHub Codespace on Windows/Linux (zero gh.exe, zero openssh subprocesses).
//
// Quick 10-second verification (PowerShell):
//
//	go run ./cmd/smoke -token (gh auth token) -codespace <name> -oneshot
//
// Daemon mode:
//
//	go run ./cmd/smoke -token <gho_or_ghp> -codespace <name> -port 1080 -pool 2
func main() {
	token := flag.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub OAuth/PAT token (e.g. from 'gh auth token')")
	codespace := flag.String("codespace", os.Getenv("NETSHAPER_CODESPACE"), "Target GitHub Codespace name")
	port := flag.Int("port", 1080, "Local SOCKS5 listening port (0 = ephemeral)")
	poolSize := flag.Int("pool", 2, "Number of parallel in-process SSH tunnels (1..4)")
	stopOnExit := flag.Bool("stop-on-exit", false, "Stop Codespace via REST API on exit (default false for smoke test)")
	dataDir := flag.String("data-dir", "", "Optional directory for rotating log + state cache")
	probeHost := flag.String("probe-host", "cp.cloudflare.com:80", "Host:port for auto E2E HTTP 204 check through SOCKS5 (empty to disable)")
	oneshot := flag.Bool("oneshot", false, "Automatically exit 0 once E2E SOCKS5 verification passes (or 1 on timeout/fatal)")
	timeout := flag.Duration("timeout", 120*time.Second, "Maximum boot wait before failing in -oneshot mode")
	flag.Parse()

	if strings.TrimSpace(*token) == "" || strings.TrimSpace(*codespace) == "" {
		fmt.Fprintln(os.Stderr, "Usage: go run ./cmd/smoke -token (gh auth token) -codespace <name> [-port 1080] [-pool 2] [-oneshot]")
		os.Exit(2)
	}

	cfg := engine.DefaultConfig()
	cfg.GitHubToken = strings.TrimSpace(*token)
	cfg.CodespaceName = strings.TrimSpace(*codespace)
	cfg.LocalPort = uint16(*port)
	cfg.PoolSize = *poolSize
	cfg.StopOnExit = *stopOnExit
	cfg.DataDir = *dataDir

	if err := cfg.Validate(); err != nil {
		log.Fatalf("[Smoke] invalid config: %v", err)
	}

	healthyCh := make(chan string, 1)
	fatalCh := make(chan string, 1)
	var notifiedHealthy atomic.Bool

	ctrl := engine.NewSessionController(cfg, engine.ControllerCallbacks{
		OnStateChange: func(state, detail string) {
			safeDetail := engine.RedactSecrets(detail)
			log.Printf("[State] %s (%s)", state, safeDetail)
			if (state == "RUNNING" || state == "HEALTHY") && notifiedHealthy.CompareAndSwap(false, true) {
				select {
				case healthyCh <- safeDetail:
				default:
				}
			}
		},
		OnLogLine: func(seq int64, level, text string) {
			log.Printf("[#%d %s] %s", seq, level, engine.RedactSecrets(text))
		},
		OnError: func(code, message string) {
			safeMsg := engine.RedactSecrets(message)
			log.Printf("[Error:%s] %s", code, safeMsg)
			if code != "" && code != "warn" {
				select {
				case fatalCh <- code + ": " + safeMsg:
				default:
				}
			}
		},
	}, engine.ControllerOverrides{})

	ctrl.Start()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				snap := ctrl.Snapshot()
				raw, _ := json.Marshal(snap)
				log.Printf("[Snapshot] %s", engine.RedactSecrets(string(raw)))
			}
		}
	}()

	log.Printf("[Smoke] Pure-Go mobilecore starting | codespace=%s | SOCKS5=%s | oneshot=%v",
		cfg.CodespaceName, cfg.LocalAddr(), *oneshot)

	exitCode := 0
	var bootTimer <-chan time.Time
	if *oneshot {
		tm := time.NewTimer(*timeout)
		defer tm.Stop()
		bootTimer = tm.C
	}

waitLoop:
	for {
		select {
		case <-healthyCh:
			snap := ctrl.Snapshot()
			bindAddr := snap.LocalAddr
			if bindAddr == "" {
				bindAddr = cfg.LocalAddr()
			}
			uri := snap.V2RayNGURI
			if uri == "" {
				uri = engine.BuildV2RayNGProfileURI(cfg.LocalHost, cfg.LocalPort)
			}
			log.Printf("[Smoke] TUNNEL READY | SOCKS5=%s | underlay=%.0fms | uri=%s",
				bindAddr, snap.UnderlayMS, uri)
			if strings.TrimSpace(*probeHost) != "" {
				rtt, perr := verifySOCKS5HTTPProbe(bindAddr, strings.TrimSpace(*probeHost), 15*time.Second)
				if perr != nil {
					log.Printf("[Smoke] E2E SOCKS5 PROBE FAIL (%s): %v", *probeHost, engine.RedactSecrets(perr.Error()))
					if *oneshot {
						exitCode = 1
						break waitLoop
					}
				} else {
					log.Printf("[Smoke] E2E SOCKS5 PROBE PASS (%s) rtt=%s", *probeHost, rtt.Round(time.Millisecond))
					if *oneshot {
						break waitLoop
					}
				}
			} else if *oneshot {
				break waitLoop
			}
		case ferr := <-fatalCh:
			if *oneshot {
				log.Printf("[Smoke] Abort on error: %s", ferr)
				exitCode = 1
				break waitLoop
			}
		case <-bootTimer:
			log.Printf("[Smoke] Timeout after %s waiting for RUNNING", *timeout)
			exitCode = 1
			break waitLoop
		case <-sigCh:
			break waitLoop
		}
	}

	cancel()
	log.Printf("[Smoke] Shutting down...")
	ctrl.StopAndWait(14 * time.Second)
	log.Printf("[Smoke] Clean exit (code=%d).", exitCode)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func verifySOCKS5HTTPProbe(socksAddr, targetHostPort string, timeout time.Duration) (time.Duration, error) {
	host, portStr, err := net.SplitHostPort(targetHostPort)
	if err != nil {
		return 0, fmt.Errorf("invalid probe-host %q: %w", targetHostPort, err)
	}
	var portNum int
	if _, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil || portNum <= 0 || portNum > 65535 {
		return 0, fmt.Errorf("invalid port in %q", targetHostPort)
	}
	if len(host) == 0 || len(host) > 253 {
		return 0, fmt.Errorf("invalid hostname in %q", targetHostPort)
	}

	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", socksAddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// RFC 1928 method negotiation: NO AUTH (0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return 0, err
	}
	var mrep [2]byte
	if _, err := io.ReadFull(conn, mrep[:]); err != nil {
		return 0, err
	}
	if mrep[0] != 0x05 || mrep[1] != 0x00 {
		return 0, fmt.Errorf("unexpected SOCKS5 method reply: %v", mrep)
	}

	// CONNECT with ATYP=0x03 (remote DNS domain name)
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, []byte(host)...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(portNum))
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[1] != 0x00 {
		return 0, fmt.Errorf("SOCKS5 CONNECT failed code=0x%02x", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		var skip [6]byte
		if _, err := io.ReadFull(conn, skip[:]); err != nil {
			return 0, err
		}
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return 0, err
		}
		skip := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return 0, err
		}
	case 0x04:
		var skip [18]byte
		if _, err := io.ReadFull(conn, skip[:]); err != nil {
			return 0, err
		}
	}

	if portNum == 80 {
		httpReq := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		if _, err := conn.Write([]byte(httpReq)); err != nil {
			return 0, err
		}
		line, err := bufio.NewReader(io.LimitReader(conn, 1024)).ReadString('\n')
		if err != nil && err != io.EOF {
			return 0, err
		}
		if !strings.Contains(line, "204") && !strings.Contains(line, "200") && !strings.Contains(line, "301") && !strings.Contains(line, "302") {
			return 0, fmt.Errorf("unexpected HTTP status line: %q", strings.TrimSpace(line))
		}
	}
	return time.Since(start), nil
}
