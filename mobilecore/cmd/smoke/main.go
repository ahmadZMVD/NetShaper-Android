package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netshaper/mobilecore/engine"
)

// Standalone CLI to verify the pure-Go Dev Tunnels + port 16634 RPC + Inner x/crypto/ssh + :1080 SOCKS5
// stack against a REAL GitHub Codespace on Windows/Linux (zero gh.exe, zero openssh subprocesses).
//
// Usage:
//   go run ./cmd/smoke -token ghp_xxx -codespace my-codespace -port 1080 -pool 2
func main() {
	token := flag.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub OAuth token or PAT with 'codespace' scope")
	codespace := flag.String("codespace", os.Getenv("NETSHAPER_CODESPACE"), "Target GitHub Codespace name")
	port := flag.Int("port", 1080, "Local SOCKS5 listening port")
	poolSize := flag.Int("pool", 2, "Number of parallel in-process SSH tunnels (1..4)")
	stopOnExit := flag.Bool("stop-on-exit", false, "Stop Codespace via REST API on Ctrl+C (default false for smoke test)")
	dataDir := flag.String("data-dir", "", "Optional directory for rotating log + state cache")
	flag.Parse()

	if *token == "" || *codespace == "" {
		fmt.Fprintln(os.Stderr, "Usage: go run ./cmd/smoke -token <PAT> -codespace <name> [-port 1080] [-pool 2] [-stop-on-exit=false]")
		os.Exit(2)
	}

	cfg := engine.DefaultConfig()
	cfg.GitHubToken = *token
	cfg.CodespaceName = *codespace
	cfg.LocalPort = uint16(*port)
	cfg.PoolSize = *poolSize
	cfg.StopOnExit = *stopOnExit
	cfg.DataDir = *dataDir

	if err := cfg.Validate(); err != nil {
		log.Fatalf("[Smoke] invalid config: %v", err)
	}

	ctrl := engine.NewSessionController(cfg, engine.ControllerCallbacks{
		OnStateChange: func(state, detail string) {
			log.Printf("[State] %s (%s)", state, detail)
		},
		OnLogLine: func(seq int64, level, text string) {
			log.Printf("[#%d %s] %s", seq, level, text)
		},
		OnError: func(code, message string) {
			log.Printf("[Error:%s] %s", code, message)
		},
	}, engine.ControllerOverrides{})

	ctrl.Start()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Print telemetry snapshot every 10s until Ctrl+C.
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
				log.Printf("[Snapshot] %s", string(raw))
			}
		}
	}()

	log.Printf("[Smoke] Pure-Go mobilecore starting | codespace=%s | SOCKS5=%s | URI=%s",
		cfg.CodespaceName, cfg.LocalAddr(), engine.BuildV2RayNGProfileURI(cfg.LocalHost, cfg.LocalPort))
	log.Printf("[Smoke] Test with: curl --socks5-hostname %s https://api.ipify.org", cfg.LocalAddr())
	log.Printf("[Smoke] Press Ctrl+C to shut down cleanly...")

	<-sigCh
	cancel()
	log.Printf("[Smoke] Shutting down...")
	ctrl.StopAndWait(14 * time.Second)
	log.Printf("[Smoke] Clean exit.")
}
