//go:build !linux && !android

package engine

import (
	"syscall"
	"time"
)

// setTCPUserTimeout is a portable no-op on non-Linux hosts (Windows/macOS desktop tests).
func setTCPUserTimeout(_ syscall.RawConn, _ time.Duration) error {
	return nil
}
