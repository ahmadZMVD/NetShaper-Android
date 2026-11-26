//go:build linux || android

package engine

import (
	"syscall"
	"time"
)

const linuxTCPUserTimeout = 18 // TCP_USER_TIMEOUT in <netinet/tcp.h>

// setTCPUserTimeout configures Linux/Android kernel TCP_USER_TIMEOUT so unacknowledged
// packets over silently dropped CG-NAT flows abort in <=timeout instead of ~15 minutes.
func setTCPUserTimeout(rawConn syscall.RawConn, timeout time.Duration) error {
	if rawConn == nil || timeout <= 0 {
		return nil
	}
	ms := int(timeout.Milliseconds())
	if ms < 1000 {
		ms = 1000
	}
	var sockErr error
	err := rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, linuxTCPUserTimeout, ms)
	})
	if err != nil {
		return err
	}
	return sockErr
}
