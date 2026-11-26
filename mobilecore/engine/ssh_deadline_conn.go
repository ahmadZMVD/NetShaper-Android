package engine

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshTimeoutError struct{}

func (sshTimeoutError) Error() string   { return "ssh channel i/o timeout" }
func (sshTimeoutError) Timeout() bool   { return true }
func (sshTimeoutError) Temporary() bool { return true }

var errSSHTimeout net.Error = sshTimeoutError{}

type sshChannelAddr struct {
	addr string
}

func (a sshChannelAddr) Network() string { return "tcp" }
func (a sshChannelAddr) String() string  { return a.addr }

// DeadlineSSHConn wraps an RFC 4254 ssh.Channel as a full net.Conn + CloseWrite() with
// monotonic generation-guarded (readGen/writeGen) timers so stale firing callbacks racing with
// SetReadDeadline/SetWriteDeadline can NEVER close an active or freshly extended stream.
type DeadlineSSHConn struct {
	ch         ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr

	mu            sync.Mutex
	readGen       uint64
	writeGen      uint64
	readTimer     *time.Timer
	writeTimer    *time.Timer
	readDeadline  time.Time
	writeDeadline time.Time
	readTimedOut  bool
	writeTimedOut bool
	closed        bool

	closeOnce sync.Once
	closeErr  error
}

// NewDeadlineSSHConn wraps ch as a deadline-capable net.Conn safe under -race.
func NewDeadlineSSHConn(ch ssh.Channel, remoteTarget string) *DeadlineSSHConn {
	if remoteTarget == "" {
		remoteTarget = "ssh-channel:0"
	}
	return &DeadlineSSHConn{
		ch:         ch,
		localAddr:  sshChannelAddr{addr: "127.0.0.1:0"},
		remoteAddr: sshChannelAddr{addr: remoteTarget},
	}
}

func (c *DeadlineSSHConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *DeadlineSSHConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *DeadlineSSHConn) closeUnderlying() error {
	c.closeOnce.Do(func() {
		if c.ch != nil {
			c.closeErr = c.ch.Close()
		}
	})
	return c.closeErr
}

func (c *DeadlineSSHConn) onReadTimeout(gen uint64) {
	c.mu.Lock()
	if c.closed || c.readGen != gen {
		c.mu.Unlock()
		return
	}
	c.readTimedOut = true
	c.readTimer = nil
	c.mu.Unlock()
	_ = c.closeUnderlying()
}

func (c *DeadlineSSHConn) onWriteTimeout(gen uint64) {
	c.mu.Lock()
	if c.closed || c.writeGen != gen {
		c.mu.Unlock()
		return
	}
	c.writeTimedOut = true
	c.writeTimer = nil
	c.mu.Unlock()
	_ = c.closeUnderlying()
}

func (c *DeadlineSSHConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *DeadlineSSHConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.readGen++
	gen := c.readGen
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.readDeadline = t
	if t.IsZero() {
		c.mu.Unlock()
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		c.readTimedOut = true
		c.mu.Unlock()
		_ = c.closeUnderlying()
		return nil
	}
	c.readTimer = time.AfterFunc(d, func() {
		c.onReadTimeout(gen)
	})
	c.mu.Unlock()
	return nil
}

func (c *DeadlineSSHConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.writeGen++
	gen := c.writeGen
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	c.writeDeadline = t
	if t.IsZero() {
		c.mu.Unlock()
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		c.writeTimedOut = true
		c.mu.Unlock()
		_ = c.closeUnderlying()
		return nil
	}
	c.writeTimer = time.AfterFunc(d, func() {
		c.onWriteTimeout(gen)
	})
	c.mu.Unlock()
	return nil
}

func (c *DeadlineSSHConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.readTimedOut {
		c.mu.Unlock()
		return 0, errSSHTimeout
	}
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !c.readDeadline.IsZero() && !c.readDeadline.After(time.Now()) {
		c.readTimedOut = true
		c.mu.Unlock()
		_ = c.closeUnderlying()
		return 0, errSSHTimeout
	}
	c.mu.Unlock()

	n, err := c.ch.Read(p)
	if err != nil {
		c.mu.Lock()
		timedOut := c.readTimedOut
		c.mu.Unlock()
		if timedOut {
			return n, errSSHTimeout
		}
	}
	return n, err
}

func (c *DeadlineSSHConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.writeTimedOut {
		c.mu.Unlock()
		return 0, errSSHTimeout
	}
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !c.writeDeadline.IsZero() && !c.writeDeadline.After(time.Now()) {
		c.writeTimedOut = true
		c.mu.Unlock()
		_ = c.closeUnderlying()
		return 0, errSSHTimeout
	}
	c.mu.Unlock()

	n, err := c.ch.Write(p)
	if err != nil {
		c.mu.Lock()
		timedOut := c.writeTimedOut
		c.mu.Unlock()
		if timedOut {
			return n, errSSHTimeout
		}
	}
	return n, err
}

// CloseWrite sends RFC 4254 SSH_MSG_CHANNEL_EOF without closing the reverse read half.
func (c *DeadlineSSHConn) CloseWrite() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.mu.Unlock()
	return c.ch.CloseWrite()
}

// Close stops all active timers (zero timer leaks) and closes the underlying ssh.Channel once.
func (c *DeadlineSSHConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.readGen++
	c.writeGen++
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	c.mu.Unlock()
	return c.closeUnderlying()
}
