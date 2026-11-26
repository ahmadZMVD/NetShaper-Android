package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	socks5Ver            = 0x05
	socks5MethodNoAuth   = 0x00
	socks5MethodNoAccept = 0xFF
	socks5CmdConnect     = 0x01
	socks5CmdBind        = 0x02
	socks5CmdUDPAssoc    = 0x03

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5RepSucceeded          = 0x00
	socks5RepGeneralFailure     = 0x01
	socks5RepNotAllowed         = 0x02
	socks5RepNetUnreachable     = 0x03
	socks5RepHostUnreachable    = 0x04
	socks5RepConnRefused        = 0x05
	socks5RepCmdNotSupported    = 0x07
	socks5RepAddrNotSupported   = 0x08
)

type socks5Request struct {
	Host string
	Port uint16
}

func writeSOCKS5Reply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{socks5Ver, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
}

func isSelfLoopTarget(host string, port uint16, localPort uint16) bool {
	if localPort == 0 || port != localPort {
		return false
	}
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// mapDialErrorToSOCKS5Rep maps Go dial errors to standard RFC 1928 reply codes.
func mapDialErrorToSOCKS5Rep(err error) byte {
	if err == nil {
		return socks5RepSucceeded
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return socks5RepConnRefused
	}
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "connection refused"), strings.Contains(low, "actively refused"):
		return socks5RepConnRefused
	case strings.Contains(low, "network is unreachable"):
		return socks5RepNetUnreachable
	case strings.Contains(low, "no such host"), strings.Contains(low, "host is unreachable"):
		return socks5RepHostUnreachable
	default:
		return socks5RepGeneralFailure
	}
}

// PerformSOCKS5ServerHandshake executes strict RFC 1928 NOAUTH + CONNECT parsing:
//   - Instant REP=0x07 on UDP ASSOCIATE (0x03) and BIND (0x02) for QUIC fail-fast.
//   - Instant REP=0x02 on self-loopback targets matching localPort.
//   - Preserves domain names verbatim (ATYP=0x03) for remote DNS resolution inside the Codespace.
func PerformSOCKS5ServerHandshake(conn net.Conn, localPort uint16, timeout time.Duration) (socks5Request, error) {
	if timeout <= 0 {
		timeout = DefaultSOCKS5HandshakeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil {
		return socks5Request{}, fmt.Errorf("socks5 greeting: %w", err)
	}
	if greet[0] != socks5Ver {
		return socks5Request{}, fmt.Errorf("unsupported socks version 0x%02x", greet[0])
	}
	nMethods := int(greet[1])
	if nMethods == 0 {
		_, _ = conn.Write([]byte{socks5Ver, socks5MethodNoAccept})
		return socks5Request{}, errors.New("socks5 client offered 0 auth methods")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socks5Request{}, fmt.Errorf("socks5 methods: %w", err)
	}
	noAuthOK := false
	for _, m := range methods {
		if m == socks5MethodNoAuth {
			noAuthOK = true
			break
		}
	}
	if !noAuthOK {
		_, _ = conn.Write([]byte{socks5Ver, socks5MethodNoAccept})
		return socks5Request{}, errors.New("socks5 client did not offer NOAUTH")
	}
	if _, err := conn.Write([]byte{socks5Ver, socks5MethodNoAuth}); err != nil {
		return socks5Request{}, fmt.Errorf("socks5 method reply: %w", err)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return socks5Request{}, fmt.Errorf("socks5 request header: %w", err)
	}
	if hdr[0] != socks5Ver {
		return socks5Request{}, fmt.Errorf("socks5 bad request ver 0x%02x", hdr[0])
	}

	// Read destination address + port even for unsupported commands so client reads reply cleanly.
	var host string
	switch hdr[3] {
	case socks5AtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return socks5Request{}, fmt.Errorf("socks5 ipv4: %w", err)
		}
		host = net.IP(b[:]).String()
	case socks5AtypDomain:
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return socks5Request{}, fmt.Errorf("socks5 domain len: %w", err)
		}
		dom := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, dom); err != nil {
			return socks5Request{}, fmt.Errorf("socks5 domain: %w", err)
		}
		host = string(dom)
	case socks5AtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return socks5Request{}, fmt.Errorf("socks5 ipv6: %w", err)
		}
		host = net.IP(b[:]).String()
	default:
		writeSOCKS5Reply(conn, socks5RepAddrNotSupported)
		return socks5Request{}, fmt.Errorf("socks5 unsupported atyp 0x%02x", hdr[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return socks5Request{}, fmt.Errorf("socks5 port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	if hdr[1] == socks5CmdUDPAssoc || hdr[1] == socks5CmdBind || hdr[1] != socks5CmdConnect {
		writeSOCKS5Reply(conn, socks5RepCmdNotSupported)
		return socks5Request{}, fmt.Errorf("socks5 unsupported cmd 0x%02x", hdr[1])
	}
	if host == "" || port == 0 {
		writeSOCKS5Reply(conn, socks5RepNotAllowed)
		return socks5Request{}, errors.New("socks5 empty host or zero port")
	}
	if isSelfLoopTarget(host, port, localPort) {
		writeSOCKS5Reply(conn, socks5RepNotAllowed)
		return socks5Request{}, fmt.Errorf("socks5 blocked self-loop to %s:%d", host, port)
	}
	return socks5Request{Host: host, Port: port}, nil
}

func splitHostPortUint16(addr string) (string, uint16, error) {
	h, pStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.ParseUint(pStr, 10, 16)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("invalid port %q", pStr)
	}
	return h, uint16(p), nil
}
