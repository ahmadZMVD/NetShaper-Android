package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

var defaultDoHEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://9.9.9.9/dns-query",
	"https://[2606:4700:4700::1111]/dns-query",
}

// IsPMTU576RelayIP detects the legacy Azure Dev Tunnels Relay VIP (20.120.56.11) across IPv4,
// IPv4-mapped IPv6 (::ffff:20.120.56.11), and RFC 6052 NAT64 IPv6 (64:ff9b::1478:380b).
func IsPMTU576RelayIP(remoteEndpoint string) bool {
	s := strings.TrimSpace(remoteEndpoint)
	if s == "" {
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 20 && ip4[1] == 120 && ip4[2] == 56 && ip4[3] == 11
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	// RFC 6052 Well-Known Prefix 64:ff9b::/96 or local-use 64:ff9b:1::/48 -> embedded IPv4 in bytes 12..15.
	if ip16[0] == 0x00 && ip16[1] == 0x64 && ip16[2] == 0xff && ip16[3] == 0x9b {
		return ip16[12] == 20 && ip16[13] == 120 && ip16[14] == 56 && ip16[15] == 11
	}
	return false
}

// IsPoisonedPublicIP returns true when an ISP DNS resolver hijacks a public domain to an RFC 1918,
// CG-NAT, loopback, link-local, FakeDNS (198.18.0.0/15), RFC 5737 doc block, Iranian sinkhole
// (e.g. 10.10.34.34-36), or RFC 6052 NAT64-wrapped poisoned IPv4 (64:ff9b::10.10.34.34-36).
func IsPoisonedPublicIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 100.64.0.0/10 carrier-grade NAT sinkhole / 0.0.0.0/8 / 198.18.0.0/15 FakeDNS / RFC 5737 doc blocks.
		if ip4[0] == 100 && (ip4[1]&0xc0) == 64 {
			return true
		}
		if ip4[0] == 0 {
			return true
		}
		if ip4[0] == 198 && (ip4[1]&0xfe) == 18 {
			return true
		}
		if (ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) ||
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) {
			return true
		}
		return false
	}
	if ip16 := ip.To16(); ip16 != nil {
		// Unwrap RFC 6052 Well-Known Prefix 64:ff9b::/96 or local-use 64:ff9b:1::/48 -> embedded IPv4 in bytes 12..15.
		if ip16[0] == 0x00 && ip16[1] == 0x64 && ip16[2] == 0xff && ip16[3] == 0x9b {
			embedded := net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
			return IsPoisonedPublicIP(embedded)
		}
	}
	return false
}

func isLocalHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return h == "localhost" || strings.HasSuffix(h, ".local") || h == "127.0.0.1" || h == "::1"
}

type dnsCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

// AntiPoisonResolver performs dual-stack resolution with automatic Iranian DNS poisoning detection
// (10.10.34.x / bogon rejection) and pure-Go RFC 8484 direct-IP DoH fallback.
type AntiPoisonResolver struct {
	sysLookup    func(ctx context.Context, host string) ([]net.IP, error)
	dohEndpoints []string
	dohClient    *http.Client
	cacheMu      sync.RWMutex
	cache        map[string]dnsCacheEntry
	cacheTTL     time.Duration
}

func NewAntiPoisonResolver(dohEndpoints []string, sysLookup func(context.Context, string) ([]net.IP, error)) *AntiPoisonResolver {
	if len(dohEndpoints) == 0 {
		dohEndpoints = defaultDoHEndpoints
	}
	if sysLookup == nil {
		sysLookup = func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, nil
		}
	}
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   4 * time.Second,
			KeepAlive: 8 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &AntiPoisonResolver{
		sysLookup:    sysLookup,
		dohEndpoints: dohEndpoints,
		dohClient:    &http.Client{Transport: tr, Timeout: 5 * time.Second},
		cache:        make(map[string]dnsCacheEntry),
		cacheTTL:     2 * time.Minute,
	}
}

func (r *AntiPoisonResolver) FlushCache() {
	if r == nil {
		return
	}
	r.cacheMu.Lock()
	r.cache = make(map[string]dnsCacheEntry)
	r.cacheMu.Unlock()
}

func (r *AntiPoisonResolver) CloseIdleConnections() {
	if r == nil || r.dohClient == nil {
		return
	}
	if tr, ok := r.dohClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

var errDoHEndpointDown = errors.New("doh endpoint unreachable")

// ResolveHost returns clean public IPs for host (preferring IPv4 first while retaining IPv6 for NAT64/dual-stack).
func (r *AntiPoisonResolver) ResolveHost(ctx context.Context, host string) ([]net.IP, bool, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, false, nil
	}
	if isLocalHostname(host) {
		ips, err := r.sysLookup(ctx, host)
		return ips, false, err
	}

	r.cacheMu.RLock()
	if ent, ok := r.cache[host]; ok && time.Now().Before(ent.expiresAt) && len(ent.ips) > 0 {
		out := append([]net.IP(nil), ent.ips...)
		r.cacheMu.RUnlock()
		return out, false, nil
	}
	r.cacheMu.RUnlock()

	// 1. Try system DNS first (preserves carrier NAT64/DNS64 synthesized IPv6 on IPv6-only LTE/5G).
	sysIPs, sysErr := r.sysLookup(ctx, host)
	if sysErr == nil && len(sysIPs) > 0 {
		poisoned := false
		for _, ip := range sysIPs {
			if IsPoisonedPublicIP(ip) {
				poisoned = true
				break
			}
		}
		if !poisoned {
			ordered := orderIPv4Preferred(sysIPs)
			r.putCache(host, ordered)
			return ordered, false, nil
		}
	}

	// 2. Fallback to pure-Go RFC 8484 wire-format DoH directly against public IP literals.
	dohIPs, dohErr := r.lookupDoH(ctx, host)
	if dohErr == nil && len(dohIPs) > 0 {
		ordered := orderIPv4Preferred(dohIPs)
		r.putCache(host, ordered)
		return ordered, true, nil
	}
	if sysErr != nil {
		return nil, false, fmt.Errorf("dns resolve %s: sys=%v doh=%v", host, sysErr, dohErr)
	}
	return nil, false, fmt.Errorf("dns resolve %s: system returned poisoned IP and DoH failed: %v", host, dohErr)
}

func (r *AntiPoisonResolver) putCache(host string, ips []net.IP) {
	r.cacheMu.Lock()
	r.cache[host] = dnsCacheEntry{
		ips:       append([]net.IP(nil), ips...),
		expiresAt: time.Now().Add(r.cacheTTL),
	}
	r.cacheMu.Unlock()
}

func orderIPv4Preferred(ips []net.IP) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		} else if ip16 := ip.To16(); ip16 != nil {
			v6 = append(v6, ip16)
		}
	}
	return append(v4, v6...)
}

// DialContext dials network/address using AntiPoisonResolver + dual-stack fallback + TCP keepalive/TCP_USER_TIMEOUT.
func (r *AntiPoisonResolver) DialContext(ctx context.Context, network, address string, timeout, keepAlive, userTimeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, _, err := r.ResolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses resolved for %s", host)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if keepAlive <= 0 {
		keepAlive = DefaultTCPKeepAlivePeriod
	}
	perIPTimeout := timeout
	if len(ips) > 1 {
		perIPTimeout = timeout / time.Duration(len(ips))
		if perIPTimeout < 3*time.Second {
			perIPTimeout = 3 * time.Second
		}
		if perIPTimeout > 6*time.Second {
			perIPTimeout = 6 * time.Second
		}
		if perIPTimeout > timeout {
			perIPTimeout = timeout
		}
	}

	var lastErr error
	for _, ip := range ips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		target := net.JoinHostPort(ip.String(), port)
		d := &net.Dialer{
			Timeout:   perIPTimeout,
			KeepAlive: keepAlive,
			Control: func(_, _ string, c syscall.RawConn) error {
				_ = setTCPUserTimeout(c, userTimeout)
				return nil
			},
		}
		conn, derr := d.DialContext(ctx, "tcp", target)
		if derr == nil {
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(keepAlive)
			}
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func (r *AntiPoisonResolver) lookupDoH(ctx context.Context, host string) ([]net.IP, error) {
	var lastErr error
	for _, ep := range r.dohEndpoints {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var out []net.IP
		// Query A (type 1) first; if the endpoint fails at transport/HTTP layer, fail over immediately
		// rather than burning a second full timeout querying AAAA on the exact same dead provider.
		aIPs, err := r.queryDoHType(ctx, ep, host, 1)
		if err != nil {
			lastErr = err
			if errors.Is(err, errDoHEndpointDown) {
				continue
			}
		} else {
			for _, ip := range aIPs {
				if !IsPoisonedPublicIP(ip) {
					out = append(out, ip)
				}
			}
		}
		if len(out) == 0 {
			if aaaaIPs, err := r.queryDoHType(ctx, ep, host, 28); err == nil {
				for _, ip := range aaaaIPs {
					if !IsPoisonedPublicIP(ip) {
						out = append(out, ip)
					}
				}
			} else {
				lastErr = err
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("doh returned no clean records")
	}
	return nil, lastErr
}

func (r *AntiPoisonResolver) queryDoHType(ctx context.Context, endpoint, host string, qtype uint16) ([]net.IP, error) {
	wireReq, err := buildDNSQuery(host, qtype)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wireReq))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDoHEndpointDown, err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDoHEndpointDown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: doh %s status %d", errDoHEndpointDown, endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDoHEndpointDown, err)
	}
	return parseDNSResponseIPs(body)
}

// buildDNSQuery encodes a minimal RFC 1035 DNS query for host and qtype (1=A, 28=AAAA).
func buildDNSQuery(host string, qtype uint16) ([]byte, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, errors.New("empty DNS hostname")
	}
	var buf bytes.Buffer
	// Header: ID=0x1234, Flags=0x0100 (RD=1), QDCOUNT=1, AN=0, NS=0, AR=0.
	hdr := [12]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	buf.Write(hdr[:])
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	buf.Write(tail[:])
	return buf.Bytes(), nil
}

// parseDNSResponseIPs extracts A and AAAA answer IPs from a raw RFC 1035 DNS message.
func parseDNSResponseIPs(msg []byte) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("dns response too short")
	}
	rcode := msg[3] & 0x0f
	if rcode != 0 {
		return nil, fmt.Errorf("dns rcode=%d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12

	skipName := func(pos int) (int, error) {
		for jumps := 0; jumps < 64; jumps++ {
			if pos >= len(msg) {
				return 0, errors.New("dns name truncated")
			}
			b := msg[pos]
			if b == 0 {
				return pos + 1, nil
			}
			if (b & 0xc0) == 0xc0 {
				if pos+1 >= len(msg) {
					return 0, errors.New("dns pointer truncated")
				}
				return pos + 2, nil
			}
			pos += 1 + int(b)
		}
		return 0, errors.New("dns name loop")
	}

	var err error
	for i := 0; i < qdCount; i++ {
		if off, err = skipName(off); err != nil {
			return nil, err
		}
		if off+4 > len(msg) {
			return nil, errors.New("dns question truncated")
		}
		off += 4
	}

	var ips []net.IP
	for i := 0; i < anCount; i++ {
		if off, err = skipName(off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("dns answer header truncated")
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("dns rdata truncated")
		}
		if rtype == 1 && rdlen == 4 {
			ip := make(net.IP, 4)
			copy(ip, msg[off:off+4])
			ips = append(ips, ip)
		} else if rtype == 28 && rdlen == 16 {
			ip := make(net.IP, 16)
			copy(ip, msg[off:off+16])
			ips = append(ips, ip)
		}
		off += rdlen
	}
	return ips, nil
}
