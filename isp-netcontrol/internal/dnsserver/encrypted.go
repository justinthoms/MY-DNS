package dnsserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ---- DNS over TLS (RFC 7858) for clients ----------------------------------

// ListenTLS serves DNS over TLS on addrs (for example ":853") with cfg.
// An empty addrs stops it. On error the previous listeners are kept.
func (s *Server) ListenTLS(addrs []string, cfg *tls.Config) error {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	var started []*dns.Server
	var lns []net.Listener
	for _, addr := range addrs {
		ln, err := tls.Listen("tcp", addr, cfg)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return fmt.Errorf("dns over tls %s: %w", addr, err)
		}
		lns = append(lns, ln)
	}
	closeServers(s.tlsServers)
	s.tlsServers, s.tlsAddrs = nil, nil
	for i, ln := range lns {
		srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: s, ReadTimeout: 10 * time.Second, IdleTimeout: func() time.Duration { return 30 * time.Second }}
		go func() { _ = srv.ActivateAndServe() }()
		started = append(started, srv)
		s.tlsAddrs = append(s.tlsAddrs, addrs[i])
	}
	s.tlsServers = started
	if len(addrs) > 0 {
		log.Printf("dns: DNS over TLS on %s", strings.Join(addrs, ", "))
	}
	return nil
}

// TLSAddrs returns the addresses DNS over TLS is served on.
func (s *Server) TLSAddrs() []string {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	return append([]string(nil), s.tlsAddrs...)
}

// ---- DNS over HTTPS (RFC 8484) for clients ---------------------------------

// Resolve answers req for client exactly as a query over TCP would be
// answered (same access list, protection, filtering and cache). It returns
// nil when the query is dropped. Used for DNS over HTTPS.
func (s *Server) Resolve(client netip.Addr, req *dns.Msg) *dns.Msg {
	w := &memWriter{remote: &net.TCPAddr{IP: client.AsSlice()}}
	s.ServeDNS(w, req)
	return w.msg
}

// memWriter is a dns.ResponseWriter that keeps the answer in memory.
type memWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (w *memWriter) LocalAddr() net.Addr       { return &net.TCPAddr{} }
func (w *memWriter) RemoteAddr() net.Addr      { return w.remote }
func (w *memWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *memWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	w.msg = m
	return len(b), nil
}
func (w *memWriter) Close() error        { return nil }
func (w *memWriter) TsigStatus() error   { return nil }
func (w *memWriter) TsigTimersOnly(bool) {}
func (w *memWriter) Hijack()             {}

// ---- DNS over TLS to the upstream resolvers --------------------------------

// WithUpstreamRoots sets the CAs trusted for tls:// upstreams instead of the
// system's (for private resolvers and tests).
func WithUpstreamRoots(pool *x509.CertPool) Option { return func(s *Server) { s.dot.roots = pool } }

// ParseTLSUpstream splits "tls://IP[:port][#name]" into the address and the
// name the server's certificate must carry (the IP when no name is given).
func ParseTLSUpstream(u string) (addr, serverName string, err error) {
	rest, ok := strings.CutPrefix(u, "tls://")
	if !ok {
		return "", "", errors.New("not a tls:// upstream")
	}
	rest, serverName, _ = strings.Cut(rest, "#")
	if _, _, err := net.SplitHostPort(rest); err != nil {
		rest = net.JoinHostPort(strings.Trim(rest, "[]"), "853")
	}
	host, _, _ := net.SplitHostPort(rest)
	if _, err := netip.ParseAddr(host); err != nil {
		return "", "", fmt.Errorf("upstream %q: give an IP address, and the certificate name after #, e.g. tls://1.1.1.1#cloudflare-dns.com", u)
	}
	if serverName == "" {
		serverName = host
	}
	return rest, serverName, nil
}

// dotPool keeps TLS connections to the upstream resolvers open, so a query
// does not pay for a TLS handshake.
type dotPool struct {
	mu    sync.Mutex
	conns map[string]chan *dns.Conn
	roots *x509.CertPool // nil: the system's trusted roots
}

const dotIdlePerUpstream = 32

func (p *dotPool) idle(up string) chan *dns.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns == nil {
		p.conns = map[string]chan *dns.Conn{}
	}
	ch := p.conns[up]
	if ch == nil {
		ch = make(chan *dns.Conn, dotIdlePerUpstream)
		p.conns[up] = ch
	}
	return ch
}

func (p *dotPool) dial(up string) (*dns.Conn, error) {
	addr, name, err := ParseTLSUpstream(up)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
	cfg.RootCAs = p.roots
	d := &net.Dialer{Timeout: 3 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return &dns.Conn{Conn: c, UDPSize: dns.MaxMsgSize}, nil
}

// exchange sends m over a pooled connection. A reused connection that the
// server has closed meanwhile is replaced once.
func (p *dotPool) exchange(m *dns.Msg, up string) (*dns.Msg, error) {
	ch := p.idle(up)
	for attempt := 0; ; attempt++ {
		var c *dns.Conn
		reused := false
		select {
		case c = <-ch:
			reused = true
		default:
			var err error
			if c, err = p.dial(up); err != nil {
				return nil, err
			}
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		err := c.WriteMsg(m)
		var r *dns.Msg
		if err == nil {
			r, err = c.ReadMsg()
		}
		if err == nil && r.Id != m.Id {
			err = errors.New("upstream answered a different query")
		}
		if err != nil {
			c.Close()
			if reused && attempt == 0 {
				continue
			}
			return nil, err
		}
		select {
		case ch <- c:
		default:
			c.Close()
		}
		return r, nil
	}
}
