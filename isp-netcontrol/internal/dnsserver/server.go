// Package dnsserver is ISP NetControl's resolver: it answers subscribers'
// queries, applies the block and allow lists when DNS filtering is licensed,
// and forwards everything else to the configured upstream resolvers.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Policy is an immutable snapshot of the resolver configuration. It is
// swapped atomically whenever the console changes something.
type Policy struct {
	Filtering      bool              // DNS filtering licensed and enabled
	Blocked        map[string]string // domain -> category
	Allowed        map[string]bool   // overrides Blocked
	BlockMode      string            // "nxdomain" or "sinkhole"
	SinkholeV4     net.IP            // answer for A queries in sinkhole mode
	SinkholeV6     net.IP            // answer for AAAA queries in sinkhole mode
	Upstreams      []string          // host:port
	AllowedClients []netip.Prefix    // who may query (prevents an open resolver)
	Records        Records           // local DNS records; answered before filtering
	LogQueries     bool              // query-log feature licensed
}

// QueryEvent is emitted for the query log.
type QueryEvent struct {
	At     time.Time
	Client netip.Addr
	Name   string
	Type   string
	Action string // forwarded, cached, blocked, refused, failed, local
}

// Stats are cumulative counters since start.
type Stats struct {
	Total     uint64 `json:"total"`
	Forwarded uint64 `json:"forwarded"`
	Cached    uint64 `json:"cached"`
	Blocked   uint64 `json:"blocked"`
	Refused   uint64 `json:"refused"`
	Failed    uint64 `json:"failed"`
	Local     uint64 `json:"local"`
}

// Sub returns the counters accumulated since an earlier snapshot.
func (a Stats) Sub(b Stats) Stats {
	return Stats{Total: a.Total - b.Total, Forwarded: a.Forwarded - b.Forwarded, Cached: a.Cached - b.Cached,
		Blocked: a.Blocked - b.Blocked, Refused: a.Refused - b.Refused, Failed: a.Failed - b.Failed, Local: a.Local - b.Local}
}

// Add sums two sets of counters.
func (a Stats) Add(b Stats) Stats {
	return Stats{Total: a.Total + b.Total, Forwarded: a.Forwarded + b.Forwarded, Cached: a.Cached + b.Cached,
		Blocked: a.Blocked + b.Blocked, Refused: a.Refused + b.Refused, Failed: a.Failed + b.Failed, Local: a.Local + b.Local}
}

// Server is a running resolver.
type Server struct {
	policy  atomic.Pointer[Policy]
	cache   *cache
	events  chan QueryEvent
	lmu     sync.Mutex // guards servers and addrs
	servers []*dns.Server
	addrs   []string
	stats   struct{ total, forwarded, cached, blocked, refused, failed, local atomic.Uint64 }
	client  *dns.Client
	tcp     *dns.Client
}

// New creates a server with an initial policy.
func New(p *Policy) *Server {
	s := &Server{
		cache:  newCache(20000),
		events: make(chan QueryEvent, 4096),
		client: &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: dns.DefaultMsgSize},
		tcp:    &dns.Client{Net: "tcp", Timeout: 3 * time.Second},
	}
	s.SetPolicy(p)
	return s
}

// SetPolicy replaces the active policy. The cache is cleared because block
// decisions are not cached but sinkhole answers depend on the policy.
func (s *Server) SetPolicy(p *Policy) {
	s.policy.Store(p)
	s.cache.clear()
}

// Policy returns the active policy.
func (s *Server) Policy() *Policy { return s.policy.Load() }

// Events delivers query-log events. Events are dropped if nobody reads fast enough.
func (s *Server) Events() <-chan QueryEvent { return s.events }

// Stats returns the counters.
func (s *Server) Stats() Stats {
	return Stats{
		Total: s.stats.total.Load(), Forwarded: s.stats.forwarded.Load(), Cached: s.stats.cached.Load(),
		Blocked: s.stats.blocked.Load(), Refused: s.stats.refused.Load(), Failed: s.stats.failed.Load(),
		Local: s.stats.local.Load(),
	}
}

// Listen (re)binds the resolver to addrs ("host:port"; ":53" means every
// address). Sockets are opened synchronously, so a bad address is reported
// at once. If any address fails, the previous listeners are restored and
// the error is returned.
func (s *Server) Listen(addrs []string) error {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if len(addrs) == 0 {
		return errors.New("no listen addresses")
	}
	old := s.addrs
	s.stopLocked()
	if err := s.bindLocked(addrs); err != nil {
		s.stopLocked()
		if len(old) > 0 {
			if rerr := s.bindLocked(old); rerr != nil {
				log.Printf("dns: could not restore previous listeners %v: %v", old, rerr)
			}
		}
		return err
	}
	log.Printf("dns: listening on %s (udp+tcp)", strings.Join(addrs, ", "))
	return nil
}

func (s *Server) bindLocked(addrs []string) error {
	var started []*dns.Server
	for _, addr := range addrs {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			closeServers(started)
			return fmt.Errorf("dns udp %s: %w", addr, err)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			closeServers(started)
			return fmt.Errorf("dns tcp %s: %w", addr, err)
		}
		u := &dns.Server{PacketConn: pc, Handler: s}
		t := &dns.Server{Listener: ln, Handler: s}
		go func() { _ = u.ActivateAndServe() }()
		go func() { _ = t.ActivateAndServe() }()
		started = append(started, u, t)
	}
	s.servers = started
	s.addrs = append([]string(nil), addrs...)
	return nil
}

func (s *Server) stopLocked() {
	closeServers(s.servers)
	s.servers, s.addrs = nil, nil
}

// closeServers stops servers and always closes their sockets: Shutdown
// alone does nothing for a server whose serve loop has not started yet,
// which would leave the port bound.
func closeServers(list []*dns.Server) {
	for _, srv := range list {
		_ = srv.Shutdown()
		if srv.PacketConn != nil {
			_ = srv.PacketConn.Close()
		}
		if srv.Listener != nil {
			_ = srv.Listener.Close()
		}
	}
}

// Addrs returns the addresses currently listened on.
func (s *Server) Addrs() []string {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	return append([]string(nil), s.addrs...)
}

// ListenAndServe listens on addrs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addrs []string) error {
	if err := s.Listen(addrs); err != nil {
		return err
	}
	<-ctx.Done()
	s.Shutdown()
	return nil
}

// Shutdown stops all listeners.
func (s *Server) Shutdown() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	s.stopLocked()
}

// Decide returns the filtering decision for a name: "allowed", "blocked" or
// "" (not listed). A listed domain also covers all of its subdomains, and an
// allow entry wins over a block entry at any level.
func (p *Policy) Decide(name string) (decision, category string) {
	d, cat, _ := p.Explain(name)
	return d, cat
}

// Explain is Decide plus the list entry that matched.
func (p *Policy) Explain(name string) (decision, category, matched string) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	blockedCat, blockedBy := "", ""
	for n := name; n != ""; {
		if p.Allowed[n] {
			return "allowed", "", n
		}
		if cat, ok := p.Blocked[n]; ok && blockedBy == "" {
			blockedCat, blockedBy = cat, n
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	if blockedBy != "" {
		return "blocked", blockedCat, blockedBy
	}
	return "", "", ""
}

func (p *Policy) clientAllowed(a netip.Addr) bool {
	a = a.Unmap()
	for _, pre := range p.AllowedClients {
		if pre.Contains(a) {
			return true
		}
	}
	return false
}

func clientAddr(w dns.ResponseWriter) netip.Addr {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

func (s *Server) emit(p *Policy, ev QueryEvent) {
	if !p.LogQueries {
		return
	}
	select {
	case s.events <- ev:
	default:
	}
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	p := s.policy.Load()
	s.stats.total.Add(1)
	client := clientAddr(w)
	if len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery {
		s.reply(w, req, dns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	ev := QueryEvent{At: time.Now().UTC(), Client: client, Name: strings.TrimSuffix(strings.ToLower(q.Name), "."), Type: dns.TypeToString[q.Qtype]}

	if !p.clientAllowed(client) {
		s.stats.refused.Add(1)
		ev.Action = "refused"
		s.emit(p, ev)
		s.reply(w, req, dns.RcodeRefused)
		return
	}
	if rrs := p.Records.Lookup(q.Name); rrs != nil {
		s.stats.local.Add(1)
		ev.Action = "local"
		s.emit(p, ev)
		_ = w.WriteMsg(s.answerLocal(p, req, rrs))
		return
	}
	if p.Filtering {
		if d, _ := p.Decide(q.Name); d == "blocked" {
			s.stats.blocked.Add(1)
			ev.Action = "blocked"
			s.emit(p, ev)
			_ = w.WriteMsg(s.blockedAnswer(p, req))
			return
		}
	}
	if resp := s.cache.get(req); resp != nil {
		s.stats.cached.Add(1)
		ev.Action = "cached"
		s.emit(p, ev)
		_ = w.WriteMsg(resp)
		return
	}
	resp, err := s.forward(p, req)
	if err != nil {
		s.stats.failed.Add(1)
		ev.Action = "failed"
		s.emit(p, ev)
		s.reply(w, req, dns.RcodeServerFailure)
		return
	}
	s.stats.forwarded.Add(1)
	ev.Action = "forwarded"
	s.emit(p, ev)
	s.cache.put(req, resp)
	resp.Id = req.Id
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := uint16(dns.MinMsgSize)
		if o := req.IsEdns0(); o != nil {
			size = o.UDPSize()
		}
		resp.Truncate(int(size))
	}
	_ = w.WriteMsg(resp)
}

func (s *Server) reply(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	_ = w.WriteMsg(m)
}

func (s *Server) blockedAnswer(p *Policy, req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	q := req.Question[0]
	if p.BlockMode == "sinkhole" {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: p.SinkholeV4})
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: p.SinkholeV6})
		}
		return m
	}
	m.Rcode = dns.RcodeNameError
	return m
}

func (s *Server) forward(p *Policy, req *dns.Msg) (*dns.Msg, error) {
	out := req.Copy()
	out.Id = dns.Id()
	if out.IsEdns0() == nil {
		out.SetEdns0(dns.DefaultMsgSize, false)
	}
	var lastErr error = errors.New("no upstream resolvers configured")
	for _, up := range p.Upstreams {
		resp, _, err := s.client.Exchange(out, up)
		if err == nil && resp.Truncated {
			resp, _, err = s.tcp.Exchange(out, up)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			lastErr = errors.New("upstream " + up + " answered " + dns.RcodeToString[resp.Rcode])
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// Probe checks that the resolver can answer: it must be listening and an
// upstream must resolve name (the cache is bypassed). Used by the anycast
// health check.
func (s *Server) Probe(ctx context.Context, name string) error {
	if len(s.Addrs()) == 0 {
		return errors.New("DNS is not listening")
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	type res struct {
		r   *dns.Msg
		err error
	}
	ch := make(chan res, 1)
	go func() { r, err := s.forward(s.policy.Load(), m); ch <- res{r, err} }()
	select {
	case <-ctx.Done():
		return fmt.Errorf("no answer for %s: %w", name, ctx.Err())
	case x := <-ch:
		if x.err != nil {
			return fmt.Errorf("upstream: %w", x.err)
		}
		if x.r.Rcode != dns.RcodeSuccess && x.r.Rcode != dns.RcodeNameError {
			return fmt.Errorf("upstream answered %s for %s", dns.RcodeToString[x.r.Rcode], name)
		}
		return nil
	}
}
