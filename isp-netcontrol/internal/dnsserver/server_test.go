package dnsserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDecide(t *testing.T) {
	p := &Policy{
		Blocked: map[string]string{"ads.example": "ads", "bad.test": "malware"},
		Allowed: map[string]bool{"ok.ads.example": true},
	}
	cases := map[string]string{
		"ads.example.":         "blocked",
		"x.y.ads.example":      "blocked",
		"ok.ads.example.":      "allowed",
		"deep.ok.ads.example.": "allowed",
		"example.":             "",
		"notads.example":       "",
		"BAD.Test.":            "blocked",
	}
	for name, want := range cases {
		if got, _ := p.Decide(name); got != want {
			t.Errorf("Decide(%q) = %q, want %q", name, got, want)
		}
	}
}

// fakeUpstream answers every A query with 192.0.2.1.
func fakeUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func freeAddr(t *testing.T) string {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	l.Close()
	return addr
}

func TestResolverEndToEnd(t *testing.T) {
	up := fakeUpstream(t)
	p := &Policy{
		Filtering: true, BlockMode: "nxdomain", Upstreams: []string{up},
		Blocked:        map[string]string{"blocked.test": "test"},
		Allowed:        map[string]bool{},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
	s := New(p)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.ListenAndServe(ctx, []string{addr}) }()
	time.Sleep(200 * time.Millisecond)

	ask := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		r, _, err := new(dns.Client).Exchange(m, addr)
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		return r
	}
	if r := ask("www.blocked.test"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked: rcode %s", dns.RcodeToString[r.Rcode])
	}
	if r := ask("fine.test"); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("forwarded: %v", r)
	}
	ask("fine.test")
	if st := s.Stats(); st.Blocked != 1 || st.Forwarded != 1 || st.Cached != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Filtering off (e.g. trial expired): the blocked name now resolves.
	np := *p
	np.Filtering = false
	s.SetPolicy(&np)
	if r := ask("www.blocked.test"); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("unfiltered: rcode %s", dns.RcodeToString[r.Rcode])
	}
	// Clients outside the allowed networks are refused.
	np2 := np
	np2.AllowedClients = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	s.SetPolicy(&np2)
	if r := ask("fine.test"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("acl: rcode %s", dns.RcodeToString[r.Rcode])
	}
}

func TestRebindAndRollback(t *testing.T) {
	up := fakeUpstream(t)
	s := New(&Policy{Upstreams: []string{up}, Allowed: map[string]bool{}, Blocked: map[string]string{},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	defer s.Shutdown()
	a1, a2 := freeAddr(t), strings.Replace(freeAddr(t), "127.0.0.1", "127.0.0.2", 1)
	ok := func(addr string) bool {
		m := new(dns.Msg)
		m.SetQuestion("x.example.", dns.TypeA)
		r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(m, addr)
		return err == nil && r.Rcode == dns.RcodeSuccess
	}
	if err := s.Listen([]string{a1}); err != nil || !ok(a1) {
		t.Fatalf("first bind: %v", err)
	}
	if err := s.Listen([]string{a2}); err != nil || !ok(a2) || ok(a1) {
		t.Fatalf("rebind: err=%v new=%v old=%v", err, ok(a2), ok(a1))
	}
	// 192.0.2.1 is not on this machine: the bind fails and a2 is restored.
	if err := s.Listen([]string{a2, "192.0.2.1:53"}); err == nil {
		t.Fatal("bind to a foreign address succeeded")
	}
	if !ok(a2) || len(s.Addrs()) != 1 || s.Addrs()[0] != a2 {
		t.Fatalf("not rolled back: addrs %v", s.Addrs())
	}
}

func TestNewCountersAndUpstreamHealth(t *testing.T) {
	// Upstream that answers NXDOMAIN for "gone.example" and A records otherwise.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "gone.example." {
			m.Rcode = dns.RcodeNameError
		} else {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = up.ActivateAndServe() }()
	defer up.Shutdown()
	dead := freeAddr(t) // nothing listens here
	s := New(&Policy{Filtering: true, BlockMode: "nxdomain", Upstreams: []string{dead, pc.LocalAddr().String()},
		Blocked: map[string]string{"bad.example": "malware"}, Allowed: map[string]bool{}, LogQueries: true,
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	s.client.Timeout = 300 * time.Millisecond
	addr := freeAddr(t)
	if err := s.Listen([]string{addr}); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	ask := func(n string) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(n), dns.TypeA)
		if _, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, addr); err != nil {
			t.Fatal(err)
		}
	}
	ask("gone.example")
	ask("gone.example") // from cache, still NXDOMAIN
	ask("ok.example")
	ask("ok2.example") // third failure in a row for the dead upstream
	ask("www.bad.example")
	st := s.Stats()
	if st.Nxdomain != 2 || st.LatencyCount != 3 || st.LatencyUsSum == 0 || st.Blocked != 1 {
		t.Fatalf("stats %+v", st)
	}
	ups := s.UpstreamStats()
	if len(ups) != 2 || *ups[0].Healthy || ups[0].Failures == 0 || !*ups[1].Healthy || ups[1].AvgMs <= 0 {
		t.Fatalf("upstreams %+v %+v", ups[0], ups[1])
	}
	var blockedEv QueryEvent
	for i := 0; i < 5; i++ {
		ev := <-s.Events()
		if ev.Action == "blocked" {
			blockedEv = ev
		}
	}
	if blockedEv.Category != "malware" {
		t.Fatalf("blocked event category %q", blockedEv.Category)
	}
}

func TestCoalescesIdenticalQueries(t *testing.T) {
	var upstreamQueries atomic.Int64
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamQueries.Add(1)
		time.Sleep(150 * time.Millisecond) // a slow upstream
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = up.ActivateAndServe() }()
	defer up.Shutdown()
	s := New(&Policy{Upstreams: []string{pc.LocalAddr().String()}, Allowed: map[string]bool{}, Blocked: map[string]string{},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	addr := freeAddr(t)
	if err := s.Listen([]string{addr}); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	var wg sync.WaitGroup
	var answered atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := new(dns.Msg)
			m.SetQuestion("burst.example.", dns.TypeA)
			r, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, addr)
			if err == nil && len(r.Answer) == 1 && r.Id == m.Id {
				answered.Add(1)
			}
		}()
	}
	wg.Wait()
	if answered.Load() != 50 {
		t.Fatalf("answered %d of 50", answered.Load())
	}
	if n := upstreamQueries.Load(); n > 3 {
		t.Fatalf("upstream got %d queries for one name; want them coalesced", n)
	}
	if st := s.Stats(); st.Coalesced == 0 {
		t.Fatalf("coalesced counter not set: %+v", st)
	}
}

func TestCacheEvictionIsBounded(t *testing.T) {
	c := newCache(640) // 10 per shard
	for i := 0; i < 5000; i++ {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("n%d.example.", i), dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")})
		c.put(req, resp)
	}
	if n := c.size(); n > 640 || n < 500 {
		t.Fatalf("cache size %d, want close to but not above 640", n)
	}
}

// An upstream that answers SERVFAIL (a broken name) is working: it must not
// be shown as down, and SERVFAIL is counted apart from real failures.
// Regression: with Unbound first, 1.1.1.1 and 8.8.8.8 only saw names that
// Unbound could not resolve and were shown as "Down".
func TestServfailIsNotAnUpstreamFailure(t *testing.T) {
	servfailUp := func() string {
		pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
		})}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
		return pc.LocalAddr().String()
	}
	first, second := servfailUp(), servfailUp()
	s := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{first, second},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	for i := 0; i < 5; i++ {
		m := new(dns.Msg)
		m.SetQuestion(fmt.Sprintf("broken%d.example.", i), dns.TypeA)
		if r := s.Resolve(netip.MustParseAddr("127.0.0.1"), m); r == nil || r.Rcode != dns.RcodeServerFailure {
			t.Fatalf("query %d: %v", i, r)
		}
	}
	for _, u := range s.UpstreamStats() {
		if u.Healthy == nil || !*u.Healthy || u.Failures != 0 || u.ServFail != 5 || u.Queries != 5 {
			t.Fatalf("%s: %+v", u.Addr, u)
		}
	}
}
