package dnsserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// nxUpstream answers NXDOMAIN for names starting with "rnd" and 192.0.2.1
// for everything else.
func nxUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if strings.HasPrefix(q.Name, "rnd") {
			m.Rcode = dns.RcodeNameError
		} else {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func startProtected(t *testing.T, pr Protection) (*Server, *Policy, string) {
	t.Helper()
	p := &Policy{BlockMode: "nxdomain", Upstreams: []string{nxUpstream(t)},
		Blocked: map[string]string{}, Allowed: map[string]bool{},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Protect: pr}
	s := New(p)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.ListenAndServe(ctx, []string{addr}) }()
	time.Sleep(200 * time.Millisecond)
	return s, p, addr
}

func query(addr, network, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: network, Timeout: 300 * time.Millisecond}
	r, _, err := c.Exchange(m, addr)
	return r, err
}

// burst sends n queries at once from one socket and counts the answers.
func burst(t *testing.T, addr string, n int) int {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < n; i++ {
		m := new(dns.Msg)
		m.SetQuestion("fine.test.", dns.TypeA)
		b, _ := m.Pack()
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	got, buf := 0, make([]byte, 1500)
	for {
		if _, err := conn.Read(buf); err != nil {
			return got
		}
		got++
	}
}

func TestRateLimitDropsFloods(t *testing.T) {
	s, p, addr := startProtected(t, Protection{RateLimit: 5, Burst: 5})
	answered := burst(t, addr, 20)
	if answered < 5 || answered > 9 { // 5 at once, plus a few refilled while sending on a busy machine
		t.Fatalf("answered %d of 20 with a limit of 5/s", answered)
	}
	st := s.ProtectionStatus()
	if st.RateLimited < 8 || len(st.LimitedClients) != 1 || st.LimitedClients[0].Client != "127.0.0.1" {
		t.Fatalf("status %+v", st)
	}
	if got := s.Stats().Total; got != uint64(answered) {
		t.Fatalf("Total %d counts dropped queries (answered %d)", got, answered)
	}
	// TCP clients are told instead of being ignored.
	refused := false
	for i := 0; i < 10 && !refused; i++ {
		r, err := query(addr, "tcp", "fine.test", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		refused = r.Rcode == dns.RcodeRefused
	}
	if !refused {
		t.Fatal("tcp over the limit was answered")
	}
	// Exempt networks are never limited.
	np := *p
	np.Protect.RateLimitExempt = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s.SetPolicy(&np)
	for i := 0; i < 20; i++ {
		if _, err := query(addr, "udp", "fine.test", dns.TypeA); err != nil {
			t.Fatalf("exempt client limited: %v", err)
		}
	}
}

func TestMinimalANY(t *testing.T) {
	s, _, addr := startProtected(t, Protection{MinimalANY: true})
	r, err := query(addr, "udp", "fine.test", dns.TypeANY)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeHINFO || r.Answer[0].(*dns.HINFO).Cpu != "RFC8482" {
		t.Fatalf("ANY over UDP: %v", r)
	}
	// Over TCP (no amplification possible) the query is forwarded.
	r, err = query(addr, "tcp", "fine.test", dns.TypeANY)
	if err != nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) == 1 && r.Answer[0].Header().Rrtype == dns.TypeHINFO {
		t.Fatalf("ANY over TCP: %v %v", r, err)
	}
	if st := s.ProtectionStatus(); st.MinimalANY != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestRandomSubdomainAttackIsThrottled(t *testing.T) {
	s, _, addr := startProtected(t, Protection{TortureThreshold: 20, TortureLimit: 2, TortureHold: time.Minute})
	// A legitimate name, cached before the attack.
	if r, err := query(addr, "udp", "www.victim.example", dns.TypeA); err != nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("warm-up: %v %v", r, err)
	}
	servfail := 0
	for i := 0; i < 60; i++ {
		r, err := query(addr, "udp", fmt.Sprintf("rnd%d-x7q.victim.example", i), dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if r.Rcode == dns.RcodeServerFailure {
			servfail++
		}
	}
	// 20 NXDOMAIN start the throttle; then about 2 per second get through.
	if servfail < 30 {
		t.Fatalf("only %d of 60 random names throttled", servfail)
	}
	st := s.ProtectionStatus()
	if len(st.Zones) != 1 || st.Zones[0].Zone != "victim.example" || st.Zones[0].Throttled == 0 || st.Throttled != uint64(servfail) {
		t.Fatalf("status %+v (servfail %d)", st, servfail)
	}
	// Cached answers for the domain are still served, and other domains are unaffected.
	if r, _ := query(addr, "udp", "www.victim.example", dns.TypeA); r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("cached name under attacked domain: %v", r)
	}
	for i := 0; i < 10; i++ {
		if r, _ := query(addr, "udp", fmt.Sprintf("host%d.other.example", i), dns.TypeA); r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("other domain: %v", r)
		}
	}
}

func TestZoneOf(t *testing.T) {
	for in, want := range map[string]string{
		"a8f3k.www.example.com.": "example.com",
		"x.example.co.uk":        "example.co.uk",
		"Foo.Bar.Example.IN.":    "example.in",
		"localhost.":             "localhost",
	} {
		if got := zoneOf(in); got != want {
			t.Errorf("zoneOf(%q) = %q, want %q", in, got, want)
		}
	}
}
