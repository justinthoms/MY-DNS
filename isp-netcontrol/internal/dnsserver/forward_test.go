package dnsserver

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// upstreamWith answers every A query with ip after delay; a negative delay
// means it never answers (a black hole). n counts the queries it received.
func upstreamWith(t *testing.T, delay time.Duration, ip string, n *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)
		if delay < 0 {
			return
		}
		time.Sleep(delay)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func resolveTimed(s *Server, name string) (*dns.Msg, time.Duration) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	t0 := time.Now()
	r := s.Resolve(netip.MustParseAddr("127.0.0.1"), m)
	return r, time.Since(t0)
}

// A slow first upstream (an uncached recursive lookup) must not hold the
// answer back: after hedgeDelay the next upstream is asked as well.
func TestSlowUpstreamIsHedged(t *testing.T) {
	var slowN, fastN atomic.Int32
	slow := upstreamWith(t, 2*time.Second, "192.0.2.1", &slowN)
	fast := upstreamWith(t, 0, "192.0.2.2", &fastN)
	s := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{slow, fast},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	r, took := resolveTimed(s, "slow.example")
	if r == nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.2" {
		t.Fatalf("answer %v", r)
	}
	if took < hedgeDelay || took > hedgeDelay+500*time.Millisecond {
		t.Fatalf("answered after %v, want about %v", took, hedgeDelay)
	}
	// A fast first upstream is used alone.
	var aN, bN atomic.Int32
	a := upstreamWith(t, 0, "192.0.2.3", &aN)
	b := upstreamWith(t, 0, "192.0.2.4", &bN)
	s2 := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{a, b},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	for i := 0; i < 5; i++ {
		resolveTimed(s2, "n"+string(rune('a'+i))+".example")
	}
	if aN.Load() != 5 || bN.Load() != 0 {
		t.Fatalf("first upstream %d queries, second %d; want 5 and 0", aN.Load(), bN.Load())
	}
}

// When no upstream answers, the client gets SERVFAIL within the budget (not
// silence), and the failure is remembered briefly (RFC 9520).
func TestUnansweredLookupEndsWithinBudgetAndIsCached(t *testing.T) {
	var n1, n2 atomic.Int32
	hole1 := upstreamWith(t, -1, "", &n1)
	hole2 := upstreamWith(t, -1, "", &n2)
	s := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{hole1, hole2},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	addr := freeAddr(t)
	if err := s.Listen([]string{addr}); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	ask := func() (*dns.Msg, time.Duration) {
		m := new(dns.Msg)
		m.SetQuestion("dead.example.", dns.TypeA)
		t0 := time.Now()
		r, _, err := (&dns.Client{Timeout: 5 * time.Second}).Exchange(m, addr)
		if err != nil {
			t.Fatalf("no answer within a client's 5 s timeout: %v", err)
		}
		return r, time.Since(t0)
	}
	r, took := ask()
	if r.Rcode != dns.RcodeServerFailure || took > forwardBudget+300*time.Millisecond {
		t.Fatalf("rcode %s after %v", dns.RcodeToString[r.Rcode], took)
	}
	if n1.Load() != 1 || n2.Load() != 1 {
		t.Fatalf("upstream queries %d, %d", n1.Load(), n2.Load())
	}
	// Asked again at once: answered from the failure cache, upstreams untouched.
	r, took = ask()
	if r.Rcode != dns.RcodeServerFailure || took > 100*time.Millisecond || n1.Load() != 1 {
		t.Fatalf("repeat: rcode %s after %v, upstream queries %d", dns.RcodeToString[r.Rcode], took, n1.Load())
	}
	if st := s.Stats(); st.Failed != 2 || st.Cached != 0 {
		t.Fatalf("stats %+v", st)
	}
	for _, u := range s.UpstreamStats() {
		if u.Failures != 1 {
			t.Fatalf("%s: %+v", u.Addr, u)
		}
	}
}
