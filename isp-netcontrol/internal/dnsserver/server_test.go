package dnsserver

import (
	"context"
	"net"
	"net/netip"
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
