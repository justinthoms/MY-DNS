package dnsserver

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, name, typ string, value string, prio uint16) dns.RR {
	t.Helper()
	rr, err := BuildRR(name, typ, 300, value, prio)
	if err != nil {
		t.Fatalf("BuildRR(%s %s %s): %v", name, typ, value, err)
	}
	return rr
}

func TestBuildRRValidation(t *testing.T) {
	bad := [][3]string{
		{"host.lan", "A", "2001:db8::1"},
		{"host.lan", "AAAA", "10.0.0.1"},
		{"host.lan", "CNAME", "host.lan"},
		{"bad name!", "A", "10.0.0.1"},
		{"host.lan", "SRV", "x"},
		{"host.lan", "MX", "not a host!"},
	}
	for _, b := range bad {
		if _, err := BuildRR(b[0], b[1], 300, b[2], 10); err == nil {
			t.Errorf("accepted %v", b)
		}
	}
	ptr := mustRR(t, "192.168.1.10", "PTR", "nas.office.lan", 0)
	if ptr.Header().Name != "10.1.168.192.in-addr.arpa." {
		t.Fatalf("PTR from IP: %s", ptr.Header().Name)
	}
	long := mustRR(t, "txt.lan", "TXT", string(make([]byte, 300)), 0).(*dns.TXT)
	if len(long.Txt) != 2 {
		t.Fatalf("long TXT not split: %d parts", len(long.Txt))
	}
	r := Records{}
	_ = r.Add(mustRR(t, "a.lan", "A", "10.0.0.1", 0))
	if err := r.Add(mustRR(t, "a.lan", "CNAME", "b.lan", 0)); err == nil {
		t.Fatal("CNAME next to A accepted")
	}
}

func TestLocalRecordsEndToEnd(t *testing.T) {
	up := fakeUpstream(t) // answers every A query with 192.0.2.1
	recs := Records{}
	for _, rr := range []dns.RR{
		mustRR(t, "nas.office.lan", "A", "192.168.1.10", 0),
		mustRR(t, "nas.office.lan", "AAAA", "2001:db8::10", 0),
		mustRR(t, "files.office.lan", "CNAME", "nas.office.lan", 0),
		mustRR(t, "portal.isp.example", "CNAME", "cdn.example.net", 0),
		mustRR(t, "*.dev.lan", "A", "10.9.9.9", 0),
		mustRR(t, "office.lan", "MX", "mail.office.lan", 5),
		mustRR(t, "ads.example.com", "A", "10.1.1.1", 0), // local record wins over the block list
	} {
		if err := recs.Add(rr); err != nil {
			t.Fatal(err)
		}
	}
	p := &Policy{
		Filtering: true, BlockMode: "nxdomain", Upstreams: []string{up}, Records: recs,
		Blocked: map[string]string{"ads.example.com": "ads"}, Allowed: map[string]bool{},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
	s := New(p)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.ListenAndServe(ctx, []string{addr}) }()
	time.Sleep(200 * time.Millisecond)

	ask := func(name string, qt uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		r, _, err := new(dns.Client).Exchange(m, addr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}
	values := func(r *dns.Msg) []string {
		var out []string
		for _, rr := range r.Answer {
			switch x := rr.(type) {
			case *dns.A:
				out = append(out, x.A.String())
			case *dns.AAAA:
				out = append(out, x.AAAA.String())
			case *dns.CNAME:
				out = append(out, "->"+x.Target)
			case *dns.MX:
				out = append(out, x.Mx)
			}
		}
		return out
	}
	check := func(name string, qt uint16, want ...string) {
		t.Helper()
		r := ask(name, qt)
		got := values(r)
		if r.Rcode != dns.RcodeSuccess || len(got) != len(want) {
			t.Fatalf("%s %s: rcode %s answers %v, want %v", name, dns.TypeToString[qt], dns.RcodeToString[r.Rcode], got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s %s: answers %v, want %v", name, dns.TypeToString[qt], got, want)
			}
		}
	}
	check("nas.office.lan", dns.TypeA, "192.168.1.10")
	check("NAS.Office.LAN", dns.TypeAAAA, "2001:db8::10")
	check("files.office.lan", dns.TypeA, "->nas.office.lan.", "192.168.1.10")
	check("portal.isp.example", dns.TypeA, "->cdn.example.net.", "192.0.2.1") // CNAME chased upstream
	check("anything.dev.lan", dns.TypeA, "10.9.9.9")                          // wildcard
	check("office.lan", dns.TypeMX, "mail.office.lan.")
	check("nas.office.lan", dns.TypeTXT) // NODATA: name exists locally
	check("ads.example.com", dns.TypeA, "10.1.1.1")
	if r := ask("other.example.com", dns.TypeA); len(values(r)) != 1 {
		t.Fatalf("forwarding broke: %v", r)
	}
	if st := s.Stats(); st.Local != 8 {
		t.Fatalf("local counter = %d, want 8", st.Local)
	}
}
