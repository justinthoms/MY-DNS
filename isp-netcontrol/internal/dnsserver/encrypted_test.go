package dnsserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testCert returns a certificate for 127.0.0.1 and the name "dns.test",
// and a pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dns.test"},
		DNSNames: []string{"dns.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestDNSOverTLSForClients(t *testing.T) {
	cert, pool := testCert(t)
	up := fakeUpstream(t)
	s := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{up}, Blocked: map[string]string{"bad.test": "x"}, Filtering: true,
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	defer s.Shutdown()
	addr := freeAddr(t)
	if err := s.ListenTLS([]string{addr}, &tls.Config{Certificates: []tls.Certificate{cert}}); err != nil {
		t.Fatal(err)
	}
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{RootCAs: pool, ServerName: "dns.test"}}
	for name, want := range map[string]int{"fine.test.": dns.RcodeSuccess, "x.bad.test.": dns.RcodeNameError} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		r, _, err := c.Exchange(m, addr)
		if err != nil || r.Rcode != want {
			t.Fatalf("%s over TLS: %v %v", name, r, err)
		}
	}
	if got := s.TLSAddrs(); len(got) != 1 || got[0] != addr {
		t.Fatalf("TLSAddrs %v", got)
	}
	// Turning it off closes the port.
	if err := s.ListenTLS(nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("DNS over TLS still listening after it was turned off")
	}
}

func TestResolveForDoH(t *testing.T) {
	up := fakeUpstream(t)
	s := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{up},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protect: Protection{MinimalANY: true}})
	m := new(dns.Msg)
	m.SetQuestion("fine.test.", dns.TypeA)
	if r := s.Resolve(netip.MustParseAddr("10.1.2.3"), m); r == nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("allowed client: %v", r)
	}
	if r := s.Resolve(netip.MustParseAddr("192.0.2.9"), m); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("client outside the access list: %v", r)
	}
	// Like TCP: ANY is not minimised (no amplification over HTTPS).
	m.SetQuestion("fine.test.", dns.TypeANY)
	if r := s.Resolve(netip.MustParseAddr("10.1.2.3"), m); r == nil || len(r.Answer) == 1 && r.Answer[0].Header().Rrtype == dns.TypeHINFO {
		t.Fatalf("ANY over HTTPS: %v", r)
	}
}

func TestTLSUpstreamReusesConnections(t *testing.T) {
	cert, pool := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	counting := &countingListener{Listener: ln, n: &accepted}
	srv := &dns.Server{Listener: counting, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.53")})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	up := "tls://" + ln.Addr().String() + "#dns.test"
	s := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{up},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}, WithUpstreamRoots(pool))
	for i := 0; i < 10; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("n"+string(rune('a'+i))+".test"), dns.TypeA)
		r := s.Resolve(netip.MustParseAddr("127.0.0.1"), m)
		if r == nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.53" {
			t.Fatalf("query %d via tls upstream: %v", i, r)
		}
	}
	if n := accepted.Load(); n != 1 {
		t.Fatalf("%d TLS connections for 10 sequential queries, want 1", n)
	}
	// A wrong certificate name is refused (SERVFAIL, upstream marked failed).
	s2 := New(&Policy{BlockMode: "nxdomain", Upstreams: []string{"tls://" + ln.Addr().String() + "#other.test"},
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}, WithUpstreamRoots(pool))
	m := new(dns.Msg)
	m.SetQuestion("x.test.", dns.TypeA)
	if r := s2.Resolve(netip.MustParseAddr("127.0.0.1"), m); r == nil || r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("wrong certificate name accepted: %v", r)
	}
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func TestParseTLSUpstream(t *testing.T) {
	cases := map[string][2]string{
		"tls://1.1.1.1#cloudflare-dns.com": {"1.1.1.1:853", "cloudflare-dns.com"},
		"tls://9.9.9.9:8853":               {"9.9.9.9:8853", "9.9.9.9"},
		"tls://[2606:4700::1111]#one.one":  {"[2606:4700::1111]:853", "one.one"},
	}
	for in, want := range cases {
		a, n, err := ParseTLSUpstream(in)
		if err != nil || a != want[0] || n != want[1] {
			t.Errorf("%s: %s %s %v", in, a, n, err)
		}
	}
	if _, _, err := ParseTLSUpstream("tls://dns.google"); err == nil {
		t.Error("hostname accepted")
	}
}
