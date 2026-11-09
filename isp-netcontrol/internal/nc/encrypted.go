package nc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/miekg/dns"
)

// EncryptedSettings turns DNS over TLS (port 853) and DNS over HTTPS
// (https://<server>/dns-query) on or off for subscribers.
type EncryptedSettings struct {
	DoT bool `json:"dot"`
	DoH bool `json:"doh"`
}

func (a *App) encryptedSettings(ctx context.Context) EncryptedSettings {
	var s EncryptedSettings
	if _, err := a.getSetting(ctx, "dns.encrypted", &s); err != nil {
		log.Printf("settings: %v", err)
	}
	return s
}

// ---- Certificate ----------------------------------------------------------

// certStore serves the console certificate (fullchain.pem, privkey.pem in
// NC_TLS_DIR) and reloads it when the files change, so a renewed
// certificate is used without a restart.
type certStore struct {
	dir   string
	mu    sync.Mutex
	mtime time.Time
	cert  *tls.Certificate
	err   error
}

func (c *certStore) paths() (string, string) {
	return filepath.Join(c.dir, "fullchain.pem"), filepath.Join(c.dir, "privkey.pem")
}

func (c *certStore) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	certPath, keyPath := c.paths()
	st, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("no certificate in %s: %w", c.dir, err)
	}
	if c.cert != nil && st.ModTime().Equal(c.mtime) {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		c.err = err
		return c.cert, fmt.Errorf("certificate in %s: %w", c.dir, err)
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	c.cert, c.mtime, c.err = &cert, st.ModTime(), nil
	return c.cert, nil
}

func (c *certStore) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.get()
		},
	}
}

// CertInfo describes the certificate clients see.
type CertInfo struct {
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	Subject    string    `json:"subject"`
	Names      []string  `json:"names"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
}

func (c *certStore) info() CertInfo {
	cert, err := c.get()
	if err != nil || cert == nil || cert.Leaf == nil {
		msg := "no certificate"
		if err != nil {
			msg = err.Error()
		}
		return CertInfo{Error: msg, Names: []string{}}
	}
	l := cert.Leaf
	names := []string{}
	seen := map[string]bool{}
	for _, n := range l.DNSNames {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, ip := range l.IPAddresses {
		names = append(names, ip.String())
	}
	return CertInfo{OK: time.Now().Before(l.NotAfter), Subject: l.Subject.CommonName, Names: names, NotAfter: l.NotAfter.UTC(),
		SelfSigned: l.Issuer.String() == l.Subject.String()}
}

// ---- DNS over TLS listeners -------------------------------------------------

// dotAddrs derives the DNS-over-TLS addresses from the plain DNS addresses:
// the same IPs, port (853 when 0).
func dotAddrs(dnsAddrs []string, port int) []string {
	if port == 0 {
		port = 853
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range dnsAddrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		d := net.JoinHostPort(host, strconv.Itoa(port))
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// applyDoT starts, moves or stops DNS over TLS to match the settings and
// the current DNS addresses.
func (a *App) applyDoT(ctx context.Context) error {
	if !a.encryptedSettings(ctx).DoT {
		return a.dns.ListenTLS(nil, nil)
	}
	want := dotAddrs(a.dns.Addrs(), a.cfg.DoTPort)
	if sameSet(want, a.dns.TLSAddrs()) {
		return nil
	}
	if _, err := a.certs.get(); err != nil {
		return err
	}
	return a.dns.ListenTLS(want, a.certs.tlsConfig())
}

func (a *App) getEncrypted(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"settings": a.encryptedSettings(c.UserContext()), "dot_listening": nonNil(a.dns.TLSAddrs()),
		"certificate": a.certs.info()})
}

func (a *App) updateEncrypted(c *fiber.Ctx) error {
	ctx := c.UserContext()
	var s EncryptedSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	if s.DoT || s.DoH {
		if _, err := a.certs.get(); err != nil {
			return bad(c, "encrypted DNS needs the console certificate: "+err.Error())
		}
	}
	old := a.encryptedSettings(ctx)
	if err := a.putSetting(ctx, "dns.encrypted", s); err != nil {
		return err
	}
	if err := a.applyDoT(ctx); err != nil {
		_ = a.putSetting(ctx, "dns.encrypted", old)
		_ = a.applyDoT(ctx)
		return bad(c, "could not start DNS over TLS (settings not changed): "+err.Error())
	}
	a.auth.AuditC(c, "dns.encrypted_changed", "", s)
	return a.getEncrypted(c)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- DNS over HTTPS (RFC 8484) ---------------------------------------------

// dohQuery answers GET /dns-query?dns=<base64url> and POST /dns-query with
// an application/dns-message body. Nginx terminates TLS and passes the
// client's address in X-Real-IP.
func (a *App) dohQuery(c *fiber.Ctx) error {
	if !a.encryptedSettings(c.UserContext()).DoH {
		return fiber.ErrNotFound
	}
	var wire []byte
	switch c.Method() {
	case fiber.MethodGet:
		var err error
		if wire, err = base64.RawURLEncoding.DecodeString(c.Query("dns")); err != nil || len(wire) == 0 {
			return c.Status(fiber.StatusBadRequest).SendString("dns parameter missing or not base64url")
		}
	case fiber.MethodPost:
		if string(c.Request().Header.ContentType()) != "application/dns-message" {
			return c.Status(fiber.StatusUnsupportedMediaType).SendString("use Content-Type: application/dns-message")
		}
		wire = c.Body()
	}
	if len(wire) > dns.MaxMsgSize {
		return c.Status(fiber.StatusRequestEntityTooLarge).SendString("query too large")
	}
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("not a DNS message")
	}
	client, err := netip.ParseAddr(c.IP())
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("unknown client address")
	}
	resp := a.dns.Resolve(client.Unmap(), req)
	if resp == nil {
		return c.Status(fiber.StatusTooManyRequests).SendString("rate limited")
	}
	out, err := resp.Pack()
	if err != nil {
		return err
	}
	c.Set("Content-Type", "application/dns-message")
	c.Set("Cache-Control", "max-age="+strconv.Itoa(int(minTTL(resp))))
	return c.Send(out)
}

func minTTL(m *dns.Msg) uint32 {
	ttl := uint32(0)
	first := true
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			if t := rr.Header().Ttl; first || t < ttl {
				ttl, first = t, false
			}
		}
	}
	return ttl
}
