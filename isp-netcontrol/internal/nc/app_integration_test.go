package nc

// Integration tests: the real application against a real PostgreSQL server.
// They run only when NC_TEST_DATABASE_URL points at a database the test may
// create databases on, for example:
//
//	NC_TEST_DATABASE_URL=postgres://postgres:secret@127.0.0.1:5432/postgres go test ./isp-netcontrol/internal/nc/

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"

	"github.com/justinthoms/my-dns/shared/licensecore"
)

type testEnv struct {
	t      *testing.T
	app    *App
	cookie string
	csrf   string
	dns    string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	admin := os.Getenv("NC_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("NC_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "nc_it_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), admin)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	pc, _ := pgx.ParseConfig(admin)
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", pc.User, pc.Password, pc.Host, pc.Port, name)

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "machine-id"), []byte("0123456789abcdef0123456789abcdef\n"), 0o644)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dnsAddr := l.LocalAddr().String()
	l.Close()
	cfg := Config{
		DatabaseURL: dbURL, MasterKey: base64.StdEncoding.EncodeToString(key),
		HTTPAddr: "127.0.0.1:0", DNSListen: []string{dnsAddr}, StateDir: filepath.Join(dir, "state"),
		MachineIDPath: filepath.Join(dir, "machine-id"), ProductUUIDPath: "/nonexistent",
		FirewallEnabled: false, SyncInterval: time.Hour, CookieSecure: false, RequireTOTP: false,
		BootstrapEmail: "noc@isp.example", BootstrapPassword: "Bootstrap-Pass-123",
		TrustedProxies: []string{"127.0.0.1"}, QueryLogDays: 7,
		trustedPEM: licensecore.EncodePublicKey(pub),
	}
	runCtx, cancel := context.WithCancel(context.Background())
	app, err := New(runCtx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// Serve DNS and the background jobs, but not HTTP: requests go through app.Test.
	go func() { _ = app.dns.ListenAndServe(runCtx, cfg.DNSListen) }()
	go app.queryLogWriter(runCtx)
	t.Cleanup(func() { cancel(); app.Close() })
	time.Sleep(200 * time.Millisecond)

	e := &testEnv{t: t, app: app, dns: dnsAddr}
	e.call("POST", "/api/auth/login", map[string]string{"email": "noc@isp.example", "password": "Bootstrap-Pass-123"}, 200)
	e.call("POST", "/api/auth/password", map[string]string{"current_password": "Bootstrap-Pass-123", "new_password": "Changed-Pass-4567"}, 200)
	return e
}

// call sends a request through the Fiber app (no network) and decodes JSON.
func (e *testEnv) call(method, path string, body any, want int) map[string]any {
	e.t.Helper()
	raw := e.raw(method, path, body, want)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (e *testEnv) raw(method, path string, body any, want int) []byte {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if e.cookie != "" {
		req.Header.Set("Cookie", e.cookie)
	}
	if e.csrf != "" {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := e.app.web.Test(req, 30_000)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, ck := range resp.Cookies() {
		if ck.Name == "nc_session" && ck.Value != "" {
			e.cookie = "nc_session=" + ck.Value
		}
	}
	var m map[string]any
	if json.Unmarshal(data, &m) == nil {
		if tok, ok := m["csrf_token"].(string); ok {
			e.csrf = tok
		}
	}
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, data)
	}
	return data
}

func (e *testEnv) query(name string, qt uint16) *dns.Msg {
	e.t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	r, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, e.dns)
	if err != nil {
		e.t.Fatalf("query %s: %v", name, err)
	}
	return r
}

func TestIntegrationDNSRecords(t *testing.T) {
	e := newTestEnv(t)
	e.call("POST", "/api/dns/records", map[string]any{"name": "nas.office.lan", "type": "A", "value": "192.168.1.10", "note": "NAS"}, 201)
	r := e.call("POST", "/api/dns/records", map[string]any{"name": "files.office.lan", "type": "CNAME", "value": "nas.office.lan."}, 201)
	cnameID := r["id"]
	e.call("POST", "/api/dns/records", map[string]any{"name": "192.168.1.10", "type": "PTR", "value": "nas.office.lan"}, 201)
	// Rejected: CNAME next to an A record, bad IP, duplicate.
	e.call("POST", "/api/dns/records", map[string]any{"name": "nas.office.lan", "type": "CNAME", "value": "x.lan"}, 400)
	e.call("POST", "/api/dns/records", map[string]any{"name": "bad.lan", "type": "A", "value": "300.1.1.1"}, 400)
	e.call("POST", "/api/dns/records", map[string]any{"name": "nas.office.lan", "type": "A", "value": "192.168.1.10"}, 409)

	if m := e.query("files.office.lan", dns.TypeA); len(m.Answer) != 2 || m.Answer[1].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("CNAME answer: %v", m.Answer)
	}
	if m := e.query("10.1.168.192.in-addr.arpa", dns.TypePTR); len(m.Answer) != 1 {
		t.Fatalf("PTR answer: %v", m.Answer)
	}
	// Disabling a record removes it from DNS immediately.
	e.call("PUT", fmt.Sprintf("/api/dns/records/%v", cnameID), map[string]any{"name": "files.office.lan", "type": "CNAME", "value": "nas.office.lan", "enabled": false}, 200)
	if m := e.query("files.office.lan", dns.TypeA); m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
		t.Fatalf("disabled record still answered: %v", m.Answer)
	}
	list := e.raw("GET", "/api/dns/records", nil, 200)
	if !strings.Contains(string(list), "10.1.168.192.in-addr.arpa") {
		t.Fatalf("PTR not stored under its reverse name: %s", list)
	}
}

func TestIntegrationExportImport(t *testing.T) {
	e := newTestEnv(t)
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "ads.example.com", "category": "ads", "note": "banner, top"}, 201)
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "malware.example.org", "category": "malware"}, 201)
	csvData := string(e.raw("GET", "/api/dns/blocklist/export?format=csv", nil, 200))
	if !strings.HasPrefix(csvData, "domain,category,note,source\n") || !strings.Contains(csvData, `ads.example.com,ads,"banner, top",`) {
		t.Fatalf("csv export:\n%s", csvData)
	}
	hosts := string(e.raw("GET", "/api/dns/blocklist/export?format=hosts", nil, 200))
	if !strings.Contains(hosts, "0.0.0.0 malware.example.org\n") {
		t.Fatalf("hosts export:\n%s", hosts)
	}
	// Replace import of the CSV export restores the same list, categories included.
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "extra.example"}, 201)
	r := e.call("POST", "/api/dns/blocklist/import", map[string]string{"text": csvData, "mode": "replace"}, 200)
	if r["removed"].(float64) != 3 || r["added"].(float64) != 2 {
		t.Fatalf("replace import: %v", r)
	}
	again := string(e.raw("GET", "/api/dns/blocklist/export?format=csv", nil, 200))
	if again != csvData {
		t.Fatalf("round trip differs:\n%s\nvs\n%s", again, csvData)
	}
	// Allow-list import (new in 1.1) and an allow entry overriding a block.
	e.call("POST", "/api/dns/allowlist/import", map[string]string{"text": "ok.ads.example.com\n"}, 200)
	if m := e.query("ok.ads.example.com", dns.TypeA); m.Rcode == dns.RcodeNameError {
		t.Fatal("allow-listed name was blocked")
	}
	if m := e.query("x.ads.example.com", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked subdomain answered %s", dns.RcodeToString[m.Rcode])
	}
	chk := e.call("GET", "/api/dns/check?name=x.ads.example.com", nil, 200)
	if chk["result"] != "blocked" || chk["matched"] != "ads.example.com" || chk["source"] != "added by hand" {
		t.Fatalf("check: %v", chk)
	}
	if chk := e.call("GET", "/api/dns/check?name=ok.ads.example.com", nil, 200); chk["result"] != "allowed" {
		t.Fatalf("check allowed: %v", chk)
	}
	e.call("GET", "/api/dns/blocklist/export?format=xml", nil, 400)
}

func TestIntegrationSubscriptions(t *testing.T) {
	e := newTestEnv(t)
	var mu sync.Mutex
	body := "# list v1\n0.0.0.0 sub-a.example\n||sub-b.example^\nmanual.example\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	// A hand-made entry that the subscription also lists must survive refreshes.
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "manual.example"}, 201)
	r := e.call("POST", "/api/dns/sources", map[string]string{"name": "Test list", "url": srv.URL + "/list.txt", "category": "ads"}, 201)
	id := r["id"]
	if res := r["result"].(map[string]any); res["entries"].(float64) != 2 || res["duplicates"].(float64) != 1 {
		t.Fatalf("first fetch: %v", r)
	}
	if m := e.query("www.sub-b.example", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Fatal("subscription entry not enforced")
	}
	mu.Lock()
	body = "sub-c.example\n"
	mu.Unlock()
	e.call("POST", fmt.Sprintf("/api/dns/sources/%v/refresh", id), nil, 200)
	exp := string(e.raw("GET", "/api/dns/blocklist/export?format=txt", nil, 200))
	if strings.Contains(exp, "sub-a.example") || !strings.Contains(exp, "sub-c.example") || !strings.Contains(exp, "manual.example") {
		t.Fatalf("after refresh:\n%s", exp)
	}
	// An empty download keeps the previous entries.
	mu.Lock()
	body = "# nothing\n"
	mu.Unlock()
	e.call("POST", fmt.Sprintf("/api/dns/sources/%v/refresh", id), nil, 502)
	if !strings.Contains(string(e.raw("GET", "/api/dns/blocklist/export", nil, 200)), "sub-c.example") {
		t.Fatal("empty download dropped the list")
	}
	e.call("POST", "/api/dns/sources", map[string]string{"url": "ftp://example.com/list"}, 400)
	e.call("DELETE", fmt.Sprintf("/api/dns/sources/%v", id), nil, 200)
	exp = string(e.raw("GET", "/api/dns/blocklist/export?format=txt", nil, 200))
	if strings.Contains(exp, "sub-c.example") || !strings.Contains(exp, "manual.example") {
		t.Fatalf("after delete:\n%s", exp)
	}
}

func TestIntegrationStatsAndTop(t *testing.T) {
	e := newTestEnv(t)
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "ads.example.com"}, 201)
	e.call("POST", "/api/dns/records", map[string]any{"name": "router.lan", "type": "A", "value": "10.0.0.1"}, 201)
	for i := 0; i < 3; i++ {
		e.query("ads.example.com", dns.TypeA)
	}
	e.query("router.lan", dns.TypeA)
	// Half of the counts are flushed to the database, half are still pending:
	// the endpoint must include both.
	e.app.flushStats(context.Background(), time.Now().UTC().Truncate(time.Minute))
	e.query("ads.example.com", dns.TypeA)
	ts := e.call("GET", "/api/dns/timeseries?range=1h", nil, 200)
	tot := ts["totals"].(map[string]any)
	if tot["total"].(float64) != 5 || tot["blocked"].(float64) != 4 || tot["local"].(float64) != 1 {
		t.Fatalf("totals: %v", tot)
	}
	if n := len(ts["points"].([]any)); n != 60 {
		t.Fatalf("points for 1h: %d", n)
	}
	e.call("GET", "/api/dns/timeseries?range=1y", nil, 400)
	deadline := time.Now().Add(5 * time.Second)
	for {
		top := e.call("GET", "/api/dns/top?range=1h", nil, 200)
		b := top["blocked_domains"].([]any)
		if len(b) > 0 && b[0].(map[string]any)["key"] == "ads.example.com" && b[0].(map[string]any)["count"].(float64) == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("top: %v", top)
		}
		time.Sleep(300 * time.Millisecond)
	}
	logCSV := string(e.raw("GET", "/api/dns/querylog/export?range=1h", nil, 200))
	if !strings.HasPrefix(logCSV, "time_utc,client,name,type,result\n") || strings.Count(logCSV, "ads.example.com") != 4 {
		t.Fatalf("query log export:\n%s", logCSV)
	}
}
