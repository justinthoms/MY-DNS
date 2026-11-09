package nc

// Integration tests: the real application against a real PostgreSQL server.
// They run only when NC_TEST_DATABASE_URL points at a database the test may
// create databases on, for example:
//
//	NC_TEST_DATABASE_URL=postgres://postgres:secret@127.0.0.1:5432/postgres go test ./isp-netcontrol/internal/nc/

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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

	"github.com/justinthoms/my-dns/shared/authkit"
	"github.com/justinthoms/my-dns/shared/licensecore"
)

type testEnv struct {
	t      *testing.T
	app    *App
	cookie string
	csrf   string
	dns    string
}

func freeTCPPort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
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
		TLSDir: filepath.Join(dir, "tls"), DoTPort: freeTCPPort(t),
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

func TestIntegrationListenInterfaces(t *testing.T) {
	e := newTestEnv(t)
	r := e.call("GET", "/api/dns/listen", nil, 200)
	found := false
	for _, it := range r["interfaces"].([]any) {
		m := it.(map[string]any)
		if m["name"] == "lo" && m["loopback"] == true {
			found = true
		}
	}
	if !found {
		t.Fatalf("lo not listed: %v", r["interfaces"])
	}
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	r = e.call("PUT", "/api/dns/listen", map[string]any{"mode": "selected", "interfaces": []string{"lo"}, "port": port}, 200)
	active := fmt.Sprint(r["active"])
	if !strings.Contains(active, fmt.Sprintf("127.0.0.1:%d", port)) {
		t.Fatalf("active after selecting lo: %s", active)
	}
	e.dns = fmt.Sprintf("127.0.0.1:%d", port)
	if m := e.query("example.org", dns.TypeA); m.Rcode == dns.RcodeRefused {
		t.Fatal("not answering on the new address")
	}
	// A foreign address is refused and the previous listeners stay.
	e.call("PUT", "/api/dns/listen", map[string]any{"mode": "selected", "addresses": []string{"192.0.2.1"}, "port": port}, 400)
	if got := fmt.Sprint(e.app.dns.Addrs()); got != active {
		t.Fatalf("listeners changed after a failed update: %s vs %s", got, active)
	}
	e.call("PUT", "/api/dns/listen", map[string]any{"mode": "selected", "interfaces": []string{"no-such-if0"}, "port": port}, 400)
	e.call("PUT", "/api/dns/listen", map[string]any{"mode": "selected", "port": port}, 400)
}

func TestIntegrationQueryLogPaging(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	rows := make([][]any, 0, 130)
	now := time.Now().UTC()
	for i := 0; i < 120; i++ {
		action := "forwarded"
		if i%4 == 0 {
			action = "blocked"
		}
		rows = append(rows, []any{now.Add(-time.Duration(i) * time.Second), "198.51.100.7", fmt.Sprintf("n%03d.example", i), "A", action})
	}
	for i := 0; i < 10; i++ { // older than 12 hours
		rows = append(rows, []any{now.Add(-13 * time.Hour), "198.51.100.8", "old.example", "A", "forwarded"})
	}
	if _, err := e.app.db.CopyFrom(ctx, pgx.Identifier{"dns_query_log"}, []string{"at", "client", "qname", "qtype", "action"}, pgx.CopyFromRows(rows)); err != nil {
		t.Fatal(err)
	}
	p := e.call("GET", "/api/dns/querylog?page=2&page_size=50", nil, 200)
	if p["total"].(float64) != 130 || p["pages"].(float64) != 3 || p["page"].(float64) != 2 || len(p["entries"].([]any)) != 50 {
		t.Fatalf("page 2: total=%v pages=%v page=%v n=%d", p["total"], p["pages"], p["page"], len(p["entries"].([]any)))
	}
	if first := p["entries"].([]any)[0].(map[string]any)["name"]; first != "n050.example" {
		t.Fatalf("page 2 starts with %v", first)
	}
	b := e.call("GET", "/api/dns/querylog?action=blocked&page_size=25", nil, 200)
	if b["total"].(float64) != 30 {
		t.Fatalf("blocked total %v", b["total"])
	}
	if last := e.call("GET", "/api/dns/querylog?page=99", nil, 200); last["page"].(float64) != 3 {
		t.Fatalf("page beyond the end not clamped: %v", last["page"])
	}
	e.call("PUT", "/api/dns/querylog/settings", map[string]int{"retention_hours": 0}, 400)
	e.call("PUT", "/api/dns/querylog/settings", map[string]int{"retention_hours": 12}, 200)
	if after := e.call("GET", "/api/dns/querylog", nil, 200); after["total"].(float64) != 120 || after["retention_hours"].(float64) != 12 {
		t.Fatalf("after 12h retention: total=%v retention=%v", after["total"], after["retention_hours"])
	}
}

func TestIntegrationAnycastGuards(t *testing.T) {
	e := newTestEnv(t)
	base := map[string]any{"interface": "lo", "enabled": true, "monitor_only": true, "interval_sec": 5,
		"fail_threshold": 3, "rise_threshold": 3, "mode": "auto", "check_name": "example.com"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	if r := e.call("PUT", "/api/anycast", base, 400); !strings.Contains(fmt.Sprint(r["error"]), "loopback") {
		t.Fatalf("loopback: %v", r)
	}
	e.call("PUT", "/api/anycast", with("interface", "no-such-if0"), 400)
	e.call("PUT", "/api/anycast", with("interval_sec", 1), 400)
	e.call("PUT", "/api/anycast", with("check_name", "not a name!"), 400)
	// The interface carrying the default route is refused, if this host has one.
	for name := range defaultRouteIfaces() {
		if r := e.call("PUT", "/api/anycast", with("interface", name), 400); !strings.Contains(fmt.Sprint(r["error"]), "default route") {
			t.Fatalf("default-route interface %s: %v", name, r)
		}
		break
	}
	// Disabled settings are stored without touching any interface.
	off := with("enabled", false)
	off["interface"] = "anycast0"
	off["fail_threshold"] = 4
	e.call("PUT", "/api/anycast", off, 200)
	g := e.call("GET", "/api/anycast", nil, 200)
	s := g["settings"].(map[string]any)
	if s["fail_threshold"].(float64) != 4 || s["enabled"] != false || g["status"].(map[string]any)["enabled"] != false {
		t.Fatalf("stored: %v", g)
	}
}

func TestIntegrationAdminsAndRecovery(t *testing.T) {
	e := newTestEnv(t)
	r := e.call("POST", "/api/admins", map[string]string{"email": "Noc2@ISP.example", "password": "Second-Admin-0001"}, 201)
	id := r["id"]
	e.call("POST", "/api/admins", map[string]string{"email": "noc2@isp.example", "password": "Second-Admin-0001"}, 409)
	e.call("POST", "/api/admins", map[string]string{"email": "weak@isp.example", "password": "short"}, 400)
	list := string(e.raw("GET", "/api/admins", nil, 200))
	if !strings.Contains(list, "noc2@isp.example") || !strings.Contains(list, "noc@isp.example") {
		t.Fatalf("list: %s", list)
	}
	me := e.call("GET", "/api/auth/me", nil, 200)
	myID := me["user"].(map[string]any)["id"]
	e.call("DELETE", fmt.Sprintf("/api/admins/%v", myID), nil, 400) // cannot delete yourself

	// Recovery: a new temporary password works and must be changed.
	ctx := context.Background()
	pw, err := authkitResetPassword(ctx, e, "NOC2@isp.example")
	if err != nil {
		t.Fatal(err)
	}
	other := &testEnv{t: t, app: e.app, dns: e.dns}
	r = other.call("POST", "/api/auth/login", map[string]string{"email": "noc2@isp.example", "password": pw}, 200)
	if r["next"] != "change_password" {
		t.Fatalf("after reset: %v", r)
	}
	if _, err := authkitResetPassword(ctx, e, "nobody@isp.example"); err == nil {
		t.Fatal("reset of unknown admin succeeded")
	}
	e.call("DELETE", fmt.Sprintf("/api/admins/%v", id), nil, 200)
	if strings.Contains(string(e.raw("GET", "/api/admins", nil, 200)), "noc2@") {
		t.Fatal("admin not deleted")
	}
	audit := string(e.raw("GET", "/api/audit", nil, 200))
	for _, want := range []string{"admin.created", "admin.password_reset", "admin.deleted"} {
		if !strings.Contains(audit, want) {
			t.Fatalf("audit lacks %s", want)
		}
	}
}

func authkitResetPassword(ctx context.Context, e *testEnv, email string) (string, error) {
	return authkit.ResetPassword(ctx, e.app.db, email)
}

func TestIntegrationListenDefaultsAreLists(t *testing.T) {
	e := newTestEnv(t)
	raw := string(e.raw("GET", "/api/dns/listen", nil, 200))
	if !strings.Contains(raw, `"interfaces":[]`) || !strings.Contains(raw, `"addresses":[]`) || strings.Contains(raw, `"interfaces":null`) {
		t.Fatalf("unsaved listen settings must use empty lists: %s", raw[:200])
	}
}

func TestIntegrationDashboardData(t *testing.T) {
	e := newTestEnv(t)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "gone.example." {
			m.Rcode = dns.RcodeNameError
		} else if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = up.ActivateAndServe() }()
	defer up.Shutdown()
	e.call("PUT", "/api/dns/settings", map[string]any{"upstreams": []string{pc.LocalAddr().String()}, "block_mode": "nxdomain",
		"sinkhole_v4": "0.0.0.0", "sinkhole_v6": "::", "allowed_clients": []string{"127.0.0.0/8"}, "filtering_enabled": true}, 200)
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "bad.example", "category": "malware"}, 201)
	e.query("ok.example", dns.TypeA)
	e.query("ok.example", dns.TypeAAAA)
	e.query("gone.example", dns.TypeA)
	e.query("x.bad.example", dns.TypeA)
	e.app.flushStats(context.Background(), time.Now().UTC().Truncate(time.Minute))

	ts := e.call("GET", "/api/dns/timeseries?range=15m", nil, 200)
	tot := ts["totals"].(map[string]any)
	if tot["total"].(float64) != 4 || tot["nxdomain"].(float64) != 1 || tot["blocked"].(float64) != 1 || tot["avg_ms"] == nil {
		t.Fatalf("totals %v", tot)
	}
	if n := len(ts["points"].([]any)); n != 15 {
		t.Fatalf("15m points: %d", n)
	}
	if _, ok := ts["previous"].(map[string]any)["total"]; !ok || ts["qps"] == nil {
		t.Fatalf("previous/qps missing: %v", ts)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		b := e.call("GET", "/api/dns/breakdown?range=15m", nil, 200)
		types, cats := fmt.Sprint(b["query_types"]), fmt.Sprint(b["block_categories"])
		if strings.Contains(types, "key:A]") && strings.Contains(types, "AAAA") && strings.Contains(cats, "malware") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("breakdown: %v", b)
		}
		time.Sleep(300 * time.Millisecond)
	}
	h := e.call("GET", "/api/system/health", nil, 200)
	ups := h["upstreams"].([]any)
	if len(ups) != 1 || ups[0].(map[string]any)["healthy"] != true || h["database"].(map[string]any)["ok"] != true || h["dns"].(map[string]any)["ok"] != true {
		t.Fatalf("health: %v", h)
	}
	if hostCPUs := h["host"].(map[string]any)["cpus"].(float64); hostCPUs < 1 {
		t.Fatalf("host: %v", h["host"])
	}
}

func TestIntegrationQueryLogModes(t *testing.T) {
	e := newTestEnv(t)
	e.call("POST", "/api/dns/blocklist", map[string]string{"domain": "bad.example"}, 201)
	e.call("POST", "/api/dns/records", map[string]any{"name": "host.lan", "type": "A", "value": "10.0.0.1"}, 201)
	count := func(action string) float64 {
		return e.call("GET", "/api/dns/querylog?action="+action, nil, 200)["total"].(float64)
	}
	waitFor := func(action string, want float64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for count(action) != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s entries: %v, want %v", action, count(action), want)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	e.call("PUT", "/api/dns/querylog/settings", map[string]any{"retention_hours": 24, "mode": "important", "sample": 1}, 200)
	for i := 0; i < 5; i++ {
		e.query("host.lan", dns.TypeA)
		e.query("x.bad.example", dns.TypeA)
	}
	waitFor("blocked", 5)
	if n := count("local"); n != 0 {
		t.Fatalf("important mode logged %v allowed queries", n)
	}
	e.call("PUT", "/api/dns/querylog/settings", map[string]any{"retention_hours": 24, "mode": "all", "sample": 10}, 200)
	for i := 0; i < 200; i++ {
		e.query("host.lan", dns.TypeA)
	}
	waitFor("local", 20)
	e.call("PUT", "/api/dns/querylog/settings", map[string]any{"retention_hours": 24, "mode": "verbose"}, 400)
	e.call("PUT", "/api/dns/querylog/settings", map[string]any{"retention_hours": 24, "mode": "all", "sample": 5000}, 400)
}

func TestIntegrationProtection(t *testing.T) {
	e := newTestEnv(t)
	got := e.call("GET", "/api/dns/protection", nil, 200)
	// A fresh server has empty lists, not null (the console reads .length).
	if st := got["status"].(map[string]any); st["zones"] == nil || st["limited_clients"] == nil {
		t.Fatalf("status lists are null: %v", st)
	}
	set := got["settings"].(map[string]any)
	if set["rate_limit"].(float64) != 500 || set["minimal_any"] != true || set["torture_enabled"] != true {
		t.Fatalf("defaults %v", set)
	}
	e.call("PUT", "/api/dns/protection", map[string]any{"rate_limit_enabled": true, "rate_limit": 5, "burst": 5,
		"torture_threshold": 1000, "torture_limit": 20, "torture_hold_minutes": 10}, 400)
	e.call("PUT", "/api/dns/protection", map[string]any{"rate_limit_enabled": true, "rate_limit": 10, "burst": 10, "exempt": []string{"not-an-ip"},
		"torture_threshold": 1000, "torture_limit": 20, "torture_hold_minutes": 10}, 400)
	saved := e.call("PUT", "/api/dns/protection", map[string]any{"rate_limit_enabled": true, "rate_limit": 10, "burst": 10, "exempt": []string{"192.0.2.7", "10.1.2.3/8"},
		"minimal_any": true, "torture_enabled": true, "torture_threshold": 1000, "torture_limit": 20, "torture_hold_minutes": 10}, 200)
	if ex := saved["exempt"].([]any); ex[0] != "192.0.2.7/32" || ex[1] != "10.0.0.0/8" {
		t.Fatalf("exempt not normalised: %v", ex)
	}

	// A flood from one client: most of it is dropped.
	e.call("POST", "/api/dns/records", map[string]any{"name": "host.lan", "type": "A", "value": "10.0.0.1"}, 201)
	c := &dns.Client{Timeout: 100 * time.Millisecond}
	answered := 0
	for i := 0; i < 40; i++ {
		m := new(dns.Msg)
		m.SetQuestion("host.lan.", dns.TypeA)
		if _, _, err := c.Exchange(m, e.dns); err == nil {
			answered++
		}
	}
	if answered == 40 {
		t.Fatal("rate limit did not drop anything")
	}
	st := e.call("GET", "/api/dns/protection", nil, 200)["status"].(map[string]any)
	if st["rate_limited"].(float64) == 0 || len(st["limited_clients"].([]any)) != 1 {
		t.Fatalf("status %v", st)
	}
	health := e.call("GET", "/api/system/health", nil, 200)["protection"].(map[string]any)
	if health["rate_limited"].(float64) == 0 {
		t.Fatalf("health %v", health)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.call("GET", "/api/dns/querylog?q=host.lan", nil, 200)["entries"] == nil ||
		!strings.Contains(string(e.raw("GET", "/api/dns/querylog?q=host.lan", nil, 200)), `"ratelimited"`) {
		if time.Now().After(deadline) {
			t.Fatal("no ratelimited entry in the query log")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Turning the limit off takes effect at once.
	e.call("PUT", "/api/dns/protection", map[string]any{"rate_limit_enabled": false, "rate_limit": 10, "burst": 10,
		"minimal_any": true, "torture_enabled": true, "torture_threshold": 1000, "torture_limit": 20, "torture_hold_minutes": 10}, 200)
	for i := 0; i < 30; i++ {
		e.query("host.lan", dns.TypeA)
	}
	if r := e.query("host.lan", dns.TypeANY); len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeHINFO {
		t.Fatalf("ANY: %v", r)
	}
}

func TestIntegrationEncryptedDNS(t *testing.T) {
	e := newTestEnv(t)
	// Certificate the console (and DNS over TLS) uses.
	cert, pool := testCertPEM(t, e.app.cfg.TLSDir)
	_ = cert
	got := e.call("GET", "/api/dns/encrypted", nil, 200)
	if got["settings"].(map[string]any)["dot"] != false || got["certificate"].(map[string]any)["ok"] != true {
		t.Fatalf("initial %v", got)
	}
	// DoH is off by default: the endpoint does not exist.
	e.raw("GET", "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", nil, 404)

	got = e.call("PUT", "/api/dns/encrypted", map[string]bool{"dot": true, "doh": true}, 200)
	if l := got["dot_listening"].([]any); len(l) != 1 {
		t.Fatalf("dot_listening %v", got)
	}
	e.call("POST", "/api/dns/records", map[string]any{"name": "host.lan", "type": "A", "value": "10.0.0.1"}, 201)

	// DNS over TLS on the derived address.
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{RootCAs: pool, ServerName: "dns.test"}}
	m := new(dns.Msg)
	m.SetQuestion("host.lan.", dns.TypeA)
	r, _, err := c.Exchange(m, e.app.dns.TLSAddrs()[0])
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("DNS over TLS: %v %v", r, err)
	}

	// DNS over HTTPS, GET and POST. The test client's address must be allowed.
	set := e.call("GET", "/api/dns/settings", nil, 200)
	set["allowed_clients"] = append(set["allowed_clients"].([]any), "0.0.0.0/32")
	e.call("PUT", "/api/dns/settings", set, 200)
	m.Id = 0
	wire, _ := m.Pack()
	body := e.raw("GET", "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wire), nil, 200)
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("DoH GET: %v %v", resp, err)
	}
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/dns-message")
	hr, err := e.app.web.Test(req, 5000)
	if err != nil || hr.StatusCode != 200 || hr.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("DoH POST: %v %v", hr, err)
	}
	e.raw("GET", "/dns-query?dns=!!!", nil, 400)

	// Encrypted upstreams are accepted and normalised.
	set["upstreams"] = []string{"tls://1.1.1.1#cloudflare-dns.com", "9.9.9.9"}
	saved := e.call("PUT", "/api/dns/settings", set, 200)
	if ups := saved["upstreams"].([]any); ups[0] != "tls://1.1.1.1:853#cloudflare-dns.com" || ups[1] != "9.9.9.9:53" {
		t.Fatalf("upstreams %v", ups)
	}
	set["upstreams"] = []string{"tls://dns.google"}
	e.call("PUT", "/api/dns/settings", set, 400)

	// Turning DoT off closes the port.
	e.call("PUT", "/api/dns/encrypted", map[string]bool{"dot": false, "doh": false}, 200)
	if len(e.app.dns.TLSAddrs()) != 0 {
		t.Fatal("DNS over TLS still on")
	}
}

// testCertPEM writes a self-signed certificate for "dns.test" to dir as
// fullchain.pem and privkey.pem and returns a pool that trusts it.
func testCertPEM(t *testing.T, dir string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "dns.test"}, DNSNames: []string{"dns.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
