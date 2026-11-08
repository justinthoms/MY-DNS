package nc

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/dnsserver"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/firewall"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/license"
	"github.com/justinthoms/my-dns/shared/licensecore"
)

//go:embed schema.sql
var schemaSQL string

// DNSSettings are the resolver settings editable in the console. They work in
// every license mode, so subscribers keep getting answers even when the
// trial ends.
type DNSSettings struct {
	Upstreams        []string `json:"upstreams"`
	BlockMode        string   `json:"block_mode"`
	SinkholeV4       string   `json:"sinkhole_v4"`
	SinkholeV6       string   `json:"sinkhole_v6"`
	AllowedClients   []string `json:"allowed_clients"`
	FilteringEnabled bool     `json:"filtering_enabled"`
}

func defaultDNSSettings() DNSSettings {
	return DNSSettings{
		Upstreams:  []string{"1.1.1.1:53", "8.8.8.8:53"},
		BlockMode:  "nxdomain",
		SinkholeV4: "0.0.0.0", SinkholeV6: "::",
		// Private, CGNAT and loopback ranges: subscribers behind the ISP. Public
		// ranges must be added explicitly so the server is never an open resolver.
		AllowedClients:   []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"},
		FilteringEnabled: true,
	}
}

// Validate normalises the settings.
func (s *DNSSettings) Validate() error {
	if len(s.Upstreams) == 0 {
		return errors.New("at least one upstream resolver is required")
	}
	for i, u := range s.Upstreams {
		u = strings.TrimSpace(u)
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, "53")
		}
		host, _, _ := net.SplitHostPort(u)
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("upstream %q must be an IP address (optionally with :port)", s.Upstreams[i])
		}
		s.Upstreams[i] = u
	}
	if s.BlockMode != "nxdomain" && s.BlockMode != "sinkhole" {
		return errors.New(`block_mode must be "nxdomain" or "sinkhole"`)
	}
	if a, err := netip.ParseAddr(s.SinkholeV4); err != nil || !a.Is4() {
		return errors.New("sinkhole_v4 must be an IPv4 address")
	}
	if a, err := netip.ParseAddr(s.SinkholeV6); err != nil || !a.Is6() {
		return errors.New("sinkhole_v6 must be an IPv6 address")
	}
	if len(s.AllowedClients) == 0 {
		return errors.New("at least one allowed client network is required")
	}
	for i, c := range s.AllowedClients {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return fmt.Errorf("allowed client network %q is not a CIDR network", c)
		}
		s.AllowedClients[i] = p.Masked().String()
	}
	return nil
}

// LicenseSettings control status sync.
type LicenseSettings struct {
	ServerURL   string `json:"server_url"`
	SyncEnabled bool   `json:"sync_enabled"`
}

func (a *App) getSetting(ctx context.Context, key string, out any) (bool, error) {
	var raw []byte
	err := a.db.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, out)
}

func (a *App) putSetting(ctx context.Context, key string, v any) error {
	raw, _ := json.Marshal(v)
	_, err := a.db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`, key, raw)
	return err
}

func (a *App) dnsSettings(ctx context.Context) (DNSSettings, error) {
	s := defaultDNSSettings()
	_, err := a.getSetting(ctx, "dns", &s)
	return s, err
}

func (a *App) licenseSettings(ctx context.Context) LicenseSettings {
	s := LicenseSettings{ServerURL: a.cfg.LMURL, SyncEnabled: a.cfg.LMURL != ""}
	if _, err := a.getSetting(ctx, "license", &s); err != nil {
		log.Printf("settings: %v", err)
	}
	return s
}

func (a *App) syncSettings(ctx context.Context) (string, bool) {
	s := a.licenseSettings(ctx)
	return s.ServerURL, s.SyncEnabled
}

// buildPolicy assembles the resolver policy from the database and the license.
func (a *App) buildPolicy(ctx context.Context, st license.State) (*dnsserver.Policy, error) {
	s, err := a.dnsSettings(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		log.Printf("dns settings invalid (%v); using defaults", err)
		s = defaultDNSSettings()
	}
	p := &dnsserver.Policy{
		Filtering:  s.FilteringEnabled && st.Has(licensecore.FeatureDNSFiltering),
		LogQueries: st.Has(licensecore.FeatureQueryLog),
		BlockMode:  s.BlockMode, Upstreams: s.Upstreams,
		SinkholeV4: net.ParseIP(s.SinkholeV4), SinkholeV6: net.ParseIP(s.SinkholeV6),
		Blocked: map[string]string{}, Allowed: map[string]bool{},
	}
	for _, c := range s.AllowedClients {
		p.AllowedClients = append(p.AllowedClients, netip.MustParsePrefix(c))
	}
	if p.Records, err = a.loadRecords(ctx); err != nil {
		return nil, err
	}
	if p.Filtering {
		rows, err := a.db.Query(ctx, `SELECT domain, category FROM dns_blocklist`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var d, cat string
			if err := rows.Scan(&d, &cat); err != nil {
				rows.Close()
				return nil, err
			}
			p.Blocked[d] = cat
		}
		rows.Close()
		rows, err = a.db.Query(ctx, `SELECT domain FROM dns_allowlist`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				rows.Close()
				return nil, err
			}
			p.Allowed[d] = true
		}
		rows.Close()
	}
	return p, nil
}

// reloadDNS rebuilds the resolver policy after a change.
func (a *App) reloadDNS(ctx context.Context) error {
	p, err := a.buildPolicy(ctx, a.lic.Current())
	if err != nil {
		return err
	}
	a.dns.SetPolicy(p)
	return nil
}

func (a *App) enabledRules(ctx context.Context) ([]firewall.Rule, error) {
	rows, err := a.db.Query(ctx, `SELECT cidr::text, direction FROM firewall_rules WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []firewall.Rule
	for rows.Next() {
		var cidr, dir string
		if err := rows.Scan(&cidr, &dir); err != nil {
			return nil, err
		}
		r, err := firewall.ValidateRule(cidr, dir)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// syncFirewall applies the rules when the firewall feature is licensed and
// removes ISP NetControl's table (only that table) when it is not.
func (a *App) syncFirewall(ctx context.Context, st license.State) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	a.fwStatus = fwState{UpdatedAt: time.Now().UTC()}
	if !a.fw.Enabled {
		a.fwStatus.Error = firewall.ErrDisabled.Error()
		return nil
	}
	if !st.Has(licensecore.FeatureFirewall) {
		err := a.fw.Remove(ctx)
		if err != nil {
			a.fwStatus.Error = err.Error()
		}
		return err
	}
	rules, err := a.enabledRules(ctx)
	if err == nil {
		err = a.fw.Apply(ctx, rules)
	}
	if err != nil {
		a.fwStatus.Error = err.Error()
		log.Printf("firewall: %v", err)
		return err
	}
	a.fwStatus.Applied, a.fwStatus.Rules = true, len(rules)
	return nil
}

// applyEnforcement brings DNS and firewall in line with the license state.
func (a *App) applyEnforcement(ctx context.Context, st license.State) {
	a.enforceMu.Lock()
	a.enforced = enforcementKey(st)
	a.enforceMu.Unlock()
	if err := a.reloadDNS(ctx); err != nil {
		log.Printf("dns reload: %v", err)
	}
	_ = a.syncFirewall(ctx, st)
}

func enforcementKey(st license.State) string { return st.Mode + "|" + strings.Join(st.Features, ",") }

// refreshLicense re-evaluates the license and, if the outcome changed since
// enforcement was last applied, applies it now (the background loop would
// otherwise do so within a minute).
func (a *App) refreshLicense(ctx context.Context) (license.State, error) {
	st, err := a.lic.Evaluate(ctx)
	if err != nil {
		return st, err
	}
	a.enforceMu.Lock()
	changed := a.enforced != enforcementKey(st)
	a.enforceMu.Unlock()
	if changed {
		log.Printf("license: mode is now %s", st.Mode)
		a.applyEnforcement(ctx, st)
	}
	return st, nil
}

var labelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// normaliseDomain accepts "example.com", "*.example.com", "Example.COM." and
// URLs pasted from a browser; it returns the bare lower-case domain.
func normaliseDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "http://"), "https://")
	if i := strings.IndexAny(d, "/:?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimPrefix(strings.TrimPrefix(d, "*."), ".")
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return "", fmt.Errorf("%q is not a valid domain", in)
	}
	for _, l := range strings.Split(d, ".") {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid domain", in)
		}
	}
	return d, nil
}
