package nc

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/firewall"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/license"
	"github.com/justinthoms/my-dns/shared/authkit"
)

func bad(c *fiber.Ctx, msg string) error {
	return authkit.APIError(c, fiber.StatusBadRequest, "bad_request", msg)
}

// ---- dashboard -------------------------------------------------------------

func (a *App) status(c *fiber.Ctx) error {
	ctx := c.UserContext()
	st, err := a.refreshLicense(ctx)
	if err != nil {
		return err
	}
	var blocked, allowed, rules int
	_ = a.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM dns_blocklist), (SELECT count(*) FROM dns_allowlist),
		(SELECT count(*) FROM firewall_rules WHERE enabled)`).Scan(&blocked, &allowed, &rules)
	a.applyMu.Lock()
	fw := a.fwStatus
	a.applyMu.Unlock()
	pol := a.dns.Policy()
	return c.JSON(fiber.Map{
		"version": Version,
		"license": st,
		"dns": fiber.Map{
			"stats": a.dns.Stats(), "filtering_active": pol.Filtering, "query_log_active": pol.LogQueries,
			"blocklist_entries": blocked, "allowlist_entries": allowed, "listen": a.cfg.DNSListen,
		},
		"firewall": fiber.Map{"state": fw, "enabled_rules": rules, "managed": a.fw.Enabled},
	})
}

func (a *App) listAudit(c *fiber.Ctx) error {
	rows, err := a.db.Query(c.UserContext(), `SELECT at, actor, action, target, details::text, ip FROM audit_log ORDER BY id DESC LIMIT 300`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type entry struct {
		At      time.Time `json:"at"`
		Actor   string    `json:"actor"`
		Action  string    `json:"action"`
		Target  string    `json:"target"`
		Details string    `json:"details"`
		IP      string    `json:"ip"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Details, &e.IP); err != nil {
			return err
		}
		out = append(out, e)
	}
	return c.JSON(out)
}

// ---- license ---------------------------------------------------------------

func (a *App) licenseBody(ctx context.Context, st license.State) fiber.Map {
	return fiber.Map{"state": st, "settings": a.licenseSettings(ctx), "trial_days": license.TrialDays}
}

func (a *App) getLicense(c *fiber.Ctx) error {
	st, err := a.refreshLicense(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(a.licenseBody(c.UserContext(), st))
}

func (a *App) afterLicenseChange(c *fiber.Ctx, st license.State) error {
	a.applyEnforcement(c.UserContext(), st)
	return c.JSON(a.licenseBody(c.UserContext(), st))
}

func licenseError(c *fiber.Ctx, err error) error {
	var se *license.ServerError
	if errors.As(err, &se) {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": se.Message, "code": se.Code})
	}
	return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error(), "code": "license_error"})
}

func (a *App) activateOnline(c *fiber.Ctx) error {
	var req struct {
		LicenseKey string `json:"license_key"`
		ServerURL  string `json:"server_url"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.LicenseKey) == "" {
		return bad(c, "enter the license key")
	}
	ctx := c.UserContext()
	s := a.licenseSettings(ctx)
	if req.ServerURL != "" && req.ServerURL != s.ServerURL {
		s.ServerURL = strings.TrimRight(strings.TrimSpace(req.ServerURL), "/")
		s.SyncEnabled = true
		if err := a.putSetting(ctx, "license", s); err != nil {
			return err
		}
	}
	st, err := a.lic.ActivateOnline(ctx, s.ServerURL, req.LicenseKey, Version)
	if err != nil {
		a.auth.AuditC(c, "license.activation_failed", "", fiber.Map{"error": err.Error()})
		return licenseError(c, err)
	}
	a.auth.AuditC(c, "license.activated_online", st.LicenseID, fiber.Map{"customer": st.Customer})
	return a.afterLicenseChange(c, st)
}

func (a *App) uploadLicense(c *fiber.Ctx) error {
	var req struct {
		License string `json:"license"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.License) == "" {
		return bad(c, "paste or upload the license file")
	}
	st, err := a.lic.Install(c.UserContext(), req.License)
	if err != nil {
		a.auth.AuditC(c, "license.upload_failed", "", fiber.Map{"error": err.Error()})
		return licenseError(c, err)
	}
	a.auth.AuditC(c, "license.installed_offline", st.LicenseID, fiber.Map{"customer": st.Customer})
	return a.afterLicenseChange(c, st)
}

func (a *App) syncNow(c *fiber.Ctx) error {
	s := a.licenseSettings(c.UserContext())
	st, err := a.lic.Sync(c.UserContext(), s.ServerURL)
	a.applyEnforcement(c.UserContext(), a.lic.Current())
	if err != nil {
		return licenseError(c, err)
	}
	a.auth.AuditC(c, "license.synced", st.LicenseID, st.LastSync)
	return c.JSON(a.licenseBody(c.UserContext(), st))
}

func (a *App) updateLicenseSettings(c *fiber.Ctx) error {
	var s LicenseSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	s.ServerURL = strings.TrimRight(strings.TrimSpace(s.ServerURL), "/")
	if s.ServerURL != "" && !strings.HasPrefix(s.ServerURL, "https://") && !strings.HasPrefix(s.ServerURL, "http://") {
		return bad(c, "the license server URL must start with https://")
	}
	if s.SyncEnabled && s.ServerURL == "" {
		return bad(c, "set the license server URL to enable status sync")
	}
	if err := a.putSetting(c.UserContext(), "license", s); err != nil {
		return err
	}
	a.auth.AuditC(c, "license.settings_changed", "", s)
	return c.JSON(s)
}

// ---- DNS -------------------------------------------------------------------

func (a *App) getDNSSettings(c *fiber.Ctx) error {
	s, err := a.dnsSettings(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(s)
}

func (a *App) updateDNSSettings(c *fiber.Ctx) error {
	var s DNSSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	if err := s.Validate(); err != nil {
		return bad(c, err.Error())
	}
	if err := a.putSetting(c.UserContext(), "dns", s); err != nil {
		return err
	}
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	a.auth.AuditC(c, "dns.settings_changed", "", s)
	return c.JSON(s)
}

func (a *App) dnsStats(c *fiber.Ctx) error {
	return c.JSON(a.dns.Stats())
}

type domainEntry struct {
	Domain    string    `json:"domain"`
	Category  string    `json:"category"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// table is always one of two constants chosen in routes(), never user input.
func (a *App) listDomains(table string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		q := "%" + strings.ToLower(strings.TrimSpace(c.Query("q"))) + "%"
		rows, err := a.db.Query(c.UserContext(), `SELECT domain, category, note, created_at FROM `+table+`
			WHERE domain LIKE $1 ORDER BY domain LIMIT 1000`, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		out := []domainEntry{}
		for rows.Next() {
			var e domainEntry
			if err := rows.Scan(&e.Domain, &e.Category, &e.Note, &e.CreatedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		var total int
		_ = a.db.QueryRow(c.UserContext(), `SELECT count(*) FROM `+table).Scan(&total)
		return c.JSON(fiber.Map{"entries": out, "total": total})
	}
}

func (a *App) addDomain(table string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Domain   string `json:"domain"`
			Category string `json:"category"`
			Note     string `json:"note"`
		}
		if err := c.BodyParser(&req); err != nil {
			return bad(c, "invalid body")
		}
		d, err := normaliseDomain(req.Domain)
		if err != nil {
			return bad(c, err.Error())
		}
		cat := strings.TrimSpace(req.Category)
		if cat == "" {
			cat = map[string]string{"dns_blocklist": "custom", "dns_allowlist": "allow"}[table]
		}
		upsert := `INSERT INTO ` + table + `(domain, category, note) VALUES ($1,$2,$3) ON CONFLICT (domain) DO UPDATE SET category=$2, note=$3`
		if table == "dns_blocklist" {
			upsert += `, source_id=NULL` // added by hand: no longer owned by a subscription
		}
		if _, err := a.db.Exec(c.UserContext(), upsert, d, trunc(cat, 64), trunc(req.Note, 500)); err != nil {
			return err
		}
		if err := a.reloadDNS(c.UserContext()); err != nil {
			return err
		}
		a.auth.AuditC(c, table+".added", d, fiber.Map{"category": cat})
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"domain": d})
	}
}

func (a *App) deleteDomain(table string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		d, err := normaliseDomain(c.Params("domain"))
		if err != nil {
			return bad(c, err.Error())
		}
		tag, err := a.db.Exec(c.UserContext(), `DELETE FROM `+table+` WHERE domain=$1`, d)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
		}
		if err := a.reloadDNS(c.UserContext()); err != nil {
			return err
		}
		a.auth.AuditC(c, table+".removed", d, nil)
		return c.JSON(fiber.Map{"ok": true})
	}
}

// queryLogWriter stores query events in batches and prunes old rows.
func (a *App) queryLogWriter(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	prune := time.NewTicker(10 * time.Minute)
	defer prune.Stop()
	var batch [][]any
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if _, err := a.db.CopyFrom(ctx, pgx.Identifier{"dns_query_log"}, []string{"at", "client", "qname", "qtype", "action", "category"},
			pgx.CopyFromRows(batch)); err != nil {
			log.Printf("query log: %v", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev := <-a.dns.Events():
			var client any
			if ev.Client.IsValid() {
				client = ev.Client
			}
			batch = append(batch, []any{ev.At, client, trunc(ev.Name, 253), ev.Type, ev.Action, trunc(ev.Category, 64)})
			if len(batch) >= 5000 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-prune.C:
			a.pruneQueryLog(ctx)
		}
	}
}

// ---- firewall --------------------------------------------------------------

type ruleRow struct {
	ID        int64     `json:"id"`
	CIDR      string    `json:"cidr"`
	Direction string    `json:"direction"`
	Note      string    `json:"note"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *App) listRules(c *fiber.Ctx) error {
	rows, err := a.db.Query(c.UserContext(), `SELECT id, cidr::text, direction, note, enabled, created_at FROM firewall_rules ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []ruleRow{}
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.ID, &r.CIDR, &r.Direction, &r.Note, &r.Enabled, &r.CreatedAt); err != nil {
			return err
		}
		out = append(out, r)
	}
	return c.JSON(out)
}

// applyAfterChange pushes the rules to nftables and reports the outcome.
func (a *App) applyAfterChange(c *fiber.Ctx, status int, body fiber.Map) error {
	if err := a.syncFirewall(c.UserContext(), a.lic.Current()); err != nil {
		body["apply_error"] = err.Error()
	}
	a.applyMu.Lock()
	body["firewall"] = a.fwStatus
	a.applyMu.Unlock()
	return c.Status(status).JSON(body)
}

func (a *App) addRule(c *fiber.Ctx) error {
	var req struct {
		CIDR      string `json:"cidr"`
		Direction string `json:"direction"`
		Note      string `json:"note"`
	}
	if err := c.BodyParser(&req); err != nil {
		return bad(c, "invalid body")
	}
	r, err := firewall.ValidateRule(req.CIDR, req.Direction)
	if err != nil {
		return bad(c, err.Error())
	}
	var id int64
	err = a.db.QueryRow(c.UserContext(), `INSERT INTO firewall_rules(cidr, direction, note) VALUES ($1,$2,$3) RETURNING id`,
		r.CIDR.String(), r.Direction, trunc(req.Note, 500)).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return authkit.APIError(c, fiber.StatusConflict, "exists", "that rule already exists")
		}
		return err
	}
	a.auth.AuditC(c, "firewall.rule_added", r.CIDR.String(), fiber.Map{"direction": r.Direction})
	return a.applyAfterChange(c, fiber.StatusCreated, fiber.Map{"id": id})
}

func (a *App) updateRule(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	var req struct {
		Enabled bool   `json:"enabled"`
		Note    string `json:"note"`
	}
	if err := c.BodyParser(&req); err != nil {
		return bad(c, "invalid body")
	}
	tag, err := a.db.Exec(c.UserContext(), `UPDATE firewall_rules SET enabled=$2, note=$3 WHERE id=$1`, id, req.Enabled, trunc(req.Note, 500))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
	}
	a.auth.AuditC(c, "firewall.rule_updated", c.Params("id"), req)
	return a.applyAfterChange(c, fiber.StatusOK, fiber.Map{"ok": true})
}

func (a *App) deleteRule(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	var cidr string
	err = a.db.QueryRow(c.UserContext(), `DELETE FROM firewall_rules WHERE id=$1 RETURNING cidr::text`, id).Scan(&cidr)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
	}
	if err != nil {
		return err
	}
	a.auth.AuditC(c, "firewall.rule_removed", cidr, nil)
	return a.applyAfterChange(c, fiber.StatusOK, fiber.Map{"ok": true})
}

func (a *App) applyNow(c *fiber.Ctx) error {
	a.auth.AuditC(c, "firewall.applied", "", nil)
	return a.applyAfterChange(c, fiber.StatusOK, fiber.Map{"ok": true})
}

func (a *App) firewallStatus(c *fiber.Ctx) error {
	ruleset, err := a.fw.Status(c.UserContext())
	a.applyMu.Lock()
	st := a.fwStatus
	a.applyMu.Unlock()
	body := fiber.Map{"state": st, "ruleset": ruleset, "table": firewall.Family + " " + firewall.Table}
	if err != nil {
		body["error"] = err.Error()
	}
	return c.JSON(body)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
