package nc

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/justinthoms/my-dns/shared/authkit"
)

// listEntry is one parsed line of an imported list.
type listEntry struct {
	Domain   string
	Category string // from a CSV column; empty = use the import's category
	Note     string
}

const maxListEntries = 1_000_000

// parseList reads a domain list in any of the common formats, one entry per
// line:
//
//	example.com                  plain domain (or *.example.com)
//	0.0.0.0 a.example b.example  hosts file
//	||example.com^               Adblock-style domain rule (options other than $important are skipped)
//	domain,category,note         CSV, as written by the export (header optional)
//
// Comments (#, !) and anything else are skipped and counted.
func parseList(r io.Reader) (entries []listEntry, skipped int, err error) {
	seen := map[string]bool{}
	add := func(e listEntry) {
		d, err := normaliseDomain(e.Domain)
		if err != nil || d == "localhost" || d == "localhost.localdomain" || d == "local" || d == "broadcasthost" {
			skipped++
			return
		}
		if seen[d] {
			return
		}
		seen[d] = true
		e.Domain = d
		entries = append(entries, e)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(entries) > maxListEntries {
			return nil, 0, fmt.Errorf("too many entries (max %d)", maxListEntries)
		}
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "||"):
			rule := strings.TrimPrefix(line, "||")
			end := strings.IndexByte(rule, '^')
			if end < 0 || (rule[end+1:] != "" && rule[end+1:] != "$important") {
				skipped++ // path or option rules cannot be expressed in DNS
				continue
			}
			add(listEntry{Domain: rule[:end]})
		case strings.Contains(line, ","):
			rec, err := csv.NewReader(strings.NewReader(line)).Read()
			if err != nil || len(rec) == 0 {
				skipped++
				continue
			}
			if strings.EqualFold(strings.TrimSpace(rec[0]), "domain") {
				continue // header
			}
			e := listEntry{Domain: rec[0]}
			if len(rec) > 1 {
				e.Category = strings.TrimSpace(rec[1])
			}
			if len(rec) > 2 {
				e.Note = strings.TrimSpace(rec[2])
			}
			add(e)
		default:
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if _, err := netip.ParseAddr(fields[0]); err == nil && len(fields) >= 2 {
				for _, f := range fields[1:] {
					add(listEntry{Domain: f})
				}
			} else if len(fields) == 1 {
				add(listEntry{Domain: fields[0]})
			} else {
				skipped++
			}
		}
	}
	return entries, skipped, sc.Err()
}

// insertEntries loads entries into table through a temporary table. Existing
// entries are left alone (ON CONFLICT DO NOTHING), so hand-made entries are
// never overwritten by an import or a subscription.
func insertEntries(ctx context.Context, tx pgx.Tx, table string, entries []listEntry, defCategory string, sourceID *int64) (int64, error) {
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE IF NOT EXISTS import_entries (domain TEXT, category TEXT, note TEXT) ON COMMIT DROP`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `TRUNCATE import_entries`); err != nil {
		return 0, err
	}
	rows := make([][]any, len(entries))
	for i, e := range entries {
		cat := e.Category
		if cat == "" {
			cat = defCategory
		}
		rows[i] = []any{e.Domain, trunc(cat, 64), trunc(e.Note, 500)}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"import_entries"}, []string{"domain", "category", "note"}, pgx.CopyFromRows(rows)); err != nil {
		return 0, err
	}
	sql := `INSERT INTO ` + table + `(domain, category, note) SELECT DISTINCT ON (domain) domain, category, note FROM import_entries ON CONFLICT (domain) DO NOTHING`
	args := []any{}
	if table == "dns_blocklist" {
		sql = `INSERT INTO dns_blocklist(domain, category, note, source_id) SELECT DISTINCT ON (domain) domain, category, note, $1::bigint FROM import_entries ON CONFLICT (domain) DO NOTHING`
		args = append(args, sourceID)
	}
	tag, err := tx.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

// importList imports into the block list or the allow list.
// mode "merge" (default) adds new entries; "replace" first removes every
// entry added by hand (subscription entries stay).
func (a *App) importList(table string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Text     string `json:"text"`
			Category string `json:"category"`
			Mode     string `json:"mode"`
		}
		if err := c.BodyParser(&req); err != nil {
			return bad(c, "invalid body")
		}
		if req.Mode == "" {
			req.Mode = "merge"
		}
		if req.Mode != "merge" && req.Mode != "replace" {
			return bad(c, `mode must be "merge" or "replace"`)
		}
		cat := strings.TrimSpace(req.Category)
		if cat == "" {
			cat = map[string]string{"dns_blocklist": "imported", "dns_allowlist": "allow"}[table]
		}
		entries, skipped, err := parseList(strings.NewReader(req.Text))
		if err != nil {
			return bad(c, err.Error())
		}
		ctx := c.UserContext()
		tx, err := a.db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		var removed int64
		if req.Mode == "replace" {
			del := `DELETE FROM ` + table
			if table == "dns_blocklist" {
				del += ` WHERE source_id IS NULL`
			}
			tag, err := tx.Exec(ctx, del)
			if err != nil {
				return err
			}
			removed = tag.RowsAffected()
		}
		added, err := insertEntries(ctx, tx, table, entries, cat, nil)
		if err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		if err := a.reloadDNS(ctx); err != nil {
			return err
		}
		res := fiber.Map{"added": added, "already_present": int64(len(entries)) - added, "skipped": skipped, "removed": removed, "mode": req.Mode}
		a.auth.AuditC(c, table+".imported", cat, res)
		return c.JSON(res)
	}
}

// exportList downloads a list as plain text, hosts file or CSV.
func (a *App) exportList(table string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		format := c.Query("format", "txt")
		if format != "txt" && format != "hosts" && format != "csv" {
			return bad(c, `format must be "txt", "hosts" or "csv"`)
		}
		sql := `SELECT domain, category, note, '' FROM ` + table + ` ORDER BY domain`
		if table == "dns_blocklist" {
			sql = `SELECT b.domain, b.category, b.note, coalesce(s.name, '') FROM dns_blocklist b
				LEFT JOIN blocklist_sources s ON s.id = b.source_id ORDER BY b.domain`
		}
		if c.Query("manual") == "1" && table == "dns_blocklist" {
			sql = strings.Replace(sql, "ORDER BY", "WHERE b.source_id IS NULL ORDER BY", 1)
		}
		rows, err := a.db.Query(c.UserContext(), sql)
		if err != nil {
			return err
		}
		defer rows.Close()
		name := map[string]string{"dns_blocklist": "blocklist", "dns_allowlist": "allowlist"}[table]
		var sb strings.Builder
		var cw *csv.Writer
		switch format {
		case "csv":
			cw = csv.NewWriter(&sb)
			_ = cw.Write([]string{"domain", "category", "note", "source"})
		default:
			fmt.Fprintf(&sb, "# ISP NetControl %s, exported %s\n", name, time.Now().UTC().Format(time.RFC3339))
		}
		n := 0
		for rows.Next() {
			var d, cat, note, src string
			if err := rows.Scan(&d, &cat, &note, &src); err != nil {
				return err
			}
			n++
			switch format {
			case "csv":
				_ = cw.Write([]string{d, cat, note, src})
			case "hosts":
				fmt.Fprintf(&sb, "0.0.0.0 %s\n", d)
			default:
				sb.WriteString(d + "\n")
			}
		}
		if cw != nil {
			cw.Flush()
		}
		ext := map[string]string{"txt": "txt", "hosts": "hosts", "csv": "csv"}[format]
		a.auth.AuditC(c, table+".exported", format, fiber.Map{"entries": n})
		c.Set(fiber.HeaderContentType, "text/plain; charset=utf-8")
		if format == "csv" {
			c.Set(fiber.HeaderContentType, "text/csv; charset=utf-8")
		}
		c.Set(fiber.HeaderContentDisposition, fmt.Sprintf(`attachment; filename="isp-netcontrol-%s-%s.%s"`, name, time.Now().UTC().Format("20060102"), ext))
		return c.SendString(sb.String())
	}
}

// ---- block-list subscriptions ------------------------------------------------

type source struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Category    string     `json:"category"`
	Enabled     bool       `json:"enabled"`
	LastFetchAt *time.Time `json:"last_fetch_at"`
	LastStatus  string     `json:"last_status"`
	Entries     int        `json:"entries"`
}

const sourceRefreshInterval = 24 * time.Hour

func (a *App) listSources(c *fiber.Ctx) error {
	rows, err := a.db.Query(c.UserContext(), `SELECT id, name, url, category, enabled, last_fetch_at, last_status, entries FROM blocklist_sources ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []source{}
	for rows.Next() {
		var s source
		if err := rows.Scan(&s.ID, &s.Name, &s.URL, &s.Category, &s.Enabled, &s.LastFetchAt, &s.LastStatus, &s.Entries); err != nil {
			return err
		}
		out = append(out, s)
	}
	return c.JSON(out)
}

func (a *App) addSource(c *fiber.Ctx) error {
	var req struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Category string `json:"category"`
	}
	if err := c.BodyParser(&req); err != nil {
		return bad(c, "invalid body")
	}
	u, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return bad(c, "the URL must start with https:// (or http://)")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = u.Host
	}
	cat := strings.TrimSpace(req.Category)
	if cat == "" {
		cat = "subscription"
	}
	var id int64
	err = a.db.QueryRow(c.UserContext(), `INSERT INTO blocklist_sources(name, url, category) VALUES ($1,$2,$3) RETURNING id`,
		trunc(req.Name, 100), u.String(), trunc(cat, 64)).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return authkit.APIError(c, fiber.StatusConflict, "exists", "that URL is already subscribed")
		}
		return err
	}
	a.auth.AuditC(c, "blocklist_source.added", u.String(), fiber.Map{"name": req.Name})
	res, ferr := a.refreshSource(c.UserContext(), id)
	body := fiber.Map{"id": id, "result": res}
	if ferr != nil {
		body["error"] = ferr.Error()
	}
	return c.Status(fiber.StatusCreated).JSON(body)
}

func (a *App) updateSource(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&req); err != nil {
		return bad(c, "invalid body")
	}
	ctx := c.UserContext()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE blocklist_sources SET enabled=$2 WHERE id=$1`, id, req.Enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
	}
	if !req.Enabled {
		if _, err := tx.Exec(ctx, `DELETE FROM dns_blocklist WHERE source_id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE blocklist_sources SET entries=0, last_status='disabled' WHERE id=$1`, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	a.auth.AuditC(c, "blocklist_source.updated", c.Params("id"), req)
	if req.Enabled {
		if _, err := a.refreshSource(ctx, int64(id)); err != nil {
			return c.JSON(fiber.Map{"ok": true, "error": err.Error()})
		}
	} else if err := a.reloadDNS(ctx); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (a *App) deleteSource(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	var u string
	// ON DELETE CASCADE removes the source's entries.
	err = a.db.QueryRow(c.UserContext(), `DELETE FROM blocklist_sources WHERE id=$1 RETURNING url`, id).Scan(&u)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
	}
	if err != nil {
		return err
	}
	a.auth.AuditC(c, "blocklist_source.removed", u, nil)
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (a *App) refreshSourceNow(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	res, err := a.refreshSource(c.UserContext(), int64(id))
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error(), "code": "fetch_failed"})
	}
	a.auth.AuditC(c, "blocklist_source.refreshed", c.Params("id"), res)
	return c.JSON(res)
}

var sourceHTTP = &http.Client{Timeout: 2 * time.Minute}

// refreshSource downloads a subscription and replaces its entries.
func (a *App) refreshSource(ctx context.Context, id int64) (fiber.Map, error) {
	var u, cat string
	var enabled bool
	if err := a.db.QueryRow(ctx, `SELECT url, category, enabled FROM blocklist_sources WHERE id=$1`, id).Scan(&u, &cat, &enabled); err != nil {
		return nil, err
	}
	if !enabled {
		return nil, errors.New("subscription is disabled")
	}
	record := func(status string, entries int) {
		_, _ = a.db.Exec(ctx, `UPDATE blocklist_sources SET last_fetch_at=now(), last_status=$2, entries=$3 WHERE id=$1`, id, trunc(status, 300), entries)
	}
	keep := func(status string) {
		_, _ = a.db.Exec(ctx, `UPDATE blocklist_sources SET last_fetch_at=now(), last_status=$2 WHERE id=$1`, id, trunc(status, 300))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		keep("error: " + err.Error())
		return nil, err
	}
	req.Header.Set("User-Agent", "ISP-NetControl/"+Version)
	resp, err := sourceHTTP.Do(req)
	if err != nil {
		keep("error: " + err.Error())
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		keep("error: HTTP " + strconv.Itoa(resp.StatusCode))
		return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	entries, skipped, err := parseList(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		keep("error: " + err.Error())
		return nil, err
	}
	if len(entries) == 0 {
		// Keep the previous entries rather than silently dropping protection.
		keep("error: the list was empty or had no valid domains")
		return nil, errors.New("the downloaded list contains no valid domains")
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM dns_blocklist WHERE source_id=$1`, id); err != nil {
		return nil, err
	}
	sid := id
	added, err := insertEntries(ctx, tx, "dns_blocklist", entries, cat, &sid)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	record(fmt.Sprintf("ok: %d domains (%d already listed elsewhere, %d lines skipped)", added, int64(len(entries))-added, skipped), int(added))
	if err := a.reloadDNS(ctx); err != nil {
		return nil, err
	}
	return fiber.Map{"entries": added, "duplicates": int64(len(entries)) - added, "skipped": skipped}, nil
}

// sourceRefresher refreshes enabled subscriptions once a day.
func (a *App) sourceRefresher(ctx context.Context) {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		rows, err := a.db.Query(ctx, `SELECT id FROM blocklist_sources WHERE enabled
			AND (last_fetch_at IS NULL OR last_fetch_at < now() - $1::interval)`, fmt.Sprintf("%d seconds", int(sourceRefreshInterval.Seconds())))
		if err == nil {
			var ids []int64
			for rows.Next() {
				var id int64
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				if _, err := a.refreshSource(ctx, id); err != nil {
					log.Printf("block list subscription %d: %v", id, err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
