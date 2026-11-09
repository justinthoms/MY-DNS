package nc

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// QueryLogSettings controls how long the query log is kept.
type QueryLogSettings struct {
	RetentionHours int    `json:"retention_hours"`
	Mode           string `json:"mode"`   // all | important | off
	Sample         int    `json:"sample"` // with "all": keep 1 in N allowed queries
}

const maxRetentionHours = 90 * 24

func (a *App) queryLogSettings(ctx context.Context) QueryLogSettings {
	s := QueryLogSettings{RetentionHours: a.cfg.QueryLogDays * 24}
	if _, err := a.getSetting(ctx, "querylog", &s); err != nil {
		log.Printf("settings: %v", err)
	}
	if s.RetentionHours < 1 || s.RetentionHours > maxRetentionHours {
		s.RetentionHours = a.cfg.QueryLogDays * 24
	}
	if s.Mode == "" {
		s.Mode = "all"
	}
	if s.Sample < 1 {
		s.Sample = 1
	}
	return s
}

func (a *App) pruneQueryLog(ctx context.Context) {
	h := a.queryLogSettings(ctx).RetentionHours
	if _, err := a.db.Exec(ctx, `DELETE FROM dns_query_log WHERE at < now() - make_interval(hours => $1)`, h); err != nil {
		log.Printf("query log prune: %v", err)
	}
}

func (a *App) getQueryLogSettings(c *fiber.Ctx) error {
	return c.JSON(a.queryLogSettings(c.UserContext()))
}

func (a *App) updateQueryLogSettings(c *fiber.Ctx) error {
	var s QueryLogSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	if s.RetentionHours < 1 || s.RetentionHours > maxRetentionHours {
		return bad(c, "keep the query log between 1 hour and 90 days")
	}
	if s.Mode == "" {
		s.Mode = "all"
	}
	if s.Mode != "all" && s.Mode != "important" && s.Mode != "off" {
		return bad(c, `mode must be "all", "important" or "off"`)
	}
	if s.Sample == 0 {
		s.Sample = 1
	}
	if s.Sample < 1 || s.Sample > 1000 {
		return bad(c, "sample must be between 1 (every query) and 1000")
	}
	if err := a.putSetting(c.UserContext(), "querylog", s); err != nil {
		return err
	}
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	a.pruneQueryLog(c.UserContext()) // apply a shorter retention immediately
	a.auth.AuditC(c, "querylog.settings_changed", "", s)
	return c.JSON(s)
}

var pageSizes = map[int]bool{25: true, 50: true, 100: true, 200: true}

// queryLog returns one page of the query log, newest first.
func (a *App) queryLog(c *fiber.Ctx) error {
	size := c.QueryInt("page_size", 50)
	if !pageSizes[size] {
		size = 50
	}
	page := c.QueryInt("page", 1)
	if page < 1 {
		page = 1
	}
	q := "%" + strings.ToLower(strings.TrimSpace(c.Query("q"))) + "%"
	action := c.Query("action")
	ctx := c.UserContext()
	const where = `(qname LIKE $1 OR coalesce(host(client),'') LIKE $1) AND ($2 = '' OR action = $2)`
	var total int64
	if err := a.db.QueryRow(ctx, `SELECT count(*) FROM dns_query_log WHERE `+where, q, action).Scan(&total); err != nil {
		return err
	}
	pages := int((total + int64(size) - 1) / int64(size))
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	rows, err := a.db.Query(ctx, `SELECT at, coalesce(host(client),''), qname, qtype, action FROM dns_query_log
		WHERE `+where+` ORDER BY at DESC, id DESC LIMIT $3 OFFSET $4`, q, action, size, (page-1)*size)
	if err != nil {
		return err
	}
	defer rows.Close()
	type entry struct {
		At     time.Time `json:"at"`
		Client string    `json:"client"`
		Name   string    `json:"name"`
		Type   string    `json:"type"`
		Action string    `json:"action"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.At, &e.Client, &e.Name, &e.Type, &e.Action); err != nil {
			return err
		}
		out = append(out, e)
	}
	qs := a.queryLogSettings(ctx)
	return c.JSON(fiber.Map{"entries": out, "total": total, "page": page, "pages": pages, "page_size": size,
		"retention_hours": qs.RetentionHours, "mode": qs.Mode, "sample": qs.Sample, "dropped": a.dns.Stats().LogDropped})
}
