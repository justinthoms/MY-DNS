package nc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/dnsserver"
	"github.com/justinthoms/my-dns/shared/authkit"
)

type recordRow struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	Priority  int       `json:"priority"`
	Note      string    `json:"note"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type recordReq struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      *int   `json:"ttl"`
	Priority int    `json:"priority"`
	Note     string `json:"note"`
	Enabled  *bool  `json:"enabled"`
}

// normalise validates the record and returns it in stored form.
func (r *recordReq) normalise() (dns.RR, error) {
	ttl := 300
	if r.TTL != nil {
		ttl = *r.TTL
	}
	if ttl < 0 || ttl > 86400 {
		return nil, errors.New("TTL must be between 0 and 86400 seconds")
	}
	if r.Priority < 0 || r.Priority > 65535 {
		return nil, errors.New("priority must be between 0 and 65535")
	}
	rr, err := dnsserver.BuildRR(r.Name, r.Type, uint32(ttl), r.Value, uint16(r.Priority))
	if err != nil {
		return nil, err
	}
	r.TTL = &ttl
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Name = strings.TrimSuffix(rr.Header().Name, ".")
	switch x := rr.(type) {
	case *dns.A:
		r.Value = x.A.String()
	case *dns.AAAA:
		r.Value = x.AAAA.String()
	case *dns.CNAME:
		r.Value = strings.TrimSuffix(x.Target, ".")
	case *dns.PTR:
		r.Value = strings.TrimSuffix(x.Ptr, ".")
	case *dns.MX:
		r.Value = strings.TrimSuffix(x.Mx, ".")
	case *dns.TXT:
		r.Value = strings.Join(x.Txt, "")
	}
	return rr, nil
}

// loadRecords builds the resolver's record set from enabled records.
func (a *App) loadRecords(ctx context.Context) (dnsserver.Records, error) {
	rows, err := a.db.Query(ctx, `SELECT name, type, value, ttl, priority FROM dns_records WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	recs := dnsserver.Records{}
	for rows.Next() {
		var name, typ, value string
		var ttl, prio int
		if err := rows.Scan(&name, &typ, &value, &ttl, &prio); err != nil {
			return nil, err
		}
		rr, err := dnsserver.BuildRR(name, typ, uint32(ttl), value, uint16(prio))
		if err != nil {
			continue // cannot happen for rows written through the API
		}
		_ = recs.Add(rr)
	}
	return recs, rows.Err()
}

func (a *App) listRecords(c *fiber.Ctx) error {
	q := "%" + strings.ToLower(strings.TrimSpace(c.Query("q"))) + "%"
	rows, err := a.db.Query(c.UserContext(), `SELECT id, name, type, value, ttl, priority, note, enabled, created_at
		FROM dns_records WHERE name LIKE $1 OR value LIKE $1 ORDER BY name, type, value`, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []recordRow{}
	for rows.Next() {
		var r recordRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority, &r.Note, &r.Enabled, &r.CreatedAt); err != nil {
			return err
		}
		out = append(out, r)
	}
	return c.JSON(out)
}

// checkConflicts enforces the DNS rule that a CNAME is the only record of its name.
func (a *App) checkConflicts(ctx context.Context, name, typ string, exceptID int64) error {
	var n int
	sql := `SELECT count(*) FROM dns_records WHERE name=$1 AND id<>$2 AND enabled`
	if typ == "CNAME" {
		err := a.db.QueryRow(ctx, sql, name, exceptID).Scan(&n)
		if err == nil && n > 0 {
			return errors.New("a CNAME cannot coexist with other records for " + name)
		}
		return err
	}
	err := a.db.QueryRow(ctx, sql+` AND type='CNAME'`, name, exceptID).Scan(&n)
	if err == nil && n > 0 {
		return errors.New(name + " already has a CNAME record; a name with a CNAME cannot have other records")
	}
	return err
}

func (a *App) addRecord(c *fiber.Ctx) error {
	var req recordReq
	if err := c.BodyParser(&req); err != nil {
		return bad(c, "invalid body")
	}
	if _, err := req.normalise(); err != nil {
		return bad(c, err.Error())
	}
	if err := a.checkConflicts(c.UserContext(), req.Name, req.Type, 0); err != nil {
		return bad(c, err.Error())
	}
	var id int64
	err := a.db.QueryRow(c.UserContext(), `INSERT INTO dns_records(name, type, value, ttl, priority, note) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		req.Name, req.Type, req.Value, *req.TTL, req.Priority, trunc(req.Note, 500)).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return authkit.APIError(c, fiber.StatusConflict, "exists", "that record already exists")
		}
		return err
	}
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	a.auth.AuditC(c, "dns_record.added", req.Name, fiber.Map{"type": req.Type, "value": req.Value})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id, "name": req.Name, "value": req.Value})
}

func (a *App) updateRecord(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	var req recordReq
	if err := c.BodyParser(&req); err != nil {
		return bad(c, "invalid body")
	}
	if _, err := req.normalise(); err != nil {
		return bad(c, err.Error())
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if enabled {
		if err := a.checkConflicts(c.UserContext(), req.Name, req.Type, int64(id)); err != nil {
			return bad(c, err.Error())
		}
	}
	tag, err := a.db.Exec(c.UserContext(), `UPDATE dns_records SET name=$2, type=$3, value=$4, ttl=$5, priority=$6, note=$7, enabled=$8 WHERE id=$1`,
		id, req.Name, req.Type, req.Value, *req.TTL, req.Priority, trunc(req.Note, 500), enabled)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return authkit.APIError(c, fiber.StatusConflict, "exists", "that record already exists")
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
	}
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	a.auth.AuditC(c, "dns_record.updated", req.Name, fiber.Map{"type": req.Type, "value": req.Value, "enabled": enabled})
	return c.JSON(fiber.Map{"ok": true})
}

func (a *App) deleteRecord(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return bad(c, "invalid id")
	}
	var name, typ string
	err = a.db.QueryRow(c.UserContext(), `DELETE FROM dns_records WHERE id=$1 RETURNING name, type`, id).Scan(&name, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.APIError(c, fiber.StatusNotFound, "not_found", "not found")
	}
	if err != nil {
		return err
	}
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	a.auth.AuditC(c, "dns_record.removed", name, fiber.Map{"type": typ})
	return c.JSON(fiber.Map{"ok": true})
}

// checkDomain explains how the resolver would treat a name right now.
func (a *App) checkDomain(c *fiber.Ctx) error {
	name, err := normaliseDomain(c.Query("name"))
	if err != nil {
		return bad(c, err.Error())
	}
	p := a.dns.Policy()
	res := fiber.Map{"name": name, "filtering_active": p.Filtering}
	if rrs := p.Records.Lookup(name); rrs != nil {
		var vals []string
		for _, rr := range rrs {
			vals = append(vals, strings.TrimPrefix(rr.String(), rr.Header().Name+"\t"))
		}
		res["result"] = "local"
		res["records"] = vals
		return c.JSON(res)
	}
	decision, cat, matched := p.Explain(name)
	switch {
	case decision == "blocked" && p.Filtering:
		res["result"] = "blocked"
	case decision == "blocked":
		res["result"] = "forwarded"
		res["note"] = "on the block list, but filtering is not active"
	case decision == "allowed":
		res["result"] = "allowed"
	default:
		res["result"] = "forwarded"
	}
	res["matched"] = matched
	res["category"] = cat
	if matched != "" && decision == "blocked" {
		var src string
		_ = a.db.QueryRow(c.UserContext(), `SELECT coalesce(s.name, 'added by hand') FROM dns_blocklist b
			LEFT JOIN blocklist_sources s ON s.id=b.source_id WHERE b.domain=$1`, matched).Scan(&src)
		res["source"] = src
	}
	return c.JSON(res)
}
