package nc

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/dnsserver"
)

const statsRetentionDays = 30

// statsRecorder writes the resolver's counters to dns_stats_minute once a
// minute so the dashboard graph survives restarts.
type statsRecorder struct {
	mu   sync.Mutex
	last dnsserver.Stats // counters at the last flush
}

// pending returns the counts not yet written.
func (a *App) pendingStats() dnsserver.Stats {
	a.stats.mu.Lock()
	defer a.stats.mu.Unlock()
	return a.dns.Stats().Sub(a.stats.last)
}

func (a *App) flushStats(ctx context.Context, minute time.Time) {
	a.stats.mu.Lock()
	cur := a.dns.Stats()
	d := cur.Sub(a.stats.last)
	a.stats.mu.Unlock()
	if d.Total == 0 {
		return
	}
	_, err := a.db.Exec(ctx, `INSERT INTO dns_stats_minute(minute, total, forwarded, cached, blocked, refused, failed, local, nxdomain, latency_us_sum, latency_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (minute) DO UPDATE SET total=dns_stats_minute.total+$2, forwarded=dns_stats_minute.forwarded+$3,
		cached=dns_stats_minute.cached+$4, blocked=dns_stats_minute.blocked+$5, refused=dns_stats_minute.refused+$6,
		failed=dns_stats_minute.failed+$7, local=dns_stats_minute.local+$8, nxdomain=dns_stats_minute.nxdomain+$9,
		latency_us_sum=dns_stats_minute.latency_us_sum+$10, latency_count=dns_stats_minute.latency_count+$11`,
		minute, d.Total, d.Forwarded, d.Cached, d.Blocked, d.Refused, d.Failed, d.Local, d.Nxdomain, d.LatencyUsSum, d.LatencyCount)
	if err != nil {
		log.Printf("stats: %v", err)
		return
	}
	a.stats.mu.Lock()
	a.stats.last = cur
	a.stats.mu.Unlock()
}

// statsWriter flushes at every minute boundary and prunes old rows daily.
func (a *App) statsWriter(ctx context.Context) {
	lastPrune := time.Time{}
	for {
		now := time.Now().UTC()
		next := now.Truncate(time.Minute).Add(time.Minute)
		select {
		case <-ctx.Done():
			// Final partial minute, written with a fresh context.
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			a.flushStats(fctx, time.Now().UTC().Truncate(time.Minute))
			cancel()
			return
		case <-time.After(time.Until(next)):
		}
		a.flushStats(ctx, next.Add(-time.Minute))
		if time.Since(lastPrune) > 24*time.Hour {
			lastPrune = time.Now()
			_, _ = a.db.Exec(ctx, `DELETE FROM dns_stats_minute WHERE minute < now() - make_interval(days => $1)`, statsRetentionDays)
		}
	}
}

type statRange struct {
	span, bucket time.Duration
}

var statRanges = map[string]statRange{
	"15m": {15 * time.Minute, time.Minute},
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 2 * time.Hour},
	"30d": {30 * 24 * time.Hour, 12 * time.Hour},
}

type statPoint struct {
	T         time.Time `json:"t"`
	Total     int64     `json:"total"`
	Forwarded int64     `json:"forwarded"`
	Cached    int64     `json:"cached"`
	Blocked   int64     `json:"blocked"`
	Refused   int64     `json:"refused"`
	Failed    int64     `json:"failed"`
	Local     int64     `json:"local"`
	Nxdomain  int64     `json:"nxdomain"`
	LatUs     int64     `json:"-"`
	LatN      int64     `json:"-"`
	AvgMs     *float64  `json:"avg_ms"` // upstream response time; null when nothing was forwarded
}

func (p *statPoint) sum(o statPoint) {
	p.Total += o.Total
	p.Forwarded += o.Forwarded
	p.Cached += o.Cached
	p.Blocked += o.Blocked
	p.Refused += o.Refused
	p.Failed += o.Failed
	p.Local += o.Local
	p.Nxdomain += o.Nxdomain
	p.LatUs += o.LatUs
	p.LatN += o.LatN
}

func (p *statPoint) finish() {
	if p.LatN > 0 {
		v := float64(p.LatUs) / float64(p.LatN) / 1000
		p.AvgMs = &v
	}
}

func (p *statPoint) add(s dnsserver.Stats) {
	p.Total += int64(s.Total)
	p.Forwarded += int64(s.Forwarded)
	p.Cached += int64(s.Cached)
	p.Blocked += int64(s.Blocked)
	p.Refused += int64(s.Refused)
	p.Failed += int64(s.Failed)
	p.Local += int64(s.Local)
	p.Nxdomain += int64(s.Nxdomain)
	p.LatUs += int64(s.LatencyUsSum)
	p.LatN += int64(s.LatencyCount)
}

// timeseries returns counters in buckets for the dashboard graph, including
// the current, not yet written minute.
func (a *App) timeseries(c *fiber.Ctx) error {
	key := c.Query("range", "24h")
	r, ok := statRanges[key]
	if !ok {
		return bad(c, "range must be 15m, 1h, 24h, 7d or 30d")
	}
	now := time.Now().UTC()
	end := now.Truncate(r.bucket)
	start := end.Add(-r.span + r.bucket)
	rows, err := a.db.Query(c.UserContext(), `SELECT date_bin($1::interval, minute, TIMESTAMPTZ '2000-01-01') AS b,
		sum(total), sum(forwarded), sum(cached), sum(blocked), sum(refused), sum(failed), sum(local),
		sum(nxdomain), sum(latency_us_sum), sum(latency_count)
		FROM dns_stats_minute WHERE minute >= $2 GROUP BY b`,
		fmt.Sprintf("%d seconds", int(r.bucket.Seconds())), start)
	if err != nil {
		return err
	}
	defer rows.Close()
	byT := map[int64]statPoint{}
	for rows.Next() {
		var p statPoint
		if err := rows.Scan(&p.T, &p.Total, &p.Forwarded, &p.Cached, &p.Blocked, &p.Refused, &p.Failed, &p.Local,
			&p.Nxdomain, &p.LatUs, &p.LatN); err != nil {
			return err
		}
		byT[p.T.Unix()] = p
	}
	if err := rows.Err(); err != nil {
		return err
	}
	points := make([]statPoint, 0, int(r.span/r.bucket))
	var totals statPoint
	for t := start; !t.After(end); t = t.Add(r.bucket) {
		p := byT[t.Unix()]
		p.T = t
		if t.Equal(end) {
			p.add(a.pendingStats()) // live: counts since the last flush
		}
		totals.sum(p)
		p.finish()
		points = append(points, p)
	}
	totals.finish()
	// The same span just before, for "vs previous period".
	var prev statPoint
	if err := a.db.QueryRow(c.UserContext(), `SELECT coalesce(sum(total),0), coalesce(sum(forwarded),0), coalesce(sum(cached),0),
		coalesce(sum(blocked),0), coalesce(sum(refused),0), coalesce(sum(failed),0), coalesce(sum(local),0),
		coalesce(sum(nxdomain),0), coalesce(sum(latency_us_sum),0), coalesce(sum(latency_count),0)
		FROM dns_stats_minute WHERE minute >= $1 AND minute < $2`, start.Add(-r.span), start).
		Scan(&prev.Total, &prev.Forwarded, &prev.Cached, &prev.Blocked, &prev.Refused, &prev.Failed, &prev.Local,
			&prev.Nxdomain, &prev.LatUs, &prev.LatN); err != nil {
		return err
	}
	prev.finish()
	// Peak and current queries per second, from whole minutes.
	var peakMinute int64
	_ = a.db.QueryRow(c.UserContext(), `SELECT coalesce(max(total),0) FROM dns_stats_minute WHERE minute >= $1`, start).Scan(&peakMinute)
	var lastMinute int64
	_ = a.db.QueryRow(c.UserContext(), `SELECT coalesce(sum(total),0) FROM dns_stats_minute WHERE minute = $1`, now.Truncate(time.Minute).Add(-time.Minute)).Scan(&lastMinute)
	qps := fiber.Map{"current": float64(lastMinute) / 60, "peak": float64(peakMinute) / 60}
	return c.JSON(fiber.Map{"range": key, "bucket_seconds": int(r.bucket.Seconds()), "points": points, "totals": totals,
		"previous": prev, "qps": qps})
}

type topItem struct {
	Key     string `json:"key"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked,omitempty"`
}

// top returns the most blocked domains, the most queried domains and the
// busiest clients from the query log.
func (a *App) top(c *fiber.Ctx) error {
	key := c.Query("range", "24h")
	r, ok := statRanges[key]
	if !ok {
		return bad(c, "range must be 15m, 1h, 24h, 7d or 30d")
	}
	since := time.Now().UTC().Add(-r.span)
	ctx := c.UserContext()
	query := func(sql string) ([]topItem, error) {
		rows, err := a.db.Query(ctx, sql, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []topItem{}
		for rows.Next() {
			var it topItem
			if err := rows.Scan(&it.Key, &it.Count, &it.Blocked); err != nil {
				return nil, err
			}
			out = append(out, it)
		}
		return out, rows.Err()
	}
	blocked, err := query(`SELECT qname, count(*), 0 FROM dns_query_log WHERE at >= $1 AND action='blocked' GROUP BY qname ORDER BY 2 DESC, 1 LIMIT 10`)
	if err != nil {
		return err
	}
	domains, err := query(`SELECT qname, count(*), count(*) FILTER (WHERE action='blocked') FROM dns_query_log WHERE at >= $1 GROUP BY qname ORDER BY 2 DESC, 1 LIMIT 10`)
	if err != nil {
		return err
	}
	clients, err := query(`SELECT coalesce(host(client),'?'), count(*), count(*) FILTER (WHERE action='blocked') FROM dns_query_log WHERE at >= $1 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"range": key, "blocked_domains": blocked, "domains": domains, "clients": clients})
}

// exportQueryLog downloads the query log as CSV (newest first, max 100 000 rows).
func (a *App) exportQueryLog(c *fiber.Ctx) error {
	key := c.Query("range", "24h")
	r, ok := statRanges[key]
	if !ok {
		return bad(c, "range must be 15m, 1h, 24h, 7d or 30d")
	}
	q := "%" + strings.ToLower(strings.TrimSpace(c.Query("q"))) + "%"
	action := c.Query("action")
	rows, err := a.db.Query(c.UserContext(), `SELECT at, coalesce(host(client),''), qname, qtype, action FROM dns_query_log
		WHERE at >= $1 AND (qname LIKE $2 OR coalesce(host(client),'') LIKE $2) AND ($3 = '' OR action = $3)
		ORDER BY at DESC LIMIT 100000`, time.Now().UTC().Add(-r.span), q, action)
	if err != nil {
		return err
	}
	defer rows.Close()
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"time_utc", "client", "name", "type", "result"})
	n := 0
	for rows.Next() {
		var at time.Time
		var client, name, typ, act string
		if err := rows.Scan(&at, &client, &name, &typ, &act); err != nil {
			return err
		}
		_ = w.Write([]string{at.UTC().Format(time.RFC3339), client, name, typ, act})
		n++
	}
	w.Flush()
	a.auth.AuditC(c, "querylog.exported", key, fiber.Map{"rows": n})
	c.Set(fiber.HeaderContentType, "text/csv; charset=utf-8")
	c.Set(fiber.HeaderContentDisposition, fmt.Sprintf(`attachment; filename="isp-netcontrol-querylog-%s.csv"`, time.Now().UTC().Format("20060102-1504")))
	return c.SendString(sb.String())
}
