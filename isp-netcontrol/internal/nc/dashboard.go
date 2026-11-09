package nc

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/sys/unix"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/dnsserver"
)

var processStart = time.Now()

type countItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// breakdown returns query types and block categories from the query log.
func (a *App) breakdown(c *fiber.Ctx) error {
	key := c.Query("range", "24h")
	r, ok := statRanges[key]
	if !ok {
		return bad(c, "range must be 15m, 1h, 24h, 7d or 30d")
	}
	since := time.Now().UTC().Add(-r.span)
	ctx := c.UserContext()
	group := func(sql string) ([]countItem, error) {
		rows, err := a.db.Query(ctx, sql, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []countItem{}
		for rows.Next() {
			var it countItem
			if err := rows.Scan(&it.Key, &it.Count); err != nil {
				return nil, err
			}
			out = append(out, it)
		}
		return out, rows.Err()
	}
	types, err := group(`SELECT qtype, count(*) FROM dns_query_log WHERE at >= $1 GROUP BY qtype ORDER BY 2 DESC, 1 LIMIT 12`)
	if err != nil {
		return err
	}
	cats, err := group(`SELECT CASE WHEN category = '' THEN 'uncategorised' ELSE category END, count(*) FROM dns_query_log
		WHERE at >= $1 AND action = 'blocked' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 12`)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"range": key, "query_types": types, "block_categories": cats})
}

func readLoadavg() []float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	f := strings.Fields(string(raw))
	out := []float64{}
	for i := 0; i < 3 && i < len(f); i++ {
		v, _ := strconv.ParseFloat(f[i], 64)
		out = append(out, v)
	}
	return out
}

func readMeminfo() (total, available uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fs[1], 10, 64)
		switch fs[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			available = v * 1024
		}
	}
	return total, available
}

// systemHealth reports the state of every part of this server.
func (a *App) systemHealth(c *fiber.Ctx) error {
	ctx := c.UserContext()
	t0 := time.Now()
	dbErr := a.db.Ping(ctx)
	dbMs := float64(time.Since(t0).Microseconds()) / 1000
	var dbSize int64
	if dbErr == nil {
		_ = a.db.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&dbSize)
	}
	memTotal, memAvail := readMeminfo()
	disk := fiber.Map{}
	var fs unix.Statfs_t
	if err := unix.Statfs(a.cfg.StateDir, &fs); err == nil {
		disk["total"] = fs.Blocks * uint64(fs.Bsize)
		disk["free"] = fs.Bavail * uint64(fs.Bsize)
	}
	a.applyMu.Lock()
	fw := a.fwStatus
	a.applyMu.Unlock()
	lic := a.lic.Current()
	ac := a.anycast.Status()
	dbBody := fiber.Map{"ok": dbErr == nil, "ping_ms": dbMs, "size_bytes": dbSize}
	if dbErr != nil {
		dbBody["error"] = dbErr.Error()
	}
	return c.JSON(fiber.Map{
		"version":    Version,
		"uptime_s":   int64(time.Since(processStart).Seconds()),
		"dns":        fiber.Map{"listening": a.dns.Addrs(), "ok": len(a.dns.Addrs()) > 0},
		"upstreams":  a.dns.UpstreamStats(),
		"protection": protectionSummary(a.dns.ProtectionStatus()),
		"database":   dbBody,
		"firewall":   fiber.Map{"managed": a.fw.Enabled, "applied": fw.Applied, "rules": fw.Rules, "error": fw.Error},
		"license":    fiber.Map{"mode": lic.Mode, "days_left": lic.DaysLeft, "message": lic.Message},
		"anycast":    fiber.Map{"enabled": ac.Enabled, "monitor_only": ac.MonitorOnly, "interface": ac.Interface, "link_up": ac.LinkUp, "healthy": ac.Healthy, "mode": ac.Mode},
		"host": fiber.Map{"cpus": runtime.NumCPU(), "load": readLoadavg(), "mem_total": memTotal, "mem_available": memAvail,
			"disk": disk},
	})
}

// protectionSummary is the dashboard's view of the attack defences.
func protectionSummary(st dnsserver.ProtectionStatus) fiber.Map {
	zones := make([]string, 0, len(st.Zones))
	for _, z := range st.Zones {
		zones = append(zones, z.Zone)
	}
	return fiber.Map{"rate_limited": st.RateLimited, "throttled": st.Throttled, "minimal_any": st.MinimalANY,
		"limited_clients": len(st.LimitedClients), "zones_under_attack": zones}
}
