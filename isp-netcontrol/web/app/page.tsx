"use client";

import Link from "next/link";
import { ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError, get, tzName } from "@/lib/api";
import { LicenseState, MODE_LABEL } from "@/lib/license";
import { Alert, Shell } from "@/components/ui";
import LineChart, { Series } from "@/components/LineChart";

type Point = { t: string; total: number; forwarded: number; cached: number; blocked: number; refused: number; failed: number; local: number; nxdomain: number; avg_ms: number | null };
type TS = { range: string; bucket_seconds: number; points: Point[]; totals: Point; previous: Point; qps: { current: number; peak: number } };
type Item = { key: string; count: number; blocked?: number };
type Top = { blocked_domains: Item[]; domains: Item[]; clients: Item[] };
type Breakdown = { query_types: Item[]; block_categories: Item[] };
type Upstream = { addr: string; queries: number; failures: number; avg_ms: number; healthy: boolean | null; last_error?: string };
type Health = {
  version: string; uptime_s: number; dns: { listening: string[]; ok: boolean }; upstreams: Upstream[];
  database: { ok: boolean; ping_ms: number; size_bytes: number; error?: string };
  firewall: { managed: boolean; applied: boolean; rules: number; error?: string };
  license: { mode: LicenseState["mode"]; days_left: number; message: string };
  anycast: { enabled: boolean; monitor_only: boolean; interface: string; link_up: boolean; healthy: boolean; mode: string };
  protection?: { rate_limited: number; throttled: number; minimal_any: number; limited_clients: number; zones_under_attack: string[] };
  host: { cpus: number; load: number[]; mem_total: number; mem_available: number; disk: { total?: number; free?: number } };
};

const RANGES: [string, string, number][] = [["15m", "Last 15 min", 900], ["1h", "Last hour", 3600], ["24h", "Last 24 hours", 86400], ["7d", "7 days", 604800], ["30d", "30 days", 2592000]];
const nf = new Intl.NumberFormat("en-IN");
const num = (n: number) => nf.format(Math.round(n));
const pct = (part: number, whole: number, digits = 1) => (whole > 0 ? `${((part / whole) * 100).toFixed(digits)}%` : "—");
const bytes = (b: number) => (b >= 1 << 30 ? `${(b / (1 << 30)).toFixed(1)} GB` : `${(b / (1 << 20)).toFixed(0)} MB`);
const qpsFmt = (v: number) => (v >= 100 ? num(v) : v >= 10 ? v.toFixed(1) : v.toFixed(2));
const msFmt = (v: number) => `${v >= 100 ? Math.round(v) : v.toFixed(1)} ms`;
const allowed = (p: Point) => p.forwarded + p.cached + p.local;

// Outcome colours: the same entity has the same colour in every chart.
const OUTCOMES: { key: string; label: string; color: string; ink: string; value: (p: Point) => number }[] = [
  { key: "allowed", label: "Allowed", color: "var(--series-1)", ink: "#fff", value: allowed },
  { key: "blocked", label: "Blocked", color: "var(--series-2)", ink: "#fff", value: (p) => p.blocked },
  { key: "refused", label: "Refused", color: "var(--series-3)", ink: "#0b1220", value: (p) => p.refused },
  { key: "failed", label: "Failed", color: "var(--series-4)", ink: "#0b1220", value: (p) => p.failed },
];

const Icon = ({ d }: { d: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={d} /></svg>
);
const ICONS = {
  total: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
  qps: "M3 12h4l3-8 4 16 3-8h4",
  ok: "M12 3l8 3v6c0 5-3.4 8.3-8 9-4.6-.7-8-4-8-9V6l8-3zM8.5 12l2.5 2.5 4.5-5",
  blocked: "M12 3a9 9 0 100 18 9 9 0 000-18zM5.6 5.6l12.8 12.8",
  time: "M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l3 2",
  cache: "M4 7l8-4 8 4-8 4-8-4zM4 12l8 4 8-4M4 17l8 4 8-4",
};

// Delta vs the previous period; colour = direction × whether up is good.
function Delta({ cur, prev, upGood, points }: { cur: number; prev: number; upGood?: boolean; points?: boolean }) {
  if (!(prev > 0) && !points) return <span className="delta flat">no earlier data</span>;
  const d = points ? cur - prev : ((cur - prev) / prev) * 100;
  if (!isFinite(d)) return null;
  const flat = Math.abs(d) < (points ? 0.005 : 0.5);
  const cls = flat || upGood === undefined ? "flat" : (d > 0) === upGood ? "good" : "bad";
  return <span className={`delta ${cls}`}>{flat ? "→" : d > 0 ? "▲" : "▼"} {Math.abs(d).toFixed(points ? 2 : 1)}{points ? " pts" : "%"} <span style={{ fontWeight: 400, color: "var(--muted)" }}>vs prev.</span></span>;
}

function Kpi({ icon, label, value, sub }: { icon: string; label: string; value: ReactNode; sub: ReactNode }) {
  return (
    <div className="kpi">
      <div className="icon"><Icon d={icon} /></div>
      <div style={{ minWidth: 0 }}>
        <div className="label">{label}</div>
        <div className="value">{value}</div>
        <div className="sub">{sub}</div>
      </div>
    </div>
  );
}

function Ranked({ items, empty, link, fmt = num }: { items: Item[]; empty: string; link?: (k: string) => string; fmt?: (n: number) => string }) {
  if (items.length === 0) return <p className="muted" style={{ margin: 0 }}>{empty}</p>;
  const max = items[0].count || 1;
  return (
    <ol className="rank">
      {items.map((it) => {
        const inner = (
          <>
            <span className="name" title={it.key}>{it.key}</span>
            <span className="count">{fmt(it.count)}</span>
            <span className="track"><span className="fill" style={{ width: `${Math.max(2, (it.count / max) * 100)}%`, display: "block" }} /></span>
          </>
        );
        return <li key={it.key}>{link ? <Link href={link(it.key)} className="rank-link" style={{ display: "contents" }}>{inner}</Link> : inner}</li>;
      })}
    </ol>
  );
}

function SegmentedBar({ totals }: { totals: Point }) {
  const whole = OUTCOMES.reduce((a, o) => a + o.value(totals), 0);
  if (whole === 0) return <p className="muted">No queries in this period.</p>;
  return (
    <>
      <div className="segbar" role="img" aria-label={OUTCOMES.map((o) => `${o.label} ${num(o.value(totals))} (${pct(o.value(totals), whole)})`).join(", ")}>
        {OUTCOMES.map((o) => {
          const v = o.value(totals);
          if (v === 0) return null;
          const share = v / whole;
          return (
            <div key={o.key} className="seg" tabIndex={0} title={`${o.label}: ${num(v)} (${pct(v, whole)})`}
              style={{ flexGrow: share, flexBasis: 0, background: o.color, color: o.ink }}>
              {share >= 0.12 ? pct(v, whole, 0) : ""}
            </div>
          );
        })}
      </div>
      <div className="legend-list">
        {OUTCOMES.map((o) => (
          <div key={o.key} className="li">
            <span className="sw" style={{ background: o.color }} />
            <span>{o.label}</span>
            <span className="num">{num(o.value(totals))}</span>
            <span className="pct">{pct(o.value(totals), whole, 2)}</span>
          </div>
        ))}
      </div>
      <p className="muted" style={{ fontSize: 12, margin: "12px 0 0" }}>
        Of the allowed answers, {pct(totals.nxdomain, allowed(totals), 2)} were NXDOMAIN (name does not exist).
      </p>
    </>
  );
}

type Level = "good" | "warning" | "critical" | "off";
const ST_ICON: Record<Level, string> = { good: "M5 12l4 4 10-10", warning: "M12 8v5M12 17h.01", critical: "M6 6l12 12M18 6L6 18", off: "M5 12h14" };
function Status({ level, text }: { level: Level; text: string }) {
  return <span className={`st ${level}`}><Icon d={ST_ICON[level]} />{text}</span>;
}

function protectionRow(h: Health): { name: string; level: Level; text: string; detail: string } {
  const p = h.protection;
  if (!p) return { name: "Attack protection", level: "off", text: "Unknown", detail: "" };
  const zones = p.zones_under_attack;
  const detail = `${p.rate_limited.toLocaleString("en-IN")} dropped · ${p.throttled.toLocaleString("en-IN")} attack lookups refused`;
  if (zones.length) return { name: "Attack protection", level: "critical", text: `${zones.length} domain${zones.length > 1 ? "s" : ""} under attack`, detail: zones.join(", ") };
  if (p.limited_clients) return { name: "Attack protection", level: "warning", text: `${p.limited_clients} client${p.limited_clients > 1 ? "s" : ""} rate limited`, detail };
  return { name: "Attack protection", level: "good", text: "No attack", detail };
}

function SystemHealth({ h }: { h: Health }) {
  const ups = h.upstreams;
  const upOK = ups.filter((u) => u.healthy !== false).length;
  const memUsed = h.host.mem_total ? 1 - h.host.mem_available / h.host.mem_total : 0;
  const load = h.host.load?.[0] ?? 0;
  const lic = h.license;
  const licLevel: Level = lic.mode === "licensed" ? (lic.days_left <= 14 ? "warning" : "good") : lic.mode === "trial" ? "warning" : "critical";
  const rows: { name: string; level: Level; text: string; detail: string }[] = [
    { name: "DNS server", level: h.dns.ok ? "good" : "critical", text: h.dns.ok ? "Running" : "Not listening", detail: h.dns.listening.join(", ") },
    { name: "Upstream resolvers", level: upOK === ups.length ? "good" : upOK === 0 ? "critical" : "warning", text: `${upOK} / ${ups.length} answering`, detail: ups.map((u) => u.addr).join(", ") },
    { name: "Database (PostgreSQL)", level: h.database.ok ? "good" : "critical", text: h.database.ok ? "Running" : "Down", detail: h.database.ok ? `${h.database.ping_ms.toFixed(1)} ms ping · ${bytes(h.database.size_bytes)}` : h.database.error ?? "" },
    { name: "Firewall", level: !h.firewall.managed ? "off" : h.firewall.error ? "warning" : "good", text: !h.firewall.managed ? "Not managed" : h.firewall.applied ? "Applied" : "Not applied", detail: h.firewall.error || `${h.firewall.rules} rule(s)` },
    { name: "Anycast", level: !h.anycast.enabled ? "off" : !h.anycast.healthy ? "warning" : "good", text: !h.anycast.enabled ? "Off" : h.anycast.link_up ? "Announced" : "Withdrawn", detail: h.anycast.enabled ? `${h.anycast.interface} · ${h.anycast.monitor_only ? "monitor only" : h.anycast.mode}` : "Health control disabled" },
    protectionRow(h),
    { name: "License", level: licLevel, text: MODE_LABEL[lic.mode][0], detail: lic.message },
    { name: "Server load", level: load > h.host.cpus * 1.5 ? "warning" : "good", text: `${load.toFixed(2)} / ${h.host.cpus} CPU`, detail: `Memory ${pct(memUsed, 1, 0)} used${h.host.disk.free != null ? ` · disk ${bytes(h.host.disk.free)} free` : ""}` },
  ];
  return (
    <ul className="health">
      {rows.map((r) => (
        <li key={r.name}><span>{r.name}</span><Status level={r.level} text={r.text} /><span className="detail" title={r.detail}>{r.detail}</span></li>
      ))}
    </ul>
  );
}

export default function Dashboard() {
  const [range, setRange] = useState("1h");
  const [auto, setAuto] = useState(true);
  const [ts, setTs] = useState<TS | null>(null);
  const [top, setTop] = useState<Top | null>(null);
  const [bd, setBd] = useState<Breakdown | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [lic, setLic] = useState<LicenseState | null>(null);
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    const qlog = (e: ApiError) => setNote(e.code === "license_required" ? "Top lists, query types and categories need the query log, which is not licensed." : e.message);
    Promise.allSettled([
      get<TS>(`/dns/timeseries?range=${range}`).then(setTs),
      get<Top>(`/dns/top?range=${range}`).then((t) => { setTop(t); setNote(""); }, qlog),
      get<Breakdown>(`/dns/breakdown?range=${range}`).then(setBd, () => setBd(null)),
      get<Health>("/system/health").then(setHealth),
      get<{ license: LicenseState }>("/status").then((s) => setLic(s.license)),
    ]).then((res) => {
      const failed = res.find((r) => r.status === "rejected" && !(r.reason instanceof ApiError && r.reason.code === "license_required"));
      setErr(failed && failed.status === "rejected" ? String(failed.reason?.message ?? failed.reason) : "");
      setLoading(false);
    });
  }, [range]);

  useEffect(() => {
    load();
    if (!auto) return;
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load, auto]);

  const t = ts?.totals, prev = ts?.previous;
  const rangeLabel = RANGES.find((r) => r[0] === range)?.[1] ?? "";
  const qpsSeries: Series<Point>[] = OUTCOMES.map((o) => ({ key: o.key, label: o.label, color: o.color, value: (p: Point) => o.value(p) / (ts?.bucket_seconds || 60) }));
  const latSeries: Series<Point>[] = [{ key: "lat", label: "Upstream response time", color: "var(--series-5)", value: (p) => p.avg_ms }];
  const success = (p?: Point) => (p && p.total > 0 ? ((p.total - p.failed) / p.total) * 100 : 0);
  const cacheRate = (p?: Point) => (p && p.total > 0 ? (p.cached / p.total) * 100 : 0);

  return (
    <Shell>
      <div className="dash-head">
        <div>
          <h1>DNS overview</h1>
          <div className="subtitle">Live DNS traffic, performance and health of this server</div>
        </div>
        <div className="dash-controls">
          <div className="ranges" role="group" aria-label="Time range">
            {RANGES.map(([k, l]) => <button key={k} type="button" className={range === k ? "on" : ""} aria-pressed={range === k} onClick={() => setRange(k)}>{l}</button>)}
          </div>
          <label className="switch"><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />Auto refresh (30s)</label>
        </div>
      </div>
      <Alert kind="error">{err}</Alert>
      {lic && lic.mode !== "licensed" && (
        <div className={`alert ${MODE_LABEL[lic.mode][1] === "warn" ? "warn" : "error"}`}><strong>{MODE_LABEL[lic.mode][0]}.</strong> {lic.message} <Link href="/license">Manage license</Link></div>
      )}
      {lic && lic.tamper_events.length > 0 && <Alert kind="warn">Tampering with the license state or the clock was detected. See the License page.</Alert>}

      {t && prev && (
        <div className="kpis6">
          <Kpi icon={ICONS.total} label="Total queries" value={num(t.total)} sub={<Delta cur={t.total} prev={prev.total} />} />
          <Kpi icon={ICONS.qps} label="Queries per second" value={qpsFmt(ts!.qps.current)} sub={<span title="Highest one-minute average in this period">Peak {qpsFmt(ts!.qps.peak)}</span>} />
          <Kpi icon={ICONS.ok} label="Success rate" value={t.total ? `${success(t).toFixed(2)}%` : "—"} sub={t.total && prev.total ? <Delta cur={success(t)} prev={success(prev)} upGood points /> : <span className="delta flat">no earlier data</span>} />
          <Kpi icon={ICONS.blocked} label="Blocked queries" value={num(t.blocked)} sub={`${pct(t.blocked, t.total, 2)} of total`} />
          <Kpi icon={ICONS.time} label="Avg response time" value={t.avg_ms != null ? msFmt(t.avg_ms) : "—"} sub={t.avg_ms != null && prev.avg_ms != null ? <Delta cur={t.avg_ms} prev={prev.avg_ms} upGood={false} /> : "upstream resolvers"} />
          <Kpi icon={ICONS.cache} label="Cache hit rate" value={t.total ? pct(t.cached, t.total) : "—"} sub={t.total && prev.total ? <Delta cur={cacheRate(t)} prev={cacheRate(prev)} upGood points /> : <span className="delta flat">no earlier data</span>} />
        </div>
      )}

      <div className="dgrid r2">
        <div className="panel">
          <div className="panel-head"><h2>Query rate (QPS)</h2><span className="muted">{rangeLabel} · {tzName()}</span></div>
          {ts ? <LineChart points={ts.points} series={qpsSeries} bucketSeconds={ts.bucket_seconds} fmt={qpsFmt} label="Queries per second by result" loading={loading} /> : <p className="muted">Loading…</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Result distribution</h2></div>
          {t ? <SegmentedBar totals={t} /> : <p className="muted">Loading…</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Top queried domains</h2><Link href="/querylog">Query log ›</Link></div>
          {top ? <Ranked items={top.domains.slice(0, 8)} empty="No queries in this period." link={(k) => `/querylog?q=${encodeURIComponent(k)}`} /> : <p className="muted" style={{ margin: 0 }}>{note || "Loading…"}</p>}
        </div>
      </div>

      <div className="dgrid r3">
        <div className="panel">
          <div className="panel-head"><h2>Response time</h2>{t?.avg_ms != null && <span className="muted">avg {msFmt(t.avg_ms)}</span>}</div>
          {ts ? <LineChart points={ts.points} series={latSeries} bucketSeconds={ts.bucket_seconds} fmt={msFmt} area height={200} label="Average upstream response time" loading={loading} /> : <p className="muted">Loading…</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Query types</h2></div>
          {bd ? <Ranked items={bd.query_types.slice(0, 7)} empty="No queries in this period." /> : <p className="muted" style={{ margin: 0 }}>{note || "Loading…"}</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Blocked by category</h2><Link href="/querylog?action=blocked">Blocked ›</Link></div>
          {bd ? <Ranked items={bd.block_categories.slice(0, 7)} empty="Nothing blocked in this period." /> : <p className="muted" style={{ margin: 0 }}>{note || "Loading…"}</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>System health</h2>{health && <span className="muted">v{health.version}</span>}</div>
          {health ? <SystemHealth h={health} /> : <p className="muted">Loading…</p>}
        </div>
      </div>

      <div className="dgrid r4">
        <div className="panel">
          <div className="panel-head"><h2>Top blocked domains</h2><Link href="/querylog?action=blocked">All blocked ›</Link></div>
          {top ? <Ranked items={top.blocked_domains} empty="Nothing blocked in this period." link={(k) => `/querylog?action=blocked&q=${encodeURIComponent(k)}`} /> : <p className="muted" style={{ margin: 0 }}>{note || "Loading…"}</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Top clients</h2></div>
          {top ? <Ranked items={top.clients} empty="No queries in this period." link={(k) => `/querylog?q=${encodeURIComponent(k)}`} /> : <p className="muted" style={{ margin: 0 }}>{note || "Loading…"}</p>}
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Upstream resolvers</h2><Link href="/settings">Settings ›</Link></div>
          {health ? (
            <div className="table-wrap">
              <table className="compact">
                <thead><tr><th>Resolver</th><th>Status</th><th style={{ textAlign: "right" }}>Avg</th><th style={{ textAlign: "right" }}>Failures</th></tr></thead>
                <tbody>
                  {health.upstreams.map((u) => (
                    <tr key={u.addr} title={u.last_error ?? ""}>
                      <td className="mono nowrap">{u.addr}</td>
                      <td className="nowrap" title={u.healthy == null ? "No queries yet" : u.healthy ? "Answering" : "Failing"}>{u.healthy == null ? <Status level="off" text="Idle" /> : u.healthy ? <Status level="good" text="OK" /> : <Status level="critical" text="Down" />}</td>
                      <td className="num nowrap" style={{ textAlign: "right" }}>{u.avg_ms ? msFmt(u.avg_ms) : "—"}</td>
                      <td className="num nowrap" style={{ textAlign: "right" }} title={`${num(u.failures)} failed of ${num(u.queries)} queries`}>{num(u.failures)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>Counted since the service started ({Math.floor(health.uptime_s / 3600)} h ago).</p>
            </div>
          ) : <p className="muted">Loading…</p>}
        </div>
      </div>
    </Shell>
  );
}
