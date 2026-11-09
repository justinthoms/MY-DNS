"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, get, fmtDate } from "@/lib/api";
import { LicenseState, MODE_LABEL } from "@/lib/license";
import { Alert, Shell, useLoad } from "@/components/ui";
import QueryChart, { Point } from "@/components/QueryChart";

type Status = {
  version: string;
  license: LicenseState;
  dns: { filtering_active: boolean; query_log_active: boolean; blocklist_entries: number; allowlist_entries: number; listen: string[] };
  firewall: { state: { applied: boolean; rules: number; error?: string }; enabled_rules: number; managed: boolean };
};
type Series = { range: string; bucket_seconds: number; points: Point[]; totals: Point };
type TopItem = { key: string; count: number; blocked?: number };
type Top = { blocked_domains: TopItem[]; domains: TopItem[]; clients: TopItem[] };

const RANGES: [string, string][] = [["1h", "1 hour"], ["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]];
const domains = (n: number) => `${n.toLocaleString()} ${n === 1 ? "domain" : "domains"}`;
const pct = (part: number, whole: number) => (whole > 0 ? `${((part / whole) * 100).toFixed(1)}% of queries` : "—");

function Ranked({ items, empty, link }: { items: TopItem[]; empty: string; link: (key: string) => string }) {
  if (items.length === 0) return <p className="muted" style={{ margin: 0 }}>{empty}</p>;
  const max = items[0].count;
  return (
    <ol className="rank">
      {items.map((it) => (
        <li key={it.key}>
          <Link href={link(it.key)} className="rank-link" style={{ display: "contents" }}>
            <span className="name" title={`Show queries for ${it.key}`}>{it.key}</span>
            <span className="count">{it.count.toLocaleString()}</span>
            <span className="track"><span className="fill" style={{ width: `${Math.max(2, (it.count / max) * 100)}%`, display: "block" }} /></span>
          </Link>
        </li>
      ))}
    </ol>
  );
}

export default function Dashboard() {
  const { data, error } = useLoad<Status>("/status");
  const [range, setRange] = useState("24h");
  const [series, setSeries] = useState<Series | null>(null);
  const [top, setTop] = useState<Top | null>(null);
  const [topNote, setTopNote] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let live = true;
    const load = () => {
      setLoading(true);
      get<Series>(`/dns/timeseries?range=${range}`).then((s) => live && setSeries(s)).catch(() => {}).finally(() => live && setLoading(false));
      get<Top>(`/dns/top?range=${range}`)
        .then((t) => { if (live) { setTop(t); setTopNote(""); } })
        .catch((e: ApiError) => { if (live) { setTop(null); setTopNote(e.code === "license_required" ? "Top lists need the query log, which is not licensed." : e.message); } });
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { live = false; clearInterval(id); };
  }, [range]);

  const lic = data?.license;
  const [label, tone] = lic ? MODE_LABEL[lic.mode] : ["", "ok"];
  const t = series?.totals;
  return (
    <Shell>
      <div className="toprow">
        <h1>Dashboard</h1>
        <div className="ranges" role="group" aria-label="Time range">
          {RANGES.map(([k, l]) => (
            <button key={k} type="button" className={range === k ? "on" : ""} aria-pressed={range === k} onClick={() => setRange(k)}>{l}</button>
          ))}
        </div>
      </div>
      <Alert kind="error">{error}</Alert>
      {lic && (
        <div className={`alert ${tone === "ok" ? "success" : tone === "warn" ? "warn" : "error"}`}>
          <strong>{label}.</strong> {lic.message} {lic.mode !== "licensed" && <Link href="/license">Manage license</Link>}
        </div>
      )}
      {lic && lic.tamper_events.length > 0 && (
        <Alert kind="warn">Tampering with the license state or the clock was detected ({lic.tamper_events.length} event{lic.tamper_events.length > 1 ? "s" : ""}). See the License page.</Alert>
      )}

      {t && (
        <div className="grid kpis">
          <div className="stat"><div className="label">Queries</div><div className="value">{t.total.toLocaleString()}</div><div className="sub">last {RANGES.find((r) => r[0] === range)?.[1]}</div></div>
          <div className="stat"><div className="label">Blocked</div><div className="value">{t.blocked.toLocaleString()}</div><div className="sub">{pct(t.blocked, t.total)}</div></div>
          <div className="stat"><div className="label">Refused</div><div className="value">{t.refused.toLocaleString()}</div><div className="sub">clients not allowed</div></div>
          <div className="stat"><div className="label">Failed</div><div className="value">{t.failed.toLocaleString()}</div><div className="sub">no upstream answer</div></div>
          <div className="stat"><div className="label">From cache</div><div className="value">{t.cached.toLocaleString()}</div><div className="sub">{pct(t.cached, t.total)}</div></div>
          <div className="stat"><div className="label">Local records</div><div className="value">{t.local.toLocaleString()}</div><div className="sub">answered locally</div></div>
        </div>
      )}

      <div className="dash-grid">
        <div className="panel" style={{ marginBottom: 0 }}>
          <h2>Queries over time <span className="muted" style={{ fontWeight: 400, fontSize: 13 }}>(UTC)</span></h2>
          {series ? <QueryChart points={series.points} bucketSeconds={series.bucket_seconds} loading={loading} /> : <p className="muted">Loading…</p>}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div className="panel" style={{ marginBottom: 0 }}>
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <h2 style={{ margin: 0 }}>Top blocked domains</h2>
              <Link href="/querylog?action=blocked" style={{ fontSize: 13 }}>All blocked queries ›</Link>
            </div>
            {top ? <Ranked items={top.blocked_domains} empty="Nothing blocked in this period." link={(k) => `/querylog?action=blocked&q=${encodeURIComponent(k)}`} /> : <p className="muted" style={{ margin: 0 }}>{topNote || "Loading…"}</p>}
          </div>
          <div className="panel" style={{ marginBottom: 0 }}>
            <h2>Top clients</h2>
            {top ? <Ranked items={top.clients} empty="No queries in this period." link={(k) => `/querylog?q=${encodeURIComponent(k)}`} /> : <p className="muted" style={{ margin: 0 }}>{topNote || "Loading…"}</p>}
          </div>
        </div>
      </div>

      {data && lic && (
        <div className="grid" style={{ marginTop: 18 }}>
          <div className="panel" style={{ margin: 0 }}>
            <h2>DNS</h2>
            <dl className="kv">
              <dt>Filtering</dt><dd>{data.dns.filtering_active ? <span className="badge ok">active</span> : <span className="badge bad">off</span>}</dd>
              <dt>Block list</dt><dd>{domains(data.dns.blocklist_entries)}</dd>
              <dt>Allow list</dt><dd>{domains(data.dns.allowlist_entries)}</dd>
              <dt>Query log</dt><dd>{data.dns.query_log_active ? "on" : "off"}</dd>
              <dt>Listening</dt><dd className="mono">{data.dns.listen.join(", ")}</dd>
            </dl>
          </div>
          <div className="panel" style={{ margin: 0 }}>
            <h2>Firewall</h2>
            <dl className="kv">
              <dt>State</dt>
              <dd>{!data.firewall.managed ? <span className="badge muted">not managed</span> : data.firewall.state.applied ? <span className="badge ok">applied</span> : <span className="badge warn">not applied</span>}</dd>
              <dt>Enabled rules</dt><dd>{data.firewall.enabled_rules}</dd>
              {data.firewall.state.error && data.firewall.managed && <><dt>Last error</dt><dd className="muted">{data.firewall.state.error}</dd></>}
            </dl>
          </div>
          <div className="panel" style={{ margin: 0 }}>
            <h2>License</h2>
            <dl className="kv">
              <dt>Status</dt><dd>{label}</dd>
              {lic.customer && <><dt>Customer</dt><dd>{lic.customer}</dd></>}
              <dt>{lic.mode === "trial" ? "Trial ends" : "Expires"}</dt><dd>{fmtDate(lic.mode === "trial" ? lic.trial_ends_at : lic.expires_at)}</dd>
              <dt>Version</dt><dd>{data.version}</dd>
            </dl>
          </div>
        </div>
      )}
    </Shell>
  );
}
