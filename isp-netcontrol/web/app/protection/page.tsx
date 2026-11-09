"use client";

import { FormEvent, useEffect, useState } from "react";
import { fmtTime, get, put } from "@/lib/api";
import { Alert, Shell, useAction, useLoad } from "@/components/ui";

type Settings = {
  rate_limit_enabled: boolean; rate_limit: number; burst: number; exempt: string[]; minimal_any: boolean;
  torture_enabled: boolean; torture_threshold: number; torture_limit: number; torture_hold_minutes: number;
};
type Zone = { zone: string; since: string; until: string; peak_nxdomain_per_minute: number; throttled: number };
type Client = { client: string; dropped: number; last_drop: string };
type Status = { rate_limited: number; throttled: number; minimal_any: number; limited_clients: Client[]; zones: Zone[] };
type Data = { settings: Settings; status: Status };

const lines = (s: string) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
const n = (v: number) => v.toLocaleString("en-IN");
// Attacks last minutes: the time of day is enough (hover shows the full date).
const hms = (s: string) => new Date(s).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

export default function ProtectionPage() {
  const { data, error, reload } = useLoad<Data>("/dns/protection");
  const act = useAction();
  const [f, setF] = useState<Settings | null>(null);
  const [exempt, setExempt] = useState("");
  const [status, setStatus] = useState<Status | null>(null);
  useEffect(() => {
    if (data) { setF(data.settings); setExempt(data.settings.exempt.join("\n")); setStatus(data.status); }
  }, [data]);
  // The live status refreshes every 10 seconds without touching the form.
  useEffect(() => {
    const id = setInterval(() => get<Data>("/dns/protection").then((d) => setStatus(d.status)).catch(() => {}), 10000);
    return () => clearInterval(id);
  }, []);
  const num = (k: keyof Settings) => (e: React.ChangeEvent<HTMLInputElement>) => f && setF({ ...f, [k]: Number(e.target.value) });
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!f) return;
    if (await act.run(() => put("/dns/protection", { ...f, exempt: lines(exempt) }), "Saved. The new limits apply immediately.")) reload();
  };

  return (
    <Shell>
      <h1>Attack protection</h1>
      <p className="muted">Defences against floods, amplification and random-subdomain (&ldquo;water torture&rdquo;) attacks. They work in every license state.</p>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>

      {status && (
        <>
          <div className="kpis6" style={{ marginBottom: 6 }}>
            <div className="kpi"><div><div className="label">Domains under attack</div><div className="value" style={{ color: status.zones.length ? "var(--bad)" : undefined }}>{status.zones.length}</div></div></div>
            <div className="kpi"><div><div className="label">Clients rate limited (15 min)</div><div className="value" style={{ color: status.limited_clients.length ? "var(--warn)" : undefined }}>{status.limited_clients.length}</div></div></div>
            <div className="kpi"><div><div className="label">Queries dropped</div><div className="value">{n(status.rate_limited)}</div></div></div>
            <div className="kpi"><div><div className="label">Attack lookups refused</div><div className="value">{n(status.throttled)}</div></div></div>
            <div className="kpi"><div><div className="label">ANY queries minimised</div><div className="value">{n(status.minimal_any)}</div></div></div>
          </div>
          <p className="muted" style={{ fontSize: 12 }}>Counted since the service started. Refreshes every 10 seconds.</p>

          <div className="dgrid r2b">
            <div className="panel">
              <h2>Domains under attack</h2>
              {status.zones.length === 0 ? <p className="muted">None. A domain appears here when it causes an unusual number of NXDOMAIN answers.</p> : (
                <div className="table-wrap"><table>
                  <thead><tr><th>Domain</th><th>Since</th><th>Until</th><th style={{ textAlign: "right" }} className="num">Peak NX/min</th><th style={{ textAlign: "right" }} className="num">Refused</th></tr></thead>
                  <tbody>{status.zones.map((z) => (
                    <tr key={z.zone}><td className="mono" style={{ whiteSpace: "nowrap" }}>{z.zone}</td><td style={{ whiteSpace: "nowrap" }} title={fmtTime(z.since)}>{hms(z.since)}</td><td style={{ whiteSpace: "nowrap" }} title={fmtTime(z.until)}>{hms(z.until)}</td><td style={{ textAlign: "right" }} className="num">{n(z.peak_nxdomain_per_minute)}</td><td style={{ textAlign: "right" }} className="num">{n(z.throttled)}</td></tr>
                  ))}</tbody>
                </table></div>
              )}
            </div>
            <div className="panel">
              <h2>Rate-limited clients</h2>
              {status.limited_clients.length === 0 ? <p className="muted">No client went over the limit in the last 15 minutes.</p> : (
                <div className="table-wrap"><table>
                  <thead><tr><th>Client</th><th style={{ textAlign: "right" }} className="num">Dropped</th><th>Last</th></tr></thead>
                  <tbody>{status.limited_clients.map((c) => (
                    <tr key={c.client}><td className="mono"><a href={`/querylog?q=${encodeURIComponent(c.client)}`}>{c.client}</a></td><td style={{ textAlign: "right" }} className="num">{n(c.dropped)}</td><td style={{ whiteSpace: "nowrap" }}>{fmtTime(c.last_drop)}</td></tr>
                  ))}</tbody>
                </table></div>
              )}
            </div>
          </div>
        </>
      )}

      {f && (
        <form className="panel stack" onSubmit={save} style={{ marginTop: 16 }}>
          <h2 style={{ margin: 0 }}>Rate limit per client</h2>
          <label className="check"><input type="checkbox" checked={f.rate_limit_enabled} onChange={(e) => setF({ ...f, rate_limit_enabled: e.target.checked })} />Limit how fast one address may query</label>
          {f.rate_limit_enabled && (
            <>
              <div className="row">
                <label>Queries per second<input type="number" min={10} value={f.rate_limit} onChange={num("rate_limit")} /></label>
                <label>Burst<input type="number" min={10} value={f.burst} onChange={num("burst")} /></label>
              </div>
              <p className="muted" style={{ margin: 0 }}>Queries over the limit get no answer over UDP (so the server cannot be used to flood a spoofed victim) and REFUSED over TCP. A normal home sends well under 50 queries per second.</p>
              <label>Never limit these addresses or networks (one per line)<textarea style={{ minHeight: 70 }} value={exempt} onChange={(e) => setExempt(e.target.value)} placeholder={"NAT gateways, other DNS servers forwarding here, monitoring\n100.64.0.1\n10.20.0.0/24"} /></label>
            </>
          )}

          <h2 style={{ margin: "8px 0 0" }}>Amplification</h2>
          <label className="check"><input type="checkbox" checked={f.minimal_any} onChange={(e) => setF({ ...f, minimal_any: e.target.checked })} />Answer ANY queries over UDP with a minimal record (RFC 8482)</label>

          <h2 style={{ margin: "8px 0 0" }}>Random-subdomain attacks</h2>
          <label className="check"><input type="checkbox" checked={f.torture_enabled} onChange={(e) => setF({ ...f, torture_enabled: e.target.checked })} />Detect and limit random-subdomain (&ldquo;water torture&rdquo;) attacks</label>
          {f.torture_enabled && (
            <>
              <div className="row">
                <label>Threshold (NXDOMAIN/min)<input type="number" min={50} value={f.torture_threshold} onChange={num("torture_threshold")} /></label>
                <label>Then allow (lookups/s)<input type="number" min={1} value={f.torture_limit} onChange={num("torture_limit")} /></label>
                <label>Hold (minutes)<input type="number" min={1} value={f.torture_hold_minutes} onChange={num("torture_hold_minutes")} /></label>
              </div>
              <p className="muted" style={{ margin: 0 }}>Infected devices query random names such as <span className="mono">x7f2k.example.com</span> to overload that domain&rsquo;s servers and yours. While a domain is suspected, names already in the cache keep working; new names under it are limited and the rest get SERVFAIL without querying the internet.</p>
            </>
          )}
          <div><button disabled={act.busy}>Save</button></div>
        </form>
      )}
    </Shell>
  );
}
