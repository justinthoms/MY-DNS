"use client";

import { useEffect, useState } from "react";
import { get, put, fmtTime } from "@/lib/api";
import { Alert, Shell, useAction } from "@/components/ui";

type Cfg = { enabled: boolean; interface: string; monitor_only: boolean; interval_sec: number; fail_threshold: number; rise_threshold: number; mode: "auto" | "withdraw" | "announce"; check_name: string };
type Status = Cfg & { link_up: boolean; healthy: boolean; consecutive_fail: number; consecutive_ok: number; last_check: string; last_error: string; would_withdraw: boolean; events: { at: string; kind: string; message: string }[] };
type Iface = { name: string; up: boolean; loopback: boolean; addrs: string[]; default_route: boolean; internal: boolean };
type Resp = { settings: Cfg; status: Status; interfaces: Iface[] };

const MODES: [Cfg["mode"], string, string][] = [
  ["auto", "Auto", "Withdraw when DNS fails, announce when it recovers"],
  ["withdraw", "Maintenance (withdraw)", "Keep routes withdrawn, e.g. while you work on this server"],
  ["announce", "Force announce", "Keep routes announced whatever the health checks say"],
];
const kindTone = (k: string) => (k === "withdrawn" || k === "error" ? "bad" : k === "check_failed" ? "warn" : k === "announced" || k === "recovered" ? "ok" : "muted");

export default function AnycastPage() {
  const [data, setData] = useState<Resp | null>(null);
  const [f, setF] = useState<Cfg | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const act = useAction();
  const load = () => get<Resp>("/anycast").then((d) => { setData(d); setF((cur) => cur ?? d.settings); setLoadErr(""); }).catch((e) => setLoadErr(e.message));
  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id); }, []);

  const save = (next: Cfg, msg: string) => act.run(async () => { const r = await put<Resp>("/anycast", next); setF(r.settings); load(); }, msg);
  if (!data || !f) return <Shell><h1>Anycast</h1><Alert kind="error">{loadErr}</Alert></Shell>;
  const st = data.status;
  const candidates = data.interfaces.filter((i) => !i.loopback && !i.internal);

  return (
    <Shell>
      <h1>Anycast</h1>
      <Alert kind="error">{act.error || loadErr}</Alert>
      <Alert kind="success">{act.ok}</Alert>

      <div className="grid">
        <div className="stat"><div className="label">Routes</div><div className="value" style={{ fontSize: 20 }}>
          {st.enabled ? (st.link_up ? <span className="badge ok">announced</span> : <span className="badge bad">withdrawn</span>) : <span className="badge muted">not controlled</span>}
        </div><div className="sub">{st.interface || "—"} is {st.link_up ? "up" : "down"}</div></div>
        <div className="stat"><div className="label">DNS health</div><div className="value" style={{ fontSize: 20 }}>
          {!st.enabled ? <span className="badge muted">not checked</span> : st.healthy ? <span className="badge ok">healthy</span> : st.consecutive_fail > 0 ? <span className="badge bad">failing</span> : <span className="badge warn">starting</span>}
        </div><div className="sub">{st.last_check && !st.last_check.startsWith("0001") ? `checked ${fmtTime(st.last_check)}` : "no check yet"}</div></div>
        <div className="stat"><div className="label">Failures in a row</div><div className="value">{st.consecutive_fail}</div><div className="sub">withdraw at {st.fail_threshold}</div></div>
        <div className="stat"><div className="label">Successes in a row</div><div className="value">{st.consecutive_ok}</div><div className="sub">announce at {st.rise_threshold}</div></div>
      </div>
      {st.last_error && <Alert kind="warn">Last check failed: {st.last_error}</Alert>}
      {st.enabled && st.monitor_only && (
        <Alert kind="warn">Monitor only: the interface is never changed. {st.would_withdraw ? "In Auto mode the routes would be withdrawn now." : "In Auto mode nothing would change now."}</Alert>
      )}

      <div className="panel">
        <h2>Mode</h2>
        <div className="actions">
          {MODES.map(([m, label, hint]) => (
            <button key={m} type="button" className={f.mode === m ? "" : "secondary"} title={hint} disabled={act.busy || !f.enabled}
              onClick={() => (m === "withdraw" && !f.monitor_only && !confirm(`Withdraw the anycast routes of ${f.interface}? Traffic moves to your other anycast servers.`)) ? null : save({ ...f, mode: m }, `Mode set to ${label}.`)}>
              {label}
            </button>
          ))}
        </div>
        <p className="muted" style={{ marginBottom: 0 }}>{MODES.find((x) => x[0] === f.mode)?.[2]}</p>
      </div>

      <div className="panel">
        <h2>Health-based route control</h2>
        <p className="muted">
          Put this server&apos;s anycast addresses on a dedicated interface (for example a dummy interface <code>anycast0</code>) and let FRR announce
          that interface&apos;s addresses with iBGP, OSPF or IS-IS. When DNS fails the health check several times in a row, ISP NetControl sets the
          interface <strong>down</strong>, so FRR withdraws the routes and traffic moves to your other anycast servers. It sets it <strong>up</strong> again
          after DNS recovers. The interface carrying the default route cannot be used. See <code>docs/ANYCAST.md</code> for FRR examples.
        </p>
        <div className="stack" style={{ maxWidth: 640 }}>
          <label className="check"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Enable health checks for anycast</label>
          <label className="check"><input type="checkbox" checked={f.monitor_only} onChange={(e) => setF({ ...f, monitor_only: e.target.checked })} />Monitor only (recommended first: report what would happen, never change the interface)</label>
          <div className="row">
            <label>Anycast interface
              <select value={f.interface} onChange={(e) => setF({ ...f, interface: e.target.value })}>
                {!candidates.some((i) => i.name === f.interface) && <option value={f.interface}>{f.interface}</option>}
                {candidates.map((i) => <option key={i.name} value={i.name} disabled={i.default_route}>{i.name}{i.default_route ? " (default route)" : ""} {i.addrs.filter((a) => !a.startsWith("fe80")).join(", ")}</option>)}
              </select>
            </label>
            <label style={{ flex: 1, minWidth: 180 }}>Health-check name<input value={f.check_name} onChange={(e) => setF({ ...f, check_name: e.target.value })} /></label>
          </div>
          <div className="row">
            <label style={{ width: 150 }}>Check every (s)<input type="number" min={2} max={60} value={f.interval_sec} onChange={(e) => setF({ ...f, interval_sec: Number(e.target.value) })} /></label>
            <label style={{ width: 170 }}>Withdraw after failures<input type="number" min={1} max={20} value={f.fail_threshold} onChange={(e) => setF({ ...f, fail_threshold: Number(e.target.value) })} /></label>
            <label style={{ width: 170 }}>Announce after successes<input type="number" min={1} max={20} value={f.rise_threshold} onChange={(e) => setF({ ...f, rise_threshold: Number(e.target.value) })} /></label>
          </div>
          <div><button type="button" disabled={act.busy} onClick={() => save(f, "Anycast settings saved.")}>Save</button></div>
        </div>
      </div>

      <div className="panel table-wrap">
        <h2>Recent events</h2>
        {!st.events?.length ? <p className="muted">None yet.</p> : (
          <table>
            <thead><tr><th>Time</th><th>Event</th><th>Details</th></tr></thead>
            <tbody>
              {[...(st.events ?? [])].reverse().map((e, i) => (
                <tr key={i}><td style={{ whiteSpace: "nowrap" }}>{fmtTime(e.at)}</td><td><span className={`badge ${kindTone(e.kind)}`}>{e.kind.replace("_", " ")}</span></td><td>{e.message}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  );
}
