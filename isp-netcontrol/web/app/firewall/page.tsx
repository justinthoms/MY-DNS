"use client";

import { FormEvent, useState } from "react";
import { del, post, put, fmtDate } from "@/lib/api";
import { Alert, LicenseRequired, Shell, useAction, useLoad } from "@/components/ui";

type Rule = { id: number; cidr: string; direction: string; note: string; enabled: boolean; created_at: string };
type Status = { state: { applied: boolean; rules: number; error?: string; updated_at: string }; ruleset: string; table: string; error?: string };

const DIRS: Record<string, string> = { both: "From and to", src: "From (source)", dst: "To (destination)" };

export default function FirewallPage() {
  const rules = useLoad<Rule[]>("/firewall/rules");
  const status = useLoad<Status>("/firewall/status");
  const act = useAction();
  const [cidr, setCidr] = useState("");
  const [direction, setDirection] = useState("both");
  const [note, setNote] = useState("");
  const reload = () => { rules.reload(); status.reload(); };
  const run = async (fn: () => Promise<any>, msg: string) => {
    let res: any = null;
    const ok = await act.run(async () => { res = await fn(); });
    if (ok && res?.apply_error) act.setError(`Saved, but applying to nftables failed: ${res.apply_error}`);
    else if (ok) await act.run(async () => {}, msg);
    reload();
    return ok;
  };
  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (await run(() => post("/firewall/rules", { cidr, direction, note }), `${cidr} blocked.`)) { setCidr(""); setNote(""); }
  };
  if (rules.licenseError) return <Shell><h1>Firewall</h1><LicenseRequired message={rules.licenseError} /></Shell>;
  return (
    <Shell>
      <h1>Firewall</h1>
      <Alert kind="error">{rules.error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <div className="panel">
        <h2>Block a network</h2>
        <p className="muted">Rules live in a dedicated nftables table (<code>inet isp_netcontrol</code>). ISP NetControl never changes any other table, so your existing firewall stays as it is.</p>
        <form className="row" onSubmit={add}>
          <label style={{ flex: 2, minWidth: 180 }}>IP address or CIDR<input required placeholder="203.0.113.0/24" value={cidr} onChange={(e) => setCidr(e.target.value)} /></label>
          <label>Traffic
            <select value={direction} onChange={(e) => setDirection(e.target.value)}>
              {Object.entries(DIRS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label style={{ flex: 2, minWidth: 160 }}>Note<input value={note} onChange={(e) => setNote(e.target.value)} /></label>
          <button disabled={act.busy}>Block</button>
        </form>
      </div>
      <div className="panel table-wrap">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
          <h2 style={{ margin: 0 }}>Rules</h2>
          <button className="secondary" disabled={act.busy} onClick={() => run(() => post("/firewall/apply"), "Rules applied.")}>Re-apply now</button>
        </div>
        <table>
          <thead><tr><th>Network</th><th>Traffic</th><th>Note</th><th>Added</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            {rules.data?.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.cidr}</td>
                <td>{DIRS[r.direction]}</td>
                <td className="muted">{r.note}</td>
                <td>{fmtDate(r.created_at)}</td>
                <td><input type="checkbox" aria-label={`Enable ${r.cidr}`} checked={r.enabled} onChange={(e) => run(() => put(`/firewall/rules/${r.id}`, { enabled: e.target.checked, note: r.note }), "Updated.")} /></td>
                <td><button className="secondary" onClick={() => confirm(`Delete the rule for ${r.cidr}?`) && run(() => del(`/firewall/rules/${r.id}`), "Rule deleted.")}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rules.data?.length === 0 && <p className="muted">No rules yet.</p>}
      </div>
      <div className="panel">
        <h2>Applied ruleset</h2>
        {status.data?.state.error && <Alert kind="warn">{status.data.state.error}</Alert>}
        <pre className="block">{status.data?.ruleset || "(table not present)"}</pre>
      </div>
    </Shell>
  );
}
