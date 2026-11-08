"use client";

import { useState } from "react";
import { fmtTime } from "@/lib/api";
import { Alert, LicenseRequired, Shell, useLoad } from "@/components/ui";

type Entry = { at: string; client: string; name: string; type: string; action: string };

export default function QueryLog() {
  const [q, setQ] = useState("");
  const [action, setAction] = useState("");
  const [applied, setApplied] = useState({ q: "", action: "" });
  const { data, error, licenseError, reload } = useLoad<Entry[]>(`/dns/querylog?limit=500&q=${encodeURIComponent(applied.q)}&action=${applied.action}`);
  const tone = (a: string) => (a === "blocked" ? "bad" : a === "refused" || a === "failed" ? "warn" : "muted");
  return (
    <Shell>
      <h1>Query log</h1>
      {licenseError ? <LicenseRequired message={licenseError} /> : (
        <div className="panel">
          <form className="row" style={{ marginBottom: 12 }} onSubmit={(e) => { e.preventDefault(); setApplied({ q, action }); }}>
            <label>Domain or client IP<input value={q} onChange={(e) => setQ(e.target.value)} /></label>
            <label>Result
              <select value={action} onChange={(e) => setAction(e.target.value)}>
                <option value="">All</option><option value="blocked">Blocked</option><option value="forwarded">Forwarded</option>
                <option value="cached">Cached</option><option value="refused">Refused</option><option value="failed">Failed</option>
              </select>
            </label>
            <button className="secondary">Filter</button>
            <button type="button" className="secondary" onClick={reload}>Refresh</button>
            <a className="button-link" style={{ marginLeft: "auto" }} href={`/api/dns/querylog/export?range=7d&q=${encodeURIComponent(applied.q)}&action=${applied.action}`} download>Export CSV (7 days)</a>
          </form>
          <Alert kind="error">{error}</Alert>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Client</th><th>Name</th><th>Type</th><th>Result</th></tr></thead>
              <tbody>
                {data?.map((e, i) => (
                  <tr key={i}>
                    <td style={{ whiteSpace: "nowrap" }}>{fmtTime(e.at)}</td>
                    <td className="mono">{e.client}</td>
                    <td className="mono">{e.name}</td>
                    <td>{e.type}</td>
                    <td><span className={`badge ${tone(e.action)}`}>{e.action}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data?.length === 0 && <p className="muted">No queries recorded.</p>}
          </div>
        </div>
      )}
    </Shell>
  );
}
