"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useEffect, useState } from "react";
import { put, fmtTime } from "@/lib/api";
import { Alert, LicenseRequired, Shell, useAction, useLoad } from "@/components/ui";

type Entry = { at: string; client: string; name: string; type: string; action: string };
type Page = { entries: Entry[]; total: number; page: number; pages: number; page_size: number; retention_hours: number; mode: "all" | "important" | "off"; sample: number; dropped: number };

const TABS: [string, string][] = [["", "All"], ["blocked", "Blocked"], ["refused", "Refused"], ["failed", "Failed"], ["local", "Local"], ["cached", "Cached"], ["forwarded", "Forwarded"], ["ratelimited", "Rate limited"], ["throttled", "Attack"]];
const RETENTION: [number, string][] = [[1, "1 hour"], [6, "6 hours"], [12, "12 hours"], [24, "24 hours"], [72, "3 days"], [168, "7 days"], [720, "30 days"]];
const tone = (a: string) => (a === "blocked" || a === "ratelimited" || a === "throttled" ? "bad" : a === "refused" || a === "failed" ? "warn" : a === "local" ? "ok" : "muted");

function pageList(page: number, pages: number): (number | "…")[] {
  const out: (number | "…")[] = [];
  for (let p = 1; p <= pages; p++) {
    if (p === 1 || p === pages || Math.abs(p - page) <= 2) out.push(p);
    else if (out[out.length - 1] !== "…") out.push("…");
  }
  return out;
}

function QueryLogInner() {
  const params = useSearchParams();
  const router = useRouter();
  const action = params.get("action") ?? "";
  const q = params.get("q") ?? "";
  const page = Number(params.get("page") ?? "1") || 1;
  const size = Number(params.get("size") ?? "50") || 50;
  const [search, setSearch] = useState(q);
  useEffect(() => setSearch(q), [q]);

  const path = `/dns/querylog?page=${page}&page_size=${size}&action=${action}&q=${encodeURIComponent(q)}`;
  const { data, error, licenseError, reload } = useLoad<Page>(path);
  const act = useAction();

  const go = (next: Partial<{ action: string; q: string; page: number; size: number }>) => {
    const v = { action, q, page, size, ...next };
    if (next.action !== undefined || next.q !== undefined || next.size !== undefined) v.page = next.page ?? 1;
    const sp = new URLSearchParams();
    if (v.action) sp.set("action", v.action);
    if (v.q) sp.set("q", v.q);
    if (v.page > 1) sp.set("page", String(v.page));
    if (v.size !== 50) sp.set("size", String(v.size));
    router.push(`/querylog${sp.size ? "?" + sp.toString() : ""}`);
  };
  const saveSettings = (next: Partial<{ retention_hours: number; mode: string; sample: number }>, msg: string) =>
    data && act.run(() => put("/dns/querylog/settings", { retention_hours: data.retention_hours, mode: data.mode, sample: data.sample, ...next }), msg).then((ok) => ok && reload());
  const setRetention = (h: number) => saveSettings({ retention_hours: h }, `Queries older than ${RETENTION.find((r) => r[0] === h)?.[1] ?? h + " hours"} are now deleted automatically.`);

  if (licenseError) return <Shell><h1>Query log</h1><LicenseRequired message={licenseError} /></Shell>;
  return (
    <Shell>
      <div className="toprow">
        <h1>Query log</h1>
        <div className="row" style={{ alignItems: "center", gap: 14 }}>
        <label className="row" style={{ alignItems: "center", flexDirection: "row", gap: 8 }}>
          Log
          <select value={data?.mode ?? "all"} onChange={(e) => saveSettings({ mode: e.target.value }, "Query logging updated.")}>
            <option value="all">every query</option>
            <option value="important">blocked, refused and failed only</option>
            <option value="off">nothing</option>
          </select>
        </label>
        {data?.mode === "all" && (
          <label className="row" style={{ alignItems: "center", flexDirection: "row", gap: 8 }} title="On busy servers, keep only a sample of allowed queries. Blocked, refused and failed queries are always logged.">
            Allowed queries
            <select value={data?.sample ?? 1} onChange={(e) => saveSettings({ sample: Number(e.target.value) }, "Sampling updated.")}>
              {[1, 10, 100, 1000].map((n) => <option key={n} value={n}>{n === 1 ? "all" : `1 in ${n}`}</option>)}
            </select>
          </label>
        )}
        <label className="row" style={{ alignItems: "center", flexDirection: "row", gap: 8 }}>
          Keep queries for
          <select value={data?.retention_hours ?? ""} onChange={(e) => setRetention(Number(e.target.value))}>
            {data && !RETENTION.some((r) => r[0] === data.retention_hours) && <option value={data.retention_hours}>{data.retention_hours} hours</option>}
            {RETENTION.map(([h, l]) => <option key={h} value={h}>{l}</option>)}
          </select>
        </label>
        </div>
      </div>
      {data && data.dropped > 0 && (
        <Alert kind="warn">
          {data.dropped.toLocaleString("en-IN")} log entries were dropped because the database could not keep up with the query rate.
          DNS answers were not affected. Log only blocked queries, or sample allowed ones, to keep the log complete.
        </Alert>
      )}
      {data && data.mode === "all" && data.sample > 1 && <p className="muted" style={{ marginTop: -6 }}>Allowed queries are sampled: 1 in {data.sample} is logged. Blocked, refused and failed queries are all logged.</p>}
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <div className="panel">
        <div className="tabs" role="tablist" aria-label="Result">
          {TABS.map(([k, l]) => (
            <button key={k || "all"} type="button" role="tab" aria-selected={action === k} className={action === k ? "on" : ""} onClick={() => go({ action: k })}>{l}</button>
          ))}
        </div>
        <form className="row" style={{ margin: "12px 0" }} onSubmit={(e: FormEvent) => { e.preventDefault(); go({ q: search.trim() }); }}>
          <label style={{ flex: 1, minWidth: 220 }}>Domain or client IP<input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="facebook.com or 103.199.160.28" /></label>
          <button className="secondary">Search</button>
          {q && <button type="button" className="secondary" onClick={() => go({ q: "" })}>Clear</button>}
          <button type="button" className="secondary" onClick={reload}>Refresh</button>
          <a className="button-link" style={{ marginLeft: "auto", alignSelf: "flex-end" }} href={`/api/dns/querylog/export?range=7d&q=${encodeURIComponent(q)}&action=${action}`} download>Export CSV</a>
        </form>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Client</th><th>Name</th><th>Type</th><th>Result</th></tr></thead>
            <tbody>
              {data?.entries.map((e, i) => (
                <tr key={`${e.at}-${i}`}>
                  <td style={{ whiteSpace: "nowrap" }}>{fmtTime(e.at)}</td>
                  <td className="mono"><a href="#" onClick={(ev) => { ev.preventDefault(); go({ q: e.client }); }}>{e.client}</a></td>
                  <td className="mono"><a href="#" onClick={(ev) => { ev.preventDefault(); go({ q: e.name }); }}>{e.name}</a></td>
                  <td>{e.type}</td>
                  <td><span className={`badge ${tone(e.action)}`}>{e.action}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {data?.entries.length === 0 && <p className="muted">No queries match.</p>}
        </div>
        {data && (
          <div className="pager">
            <span className="muted">
              {data.total === 0 ? "0 queries" : `${((data.page - 1) * data.page_size + 1).toLocaleString()}–${Math.min(data.page * data.page_size, data.total).toLocaleString()} of ${data.total.toLocaleString()}`}
            </span>
            <nav aria-label="Pages" className="pages">
              <button type="button" className="secondary" disabled={data.page <= 1} onClick={() => go({ page: data.page - 1 })}>‹ Previous</button>
              {pageList(data.page, data.pages).map((p, i) =>
                p === "…" ? <span key={`gap${i}`} className="muted">…</span> : (
                  <button key={p} type="button" className={p === data.page ? "" : "secondary"} aria-current={p === data.page ? "page" : undefined} onClick={() => go({ page: p })}>{p}</button>
                ),
              )}
              <button type="button" className="secondary" disabled={data.page >= data.pages} onClick={() => go({ page: data.page + 1 })}>Next ›</button>
            </nav>
            <label className="row" style={{ alignItems: "center", flexDirection: "row", gap: 6 }}>
              Rows
              <select value={data.page_size} onChange={(e) => go({ size: Number(e.target.value) })}>
                {[25, 50, 100, 200].map((n) => <option key={n}>{n}</option>)}
              </select>
            </label>
          </div>
        )}
      </div>
    </Shell>
  );
}

export default function QueryLog() {
  return <Suspense><QueryLogInner /></Suspense>;
}
