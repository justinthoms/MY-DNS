"use client";

import { FormEvent, useState } from "react";
import { del, get, post, put, fmtTime } from "@/lib/api";
import { Alert, LicenseRequired, Shell, useAction, useLoad } from "@/components/ui";
import DomainList from "@/components/DomainList";

type Source = { id: number; name: string; url: string; category: string; enabled: boolean; last_fetch_at: string | null; last_status: string; entries: number };
type Check = { name: string; result: "local" | "blocked" | "allowed" | "forwarded"; matched?: string; category?: string; source?: string; records?: string[]; note?: string };

const RESULT: Record<Check["result"], [string, string]> = {
  blocked: ["Blocked", "bad"],
  allowed: ["Allowed by the allow list", "ok"],
  forwarded: ["Not listed: resolved normally", "muted"],
  local: ["Answered from a local DNS record", "ok"],
};

function CheckDomain() {
  const [name, setName] = useState("");
  const [res, setRes] = useState<Check | null>(null);
  const act = useAction();
  const run = (e: FormEvent) => { e.preventDefault(); act.run(async () => setRes(await get<Check>(`/dns/check?name=${encodeURIComponent(name)}`))); };
  return (
    <div className="panel">
      <h2>Check a domain</h2>
      <p className="muted">See how this server answers a name, and which entry decides it.</p>
      <form className="row" onSubmit={run}>
        <label style={{ flex: 1, minWidth: 220 }}>Domain<input required placeholder="tracker.ads.example.com" value={name} onChange={(e) => setName(e.target.value)} /></label>
        <button disabled={act.busy}>Check</button>
      </form>
      <Alert kind="error">{act.error}</Alert>
      {res && (
        <div style={{ marginTop: 12 }}>
          <span className={`badge ${RESULT[res.result][1]}`}>{RESULT[res.result][0]}</span>{" "}
          <span className="mono">{res.name}</span>
          {res.matched && <p style={{ margin: "8px 0 0" }}>Matched list entry <code>{res.matched}</code>{res.category && <> (category {res.category})</>}{res.source && <>, from {res.source}</>}.</p>}
          {res.note && <p className="muted" style={{ margin: "6px 0 0" }}>{res.note}</p>}
          {res.records && <pre className="block" style={{ marginTop: 8 }}>{res.records.join("\n")}</pre>}
        </div>
      )}
    </div>
  );
}

function Sources({ onChange }: { onChange: () => void }) {
  const { data, reload } = useLoad<Source[]>("/dns/sources");
  const act = useAction();
  const [f, setF] = useState({ name: "", url: "", category: "ads" });
  const refresh = () => { reload(); onChange(); };
  const add = async (e: FormEvent) => {
    e.preventDefault();
    let res: any = null;
    if (await act.run(async () => { res = await post("/dns/sources", f); })) {
      if (res?.error) act.setError(`Subscribed, but the first download failed: ${res.error}`);
      setF({ name: "", url: "", category: "ads" });
      refresh();
    }
  };
  return (
    <div className="panel">
      <h2>Block list subscriptions</h2>
      <p className="muted">
        Download public block lists from a URL. They are refreshed every 24 hours. Plain, hosts-file and Adblock-style
        (<code>||domain^</code>) lists are understood. Entries you add by hand are never overwritten, and a failed or
        empty download keeps the previous list.
      </p>
      <Alert kind="error">{act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <form className="row" onSubmit={add} style={{ marginBottom: 14 }}>
        <label style={{ flex: 1, minWidth: 140 }}>Name<input placeholder="Ad servers" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label style={{ flex: 3, minWidth: 240 }}>URL<input required type="url" placeholder="https://example.org/hosts.txt" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></label>
        <label style={{ width: 130 }}>Category<input value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })} /></label>
        <button disabled={act.busy}>Subscribe</button>
      </form>
      {data && data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Domains</th><th>Last update</th><th>Enabled</th><th></th></tr></thead>
            <tbody>
              {data.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}<div className="mono muted" style={{ fontSize: 11.5 }}>{s.url}</div></td>
                  <td className="num">{s.entries.toLocaleString()}</td>
                  <td>{fmtTime(s.last_fetch_at)}<div className={s.last_status.startsWith("error") ? "" : "muted"} style={{ fontSize: 12, color: s.last_status.startsWith("error") ? "var(--bad)" : undefined }}>{s.last_status}</div></td>
                  <td><input type="checkbox" aria-label={`Enable ${s.name}`} checked={s.enabled} onChange={() => act.run(() => put(`/dns/sources/${s.id}`, { enabled: !s.enabled }), "Updated.").then(refresh)} /></td>
                  <td className="actions" style={{ flexWrap: "nowrap" }}>
                    <button className="secondary" disabled={!s.enabled || act.busy} onClick={() => act.run(() => post(`/dns/sources/${s.id}/refresh`), `${s.name} refreshed.`).then(refresh)}>Refresh</button>
                    <button className="secondary" onClick={() => confirm(`Remove ${s.name} and its ${s.entries} domains?`) && act.run(() => del(`/dns/sources/${s.id}`), `${s.name} removed.`).then(refresh)}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function DNSPage() {
  const probe = useLoad<unknown>("/dns/allowlist?q=__probe__");
  const act = useAction();
  const [text, setText] = useState("");
  const [target, setTarget] = useState<"blocklist" | "allowlist">("blocklist");
  const [mode, setMode] = useState<"merge" | "replace">("merge");
  const [category, setCategory] = useState("");
  const [key, setKey] = useState(0);
  const importList = async (e: FormEvent) => {
    e.preventDefault();
    if (mode === "replace" && !confirm(`Replace every hand-made entry of the ${target === "blocklist" ? "block" : "allow"} list with this file?`)) return;
    let res: any = null;
    if (await act.run(async () => { res = await post(`/dns/${target}/import`, { text, category, mode }); })) {
      await act.run(async () => {}, `Imported: ${res.added} added, ${res.already_present} already present, ${res.skipped} lines skipped${res.removed ? `, ${res.removed} removed first` : ""}.`);
      setText("");
      setKey(key + 1);
    }
  };
  const readFile = async (f: File | undefined) => { if (f) setText(await f.text()); };
  return (
    <Shell>
      <h1>DNS filtering</h1>
      {probe.licenseError ? <LicenseRequired message={probe.licenseError} /> : (
        <>
          <CheckDomain />
          <DomainList kind="blocklist" reloadKey={key} />
          <DomainList kind="allowlist" reloadKey={key} />
          <div className="panel">
            <h2>Import a list</h2>
            <p className="muted">
              One domain per line, a hosts file (<code>0.0.0.0 ads.example.com</code>), Adblock-style rules
              (<code>||ads.example.com^</code>) or a CSV exported from here (<code>domain,category,note</code>).
              Comments and invalid lines are skipped.
            </p>
            <Alert kind="error">{act.error}</Alert>
            <Alert kind="success">{act.ok}</Alert>
            <form className="stack" onSubmit={importList} style={{ maxWidth: 720 }}>
              <div className="row">
                <label>Into
                  <select value={target} onChange={(e) => setTarget(e.target.value as "blocklist" | "allowlist")}>
                    <option value="blocklist">Block list</option>
                    <option value="allowlist">Allow list</option>
                  </select>
                </label>
                <label>Mode
                  <select value={mode} onChange={(e) => setMode(e.target.value as "merge" | "replace")}>
                    <option value="merge">Merge: add new entries</option>
                    <option value="replace">Replace hand-made entries</option>
                  </select>
                </label>
                <label>Category<input placeholder={target === "blocklist" ? "imported" : "allow"} value={category} onChange={(e) => setCategory(e.target.value)} /></label>
              </div>
              <input type="file" accept=".txt,.hosts,.list,.csv" onChange={(e) => readFile(e.target.files?.[0])} />
              <textarea required value={text} onChange={(e) => setText(e.target.value)} />
              <div><button disabled={act.busy}>Import</button></div>
            </form>
          </div>
          <Sources onChange={() => setKey((k) => k + 1)} />
        </>
      )}
    </Shell>
  );
}
