"use client";

import { FormEvent, useState } from "react";
import { del, post, fmtDate } from "@/lib/api";
import { Alert, useAction, useLoad } from "./ui";

type Entry = { domain: string; category: string; note: string; created_at: string };

// reloadKey lets the page refresh both lists after an import.

// DomainList manages the block list or the allow list.
export default function DomainList({ kind, reloadKey = 0 }: { kind: "blocklist" | "allowlist"; reloadKey?: number }) {
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const { data, error, reload } = useLoad<{ entries: Entry[]; total: number }>(`/dns/${kind}?q=${encodeURIComponent(query)}&r=${reloadKey}`);
  const act = useAction();
  const [domain, setDomain] = useState("");
  const [category, setCategory] = useState("");
  const [note, setNote] = useState("");
  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (await act.run(() => post(`/dns/${kind}`, { domain, category, note }), `${domain} added.`)) { setDomain(""); setNote(""); reload(); }
  };
  const remove = async (d: string) => { if (await act.run(() => del(`/dns/${kind}/${encodeURIComponent(d)}`), `${d} removed.`)) reload(); };
  const block = kind === "blocklist";
  return (
    <div className="panel">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h2 style={{ margin: 0 }}>{block ? "Block list" : "Allow list"} {data && <span className="muted">({data.total.toLocaleString()})</span>}</h2>
        <div className="actions" aria-label="Export">
          <span className="muted" style={{ alignSelf: "center", fontSize: 13 }}>Export:</span>
          {(["txt", "hosts", "csv"] as const).map((f) => (
            <a key={f} className="button-link" href={`/api/dns/${kind}/export?format=${f}`} download>{f === "txt" ? "Text" : f === "hosts" ? "Hosts" : "CSV"}</a>
          ))}
        </div>
      </div>
      <p className="muted">
        {block
          ? "A blocked domain also blocks all of its subdomains."
          : "Allowed domains (and their subdomains) are never blocked, even if a block-list entry covers them."}
      </p>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <form className="row" onSubmit={add} style={{ marginBottom: 14 }}>
        <label style={{ flex: 2, minWidth: 200 }}>Domain<input required placeholder="ads.example.com" value={domain} onChange={(e) => setDomain(e.target.value)} /></label>
        {block && <label style={{ flex: 1, minWidth: 120 }}>Category<input placeholder="custom" value={category} onChange={(e) => setCategory(e.target.value)} /></label>}
        <label style={{ flex: 2, minWidth: 160 }}>Note<input value={note} onChange={(e) => setNote(e.target.value)} /></label>
        <button disabled={act.busy}>Add</button>
      </form>
      <form className="row" onSubmit={(e) => { e.preventDefault(); setQuery(q); }} style={{ marginBottom: 10 }}>
        <label>Search<input value={q} onChange={(e) => setQ(e.target.value)} /></label>
        <button className="secondary">Search</button>
      </form>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Domain</th>{block && <th>Category</th>}<th>Note</th><th>Added</th><th></th></tr></thead>
          <tbody>
            {data?.entries.map((e) => (
              <tr key={e.domain}>
                <td className="mono">{e.domain}</td>
                {block && <td>{e.category}</td>}
                <td className="muted">{e.note}</td>
                <td>{fmtDate(e.created_at)}</td>
                <td><button className="secondary" onClick={() => remove(e.domain)}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.total > data.entries.length && <p className="muted">Showing {data.entries.length} of {data.total.toLocaleString()}. Search to narrow down.</p>}
      </div>
    </div>
  );
}
