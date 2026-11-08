"use client";

import { FormEvent, useState } from "react";
import { del, post, put } from "@/lib/api";
import { Alert, Shell, useAction, useLoad } from "@/components/ui";

type Rec = { id: number; name: string; type: string; value: string; ttl: number; priority: number; note: string; enabled: boolean };

const TYPES: Record<string, { value: string; hint: string }> = {
  A: { value: "IPv4 address", hint: "192.168.1.10" },
  AAAA: { value: "IPv6 address", hint: "2001:db8::10" },
  CNAME: { value: "Target name", hint: "nas.office.lan" },
  TXT: { value: "Text", hint: "v=spf1 -all" },
  MX: { value: "Mail server", hint: "mail.office.lan" },
  PTR: { value: "Host name", hint: "nas.office.lan" },
};

const empty = { name: "", type: "A", value: "", ttl: 300, priority: 10, note: "" };

export default function RecordsPage() {
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const { data, error, reload } = useLoad<Rec[]>(`/dns/records?q=${encodeURIComponent(query)}`);
  const act = useAction();
  const [f, setF] = useState(empty);
  const [editing, setEditing] = useState<number | null>(null);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    const body = { ...f, ttl: Number(f.ttl), priority: Number(f.priority) };
    const ok = editing
      ? await act.run(() => put(`/dns/records/${editing}`, { ...body, enabled: true }), `${f.name} updated.`)
      : await act.run(() => post("/dns/records", body), `${f.name} added. It is answered immediately.`);
    if (ok) { setF(empty); setEditing(null); reload(); }
  };
  const toggle = (r: Rec) => act.run(() => put(`/dns/records/${r.id}`, { ...r, enabled: !r.enabled }), `${r.name} ${r.enabled ? "disabled" : "enabled"}.`).then((ok) => ok && reload());
  const remove = (r: Rec) => confirm(`Delete the ${r.type} record for ${r.name}?`) && act.run(() => del(`/dns/records/${r.id}`), `${r.name} deleted.`).then((ok) => ok && reload());
  const edit = (r: Rec) => { setEditing(r.id); setF({ name: r.name, type: r.type, value: r.value, ttl: r.ttl, priority: r.priority, note: r.note }); window.scrollTo({ top: 0, behavior: "smooth" }); };

  return (
    <Shell>
      <h1>DNS records</h1>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <div className="panel">
        <h2>{editing ? "Edit record" : "Add a record"}</h2>
        <p className="muted">
          Local records are answered by this server before filtering and forwarding: use them for internal hosts
          (<code>router.lan</code>), to override a public name, or for reverse lookups. A name starting with <code>*.</code> matches
          every name below it. For PTR records you can type the IP address as the name.
        </p>
        <form className="row" onSubmit={save}>
          <label style={{ flex: 2, minWidth: 200 }}>Name<input required placeholder={f.type === "PTR" ? "192.168.1.10" : "nas.office.lan"} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label>Type
            <select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}>
              {Object.keys(TYPES).map((t) => <option key={t}>{t}</option>)}
            </select>
          </label>
          <label style={{ flex: 2, minWidth: 180 }}>{TYPES[f.type].value}<input required placeholder={TYPES[f.type].hint} value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} /></label>
          {f.type === "MX" && <label style={{ width: 90 }}>Priority<input type="number" min={0} max={65535} value={f.priority} onChange={(e) => setF({ ...f, priority: Number(e.target.value) })} /></label>}
          <label style={{ width: 100 }}>TTL (s)<input type="number" min={0} max={86400} value={f.ttl} onChange={(e) => setF({ ...f, ttl: Number(e.target.value) })} /></label>
          <label style={{ flex: 1, minWidth: 140 }}>Note<input value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} /></label>
          <div className="actions">
            <button disabled={act.busy}>{editing ? "Save" : "Add"}</button>
            {editing && <button type="button" className="secondary" onClick={() => { setEditing(null); setF(empty); }}>Cancel</button>}
          </div>
        </form>
      </div>
      <div className="panel table-wrap">
        <form className="row" onSubmit={(e) => { e.preventDefault(); setQuery(q); }} style={{ marginBottom: 10 }}>
          <label>Search<input value={q} onChange={(e) => setQ(e.target.value)} /></label>
          <button className="secondary">Search</button>
        </form>
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th>Note</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            {data?.map((r) => (
              <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.6 }}>
                <td className="mono">{r.name}</td>
                <td><span className="badge muted">{r.type}</span></td>
                <td className="mono">{r.type === "MX" ? `${r.priority} ${r.value}` : r.value}</td>
                <td className="num">{r.ttl}</td>
                <td className="muted">{r.note}</td>
                <td><input type="checkbox" aria-label={`Enable ${r.name}`} checked={r.enabled} onChange={() => toggle(r)} /></td>
                <td className="actions" style={{ flexWrap: "nowrap" }}>
                  <button className="secondary" onClick={() => edit(r)}>Edit</button>
                  <button className="secondary" onClick={() => remove(r)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data?.length === 0 && <p className="muted">No records yet.</p>}
      </div>
    </Shell>
  );
}
