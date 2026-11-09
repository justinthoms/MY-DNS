"use client";

import { FormEvent, useEffect, useState } from "react";
import { put } from "@/lib/api";
import { Alert, Shell, useAction, useLoad } from "@/components/ui";
import ListenPanel from "@/components/ListenPanel";
import EncryptedPanel from "@/components/EncryptedPanel";

type Settings = { upstreams: string[]; block_mode: string; sinkhole_v4: string; sinkhole_v6: string; allowed_clients: string[]; filtering_enabled: boolean };

const lines = (s: string) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

export default function SettingsPage() {
  const { data, error, reload } = useLoad<Settings>("/dns/settings");
  const act = useAction();
  const [f, setF] = useState<Settings | null>(null);
  const [ups, setUps] = useState("");
  const [clients, setClients] = useState("");
  useEffect(() => {
    if (data) { setF(data); setUps(data.upstreams.join("\n")); setClients(data.allowed_clients.join("\n")); }
  }, [data]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!f) return;
    if (await act.run(() => put("/dns/settings", { ...f, upstreams: lines(ups), allowed_clients: lines(clients) }), "Saved. The resolver uses the new settings immediately.")) reload();
  };
  return (
    <Shell>
      <h1>DNS settings</h1>
      <p className="muted">These settings work in every license state, so subscribers keep getting answers even when filtering is unavailable.</p>
      <ListenPanel />
      <h2 style={{ marginTop: 8 }}>Resolver</h2>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      {f && (
        <form className="panel stack" onSubmit={save}>
          <label>Upstream resolvers (one per line)<textarea style={{ minHeight: 80 }} value={ups} onChange={(e) => setUps(e.target.value)} /></label>
          <p className="muted" style={{ margin: "-6px 0 0" }}>IP or IP:port, for example <span className="mono">127.0.0.1:5335</span> (Unbound on this server). Encrypted (DNS over TLS): <span className="mono">tls://1.1.1.1#cloudflare-dns.com</span>, <span className="mono">tls://8.8.8.8#dns.google</span>, <span className="mono">tls://9.9.9.9#dns.quad9.net</span>.</p>
          <label>Allowed client networks (one CIDR per line)
            <textarea style={{ minHeight: 120 }} value={clients} onChange={(e) => setClients(e.target.value)} />
          </label>
          <p className="muted" style={{ margin: 0 }}>Queries from any other address are refused, so this server never acts as an open resolver. Add your subscribers' public ranges here if they are not private or CGNAT addresses.</p>
          <label className="check"><input type="checkbox" checked={f.filtering_enabled} onChange={(e) => setF({ ...f, filtering_enabled: e.target.checked })} />Apply the block and allow lists (needs a license with DNS filtering)</label>
          <label>Blocked domains get
            <select value={f.block_mode} onChange={(e) => setF({ ...f, block_mode: e.target.value })}>
              <option value="nxdomain">NXDOMAIN (domain does not exist)</option>
              <option value="sinkhole">Sinkhole address</option>
            </select>
          </label>
          {f.block_mode === "sinkhole" && (
            <div className="row">
              <label>IPv4 sinkhole<input value={f.sinkhole_v4} onChange={(e) => setF({ ...f, sinkhole_v4: e.target.value })} /></label>
              <label>IPv6 sinkhole<input value={f.sinkhole_v6} onChange={(e) => setF({ ...f, sinkhole_v6: e.target.value })} /></label>
            </div>
          )}
          <div><button disabled={act.busy}>Save</button></div>
        </form>
      )}
      <EncryptedPanel />
    </Shell>
  );
}
