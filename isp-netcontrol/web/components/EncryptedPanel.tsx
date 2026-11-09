"use client";

import { useEffect, useState } from "react";
import { fmtDate, put } from "@/lib/api";
import { Alert, useAction, useLoad } from "@/components/ui";

type Cert = { ok: boolean; error?: string; subject: string; names: string[]; not_after: string; self_signed: boolean };
type Data = { settings: { dot: boolean; doh: boolean }; dot_listening: string[]; certificate: Cert };

// EncryptedPanel turns DNS over TLS and DNS over HTTPS on and off for subscribers.
export default function EncryptedPanel() {
  const { data, error, reload } = useLoad<Data>("/dns/encrypted");
  const act = useAction();
  const [f, setF] = useState({ dot: false, doh: false });
  const [host, setHost] = useState("");
  useEffect(() => { if (data) setF(data.settings); }, [data]);
  useEffect(() => setHost(window.location.hostname), []);
  const save = async () => {
    if (await act.run(() => put("/dns/encrypted", f), "Saved. Encrypted DNS settings apply immediately.")) reload();
  };
  const cert = data?.certificate;
  const name = cert?.names.find((n) => !/^[\d.:]+$/.test(n)) ?? host;
  return (
    <>
      <h2 style={{ marginTop: 8 }}>Encrypted DNS for subscribers</h2>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      {data && (
        <div className="panel stack">
          <label className="check"><input type="checkbox" checked={f.dot} onChange={(e) => setF({ ...f, dot: e.target.checked })} />DNS over TLS (port 853): Android &ldquo;Private DNS&rdquo;, routers, Linux</label>
          <label className="check"><input type="checkbox" checked={f.doh} onChange={(e) => setF({ ...f, doh: e.target.checked })} />DNS over HTTPS: browsers, Windows 11, iOS and macOS profiles</label>
          <div className="kv" style={{ fontSize: 13.5 }}>
            <span className="muted">DNS over TLS</span>
            <span className="mono">{data.dot_listening.length ? data.dot_listening.join(", ") : "off"}{data.settings.dot && name ? ` · hostname ${name}` : ""}</span>
            <span className="muted">DNS over HTTPS</span>
            <span className="mono">{data.settings.doh ? `https://${name}/dns-query` : "off"}</span>
            <span className="muted">Certificate</span>
            <span>
              {cert?.ok ? (
                <>{cert.subject || cert.names[0]} · valid until {fmtDate(cert.not_after)}{cert.names.length ? <span className="muted"> · {cert.names.join(", ")}</span> : null}</>
              ) : <span style={{ color: "var(--bad)" }}>{cert?.error ?? "none"}</span>}
            </span>
          </div>
          {cert?.self_signed && (f.dot || f.doh) && (
            <Alert kind="warn">The console certificate is self-signed. Phones and browsers only use encrypted DNS with a trusted certificate for a hostname: re-run the installer with <span className="mono">--tls-cert</span> and <span className="mono">--tls-key</span> (for example from Let&rsquo;s Encrypt for {name || "your DNS hostname"}).</Alert>
          )}
          <p className="muted" style={{ margin: 0 }}>Both use the console certificate and the same access list, protection and filtering as plain DNS. Open TCP port 853 (DNS over TLS) and 443 (DNS over HTTPS) in any firewall in front of this server.</p>
          <div><button type="button" disabled={act.busy} onClick={save}>Save</button></div>
        </div>
      )}
    </>
  );
}
