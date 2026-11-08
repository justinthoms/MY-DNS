"use client";

import { FormEvent, useEffect, useState } from "react";
import { post, put, fmtDate, fmtTime } from "@/lib/api";
import { LicenseState, MODE_LABEL } from "@/lib/license";
import { Alert, Shell, useAction, useLoad } from "@/components/ui";

type Resp = { state: LicenseState; settings: { server_url: string; sync_enabled: boolean }; trial_days: number };

export default function LicensePage() {
  const { data, error, reload } = useLoad<Resp>("/license");
  const act = useAction();
  const [key, setKey] = useState("");
  const [file, setFile] = useState("");
  const [server, setServer] = useState("");
  const [sync, setSync] = useState(false);
  useEffect(() => {
    if (data) { setServer(data.settings.server_url); setSync(data.settings.sync_enabled); }
  }, [data]);

  const run = async (fn: () => Promise<unknown>, msg: string) => { if (await act.run(fn, msg)) reload(); };
  const activate = (e: FormEvent) => { e.preventDefault(); run(() => post("/license/activate", { license_key: key.trim(), server_url: server }), "License activated."); };
  const upload = (e: FormEvent) => { e.preventDefault(); run(() => post("/license/upload", { license: file }), "License file installed."); };
  const saveSettings = (e: FormEvent) => { e.preventDefault(); run(() => put("/license/settings", { server_url: server, sync_enabled: sync }), "Settings saved."); };
  const readFile = async (f: File | undefined) => { if (f) setFile(await f.text()); };

  const st = data?.state;
  return (
    <Shell>
      <h1>License</h1>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      {st && (
        <>
          <div className="panel">
            <h2>Status <span className={`badge ${MODE_LABEL[st.mode][1]}`}>{MODE_LABEL[st.mode][0]}</span></h2>
            <p>{st.message}</p>
            <dl className="kv">
              {st.customer && <><dt>Licensed to</dt><dd>{st.customer}</dd></>}
              {st.license_id && <><dt>License ID</dt><dd className="mono">{st.license_id}</dd></>}
              {st.edition && <><dt>Edition</dt><dd>{st.edition}</dd></>}
              <dt>Enabled features</dt><dd>{st.features.length ? st.features.join(", ") : <span className="muted">none</span>}</dd>
              {st.expires_at && <><dt>Expires</dt><dd>{fmtDate(st.expires_at)} ({st.days_left} days left)</dd></>}
              {!st.license_id && <><dt>Trial ends</dt><dd>{fmtDate(st.trial_ends_at)}</dd></>}
              <dt>Hardware ID</dt><dd className="mono">{st.hardware_id} <button type="button" className="secondary" style={{ padding: "1px 8px", fontSize: 12 }} onClick={() => navigator.clipboard.writeText(st.hardware_id)}>Copy</button></dd>
              {st.last_sync && <><dt>Last status sync</dt><dd>{fmtTime(st.last_sync.at)}: {st.last_sync.ok ? "" : "failed: "}{st.last_sync.message}</dd></>}
            </dl>
          </div>

          {(st.tamper_events.length > 0 || st.clock_rollback) && (
            <div className="panel">
              <h2>Tamper detection</h2>
              {st.clock_rollback && <Alert kind="warn">The system clock is behind the latest time this server has seen ({fmtTime(st.effective_time)}). Licensing uses the later time. Check NTP.</Alert>}
              <ul>
                {st.tamper_events.map((e, i) => <li key={i}><strong>{fmtTime(e.detected_at)}</strong>: {e.detail}</li>)}
              </ul>
            </div>
          )}

          <div className="panel">
            <h2>Activate online</h2>
            <p className="muted">Enter the license key from your vendor. This server contacts the License Manager once to bind the license to this hardware.</p>
            <form className="stack" onSubmit={activate}>
              <label>License key<input required placeholder="MYDNS-XXXXX-XXXXX-XXXXX-XXXXX" className="mono" value={key} onChange={(e) => setKey(e.target.value)} /></label>
              <label>License server URL<input type="url" required placeholder="https://licenses.vendor.example" value={server} onChange={(e) => setServer(e.target.value)} /></label>
              <div><button disabled={act.busy}>Activate</button></div>
            </form>
          </div>

          <div className="panel">
            <h2>Activate offline</h2>
            <p className="muted">No internet access? Send the hardware ID above to your vendor. They return a license file; upload or paste it here.</p>
            <form className="stack" onSubmit={upload}>
              <input type="file" accept=".lic,.txt,.pem" onChange={(e) => readFile(e.target.files?.[0])} />
              <textarea required placeholder="-----BEGIN ISP NETCONTROL LICENSE-----" value={file} onChange={(e) => setFile(e.target.value)} />
              <div><button disabled={act.busy}>Install license file</button></div>
            </form>
          </div>

          <div className="panel">
            <h2>Status sync</h2>
            <p className="muted">When enabled, this server checks in with the License Manager every few hours to pick up renewals and revocations. Only the license ID, the hardware ID and a random nonce are sent.</p>
            <form className="stack" onSubmit={saveSettings}>
              <label>License server URL<input type="url" value={server} onChange={(e) => setServer(e.target.value)} /></label>
              <label className="check"><input type="checkbox" checked={sync} onChange={(e) => setSync(e.target.checked)} />Enable status sync</label>
              <div className="actions">
                <button disabled={act.busy}>Save</button>
                <button type="button" className="secondary" disabled={act.busy || !st.license_id} onClick={() => run(() => post("/license/sync"), "Status sync completed.")}>Sync now</button>
              </div>
            </form>
          </div>
        </>
      )}
    </Shell>
  );
}
