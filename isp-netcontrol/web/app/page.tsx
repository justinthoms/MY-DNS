"use client";

import Link from "next/link";
import { fmtDate } from "@/lib/api";
import { LicenseState, MODE_LABEL } from "@/lib/license";
import { Alert, Shell, useLoad } from "@/components/ui";

type Status = {
  version: string;
  license: LicenseState;
  dns: {
    stats: { total: number; forwarded: number; cached: number; blocked: number; refused: number; failed: number };
    filtering_active: boolean; query_log_active: boolean; blocklist_entries: number; allowlist_entries: number; listen: string[];
  };
  firewall: { state: { applied: boolean; rules: number; error?: string }; enabled_rules: number; managed: boolean };
};

const domains = (n: number) => `${n.toLocaleString()} ${n === 1 ? "domain" : "domains"}`;

export default function Dashboard() {
  const { data, error } = useLoad<Status>("/status");
  const lic = data?.license;
  const [label, tone] = lic ? MODE_LABEL[lic.mode] : ["", "ok"];
  return (
    <Shell>
      <h1>Dashboard</h1>
      <Alert kind="error">{error}</Alert>
      {data && lic && (
        <>
          <div className={`alert ${tone === "ok" ? "success" : tone === "warn" ? "warn" : "error"}`}>
            <strong>{label}.</strong> {lic.message} {lic.mode !== "licensed" && <Link href="/license">Manage license</Link>}
          </div>
          {lic.tamper_events.length > 0 && (
            <Alert kind="warn">Tampering with the license state or the clock was detected ({lic.tamper_events.length} event{lic.tamper_events.length > 1 ? "s" : ""}). See the License page.</Alert>
          )}
          <div className="grid">
            {([
              ["Queries", data.dns.stats.total],
              ["Blocked", data.dns.stats.blocked],
              ["Forwarded", data.dns.stats.forwarded],
              ["From cache", data.dns.stats.cached],
              ["Refused (not allowed)", data.dns.stats.refused],
              ["Upstream failures", data.dns.stats.failed],
            ] as [string, number][]).map(([k, v]) => (
              <div className="stat" key={k}><div className="label">{k}</div><div className="value">{v.toLocaleString()}</div></div>
            ))}
          </div>
          <div className="grid">
            <div className="panel" style={{ margin: 0 }}>
              <h2>DNS</h2>
              <dl className="kv">
                <dt>Filtering</dt><dd>{data.dns.filtering_active ? <span className="badge ok">active</span> : <span className="badge bad">off</span>}</dd>
                <dt>Block list</dt><dd>{domains(data.dns.blocklist_entries)}</dd>
                <dt>Allow list</dt><dd>{domains(data.dns.allowlist_entries)}</dd>
                <dt>Query log</dt><dd>{data.dns.query_log_active ? "on" : "off"}</dd>
                <dt>Listening</dt><dd className="mono">{data.dns.listen.join(", ")}</dd>
              </dl>
            </div>
            <div className="panel" style={{ margin: 0 }}>
              <h2>Firewall</h2>
              <dl className="kv">
                <dt>State</dt>
                <dd>{!data.firewall.managed ? <span className="badge muted">not managed</span> : data.firewall.state.applied ? <span className="badge ok">applied</span> : <span className="badge warn">not applied</span>}</dd>
                <dt>Enabled rules</dt><dd>{data.firewall.enabled_rules}</dd>
                {data.firewall.state.error && data.firewall.managed && <><dt>Last error</dt><dd className="muted">{data.firewall.state.error}</dd></>}
              </dl>
            </div>
            <div className="panel" style={{ margin: 0 }}>
              <h2>License</h2>
              <dl className="kv">
                <dt>Status</dt><dd>{label}</dd>
                {lic.customer && <><dt>Customer</dt><dd>{lic.customer}</dd></>}
                <dt>{lic.mode === "trial" ? "Trial ends" : "Expires"}</dt><dd>{fmtDate(lic.mode === "trial" ? lic.trial_ends_at : lic.expires_at)}</dd>
                <dt>Version</dt><dd>{data.version}</dd>
              </dl>
            </div>
          </div>
        </>
      )}
    </Shell>
  );
}
