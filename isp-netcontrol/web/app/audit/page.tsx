"use client";

import { fmtTime } from "@/lib/api";
import { Alert, Shell, useLoad } from "@/components/ui";

type Entry = { at: string; actor: string; action: string; target: string; details: string; ip: string };

export default function AuditPage() {
  const { data, error } = useLoad<Entry[]>("/audit");
  return (
    <Shell>
      <h1>Audit log</h1>
      <Alert kind="error">{error}</Alert>
      <div className="panel table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
          <tbody>
            {data?.map((e) => (
              <tr key={e.at + e.action + e.target}>
                <td style={{ whiteSpace: "nowrap" }}>{fmtTime(e.at)}</td>
                <td>{e.actor}</td>
                <td><code>{e.action}</code></td>
                <td className="mono">{e.target}</td>
                <td className="mono muted">{e.details === "{}" ? "" : e.details}</td>
                <td className="muted">{e.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}
