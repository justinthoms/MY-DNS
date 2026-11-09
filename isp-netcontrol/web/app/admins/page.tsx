"use client";

import { FormEvent, useState } from "react";
import { del, post, fmtTime } from "@/lib/api";
import { Alert, Shell, useAction, useLoad } from "@/components/ui";

type Admin = { id: number; email: string; totp_enabled: boolean; locked: boolean; created_at: string; last_login_at: string | null };
type Me = { user: { id: number } };

export default function AdminsPage() {
  const { data, error, reload } = useLoad<Admin[]>("/admins");
  const me = useLoad<Me>("/auth/me");
  const act = useAction();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (await act.run(() => post("/admins", { email, password }), `${email} added. They must set up two-factor authentication and change the password at first sign-in.`)) {
      setEmail(""); setPassword(""); reload();
    }
  };
  const remove = async (a: Admin) => {
    if (!confirm(`Remove ${a.email}?`)) return;
    if (await act.run(() => del(`/admins/${a.id}`), `${a.email} removed.`)) reload();
  };
  return (
    <Shell>
      <h1>Administrators</h1>
      <Alert kind="error">{error || act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <div className="panel">
        <h2>Add administrator</h2>
        <p className="muted">Give each NOC engineer their own account. Locked out or lost the authenticator? On the server run
          <code> sudo docker compose -f /opt/isp-netcontrol/src/isp-netcontrol/deploy/docker-compose.yml exec api isp-netcontrol admin reset-password EMAIL</code> (or <code>reset-2fa</code>).</p>
        <form className="stack" onSubmit={add}>
          <label>Email<input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label>Initial password (12+ characters)<input type="password" autoComplete="new-password" minLength={12} required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          <div><button disabled={act.busy}>Add</button></div>
        </form>
      </div>
      <div className="panel table-wrap">
        <table>
          <thead><tr><th>Email</th><th>Two-factor</th><th>Last sign-in</th><th></th></tr></thead>
          <tbody>
            {data?.map((a) => (
              <tr key={a.id}>
                <td>{a.email}</td>
                <td>{a.totp_enabled ? <span className="badge ok">on</span> : <span className="badge warn">pending</span>} {a.locked && <span className="badge bad">locked</span>}</td>
                <td>{fmtTime(a.last_login_at)}</td>
                <td>{me.data?.user.id === a.id ? <span className="muted">your account</span> : <button className="secondary" onClick={() => remove(a)}>Remove</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}
