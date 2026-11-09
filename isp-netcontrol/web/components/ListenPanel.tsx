"use client";

import { useEffect, useState } from "react";
import { put } from "@/lib/api";
import { Alert, useAction, useLoad } from "./ui";

type Iface = { name: string; up: boolean; loopback: boolean; addrs: string[]; default_route: boolean; internal: boolean };
type Settings = { mode: "all" | "selected"; interfaces: string[]; addresses: string[]; port: number };
type Resp = { settings: Settings; saved: boolean; active: string[]; env_default: string[]; interfaces: Iface[] };

const ipOf = (cidr: string) => cidr.split("/")[0];
const linkLocal = (ip: string) => ip.toLowerCase().startsWith("fe80:");

// ListenPanel chooses the interfaces and addresses DNS is served on.
export default function ListenPanel() {
  const { data, error, reload } = useLoad<Resp>("/dns/listen");
  const act = useAction();
  const [s, setS] = useState<Settings | null>(null);
  const [showInternal, setShowInternal] = useState(false);
  useEffect(() => {
    if (data) setS({ ...data.settings, interfaces: data.settings.interfaces ?? [], addresses: data.settings.addresses ?? [] });
  }, [data]);
  if (!data || !s) return <div className="panel"><h2>Listen on</h2><Alert kind="error">{error}</Alert></div>;

  const toggleIface = (n: string) => setS({ ...s, interfaces: s.interfaces.includes(n) ? s.interfaces.filter((x) => x !== n) : [...s.interfaces, n] });
  const toggleAddr = (ip: string) => setS({ ...s, addresses: s.addresses.includes(ip) ? s.addresses.filter((x) => x !== ip) : [...s.addresses, ip] });
  const save = () => act.run(() => put("/dns/listen", s), "DNS now listens on the new addresses.").then((ok) => ok && reload());
  const shown = data.interfaces.filter((i) => showInternal || !i.internal);

  return (
    <div className="panel">
      <h2>Listen on</h2>
      <p className="muted">
        Choose where subscribers reach this DNS server. Changes apply immediately; if an address cannot be used, the previous ones are kept.
        When an interface is selected, addresses added to it later (for example a new anycast IP) are picked up within a minute.
      </p>
      <Alert kind="error">{act.error}</Alert>
      <Alert kind="success">{act.ok}</Alert>
      <div className="stack" style={{ maxWidth: 820 }}>
        <label className="check"><input type="radio" name="mode" checked={s.mode === "all"} onChange={() => setS({ ...s, mode: "all" })} />All addresses of this server</label>
        <label className="check"><input type="radio" name="mode" checked={s.mode === "selected"} onChange={() => setS({ ...s, mode: "selected" })} />Only the interfaces and addresses selected below</label>
        {s.mode === "selected" && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Interface</th><th>Whole interface</th><th>Or single addresses</th></tr></thead>
              <tbody>
                {shown.map((i) => {
                  const whole = s.interfaces.includes(i.name);
                  return (
                    <tr key={i.name} style={{ opacity: i.up ? 1 : 0.55 }}>
                      <td>
                        <span className="mono">{i.name}</span>{" "}
                        {!i.up && <span className="badge warn">down</span>}{" "}
                        {i.default_route && <span className="badge muted">default route</span>}{" "}
                        {i.loopback && <span className="badge muted">loopback</span>}
                      </td>
                      <td><input type="checkbox" aria-label={`All addresses of ${i.name}`} checked={whole} disabled={i.addrs.filter((a) => !linkLocal(ipOf(a))).length === 0} onChange={() => toggleIface(i.name)} /></td>
                      <td>
                        {i.addrs.filter((a) => !linkLocal(ipOf(a))).map((a) => (
                          <label key={a} className="check" style={{ fontSize: 13 }}>
                            <input type="checkbox" checked={whole || s.addresses.includes(ipOf(a))} disabled={whole} onChange={() => toggleAddr(ipOf(a))} />
                            <span className="mono">{a}</span>
                          </label>
                        ))}
                        {i.addrs.filter((a) => !linkLocal(ipOf(a))).length === 0 && <span className="muted">no usable address</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <label className="check" style={{ marginTop: 8, fontSize: 13 }}>
              <input type="checkbox" checked={showInternal} onChange={(e) => setShowInternal(e.target.checked)} />Show Docker and bridge interfaces
            </label>
          </div>
        )}
        <div className="row">
          <label style={{ width: 120 }}>Port<input type="number" min={1} max={65535} value={s.port} onChange={(e) => setS({ ...s, port: Number(e.target.value) })} /></label>
          <button type="button" disabled={act.busy} onClick={save}>Apply</button>
        </div>
        <p className="muted" style={{ margin: 0 }}>
          Listening now on: <span className="mono">{data.active.join(", ") || "—"}</span>
          {!data.saved && <> (from the installer: <span className="mono">{data.env_default.join(", ")}</span>)</>}
        </p>
      </div>
    </div>
  );
}
