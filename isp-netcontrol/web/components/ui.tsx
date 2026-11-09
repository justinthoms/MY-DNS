"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError, get, post, Me } from "@/lib/api";

const NAV = [
  { href: "/", label: "Dashboard" },
  { href: "/dns", label: "DNS filtering" },
  { href: "/records", label: "DNS records" },
  { href: "/querylog", label: "Query log" },
  { href: "/firewall", label: "Firewall" },
  { href: "/settings", label: "DNS settings" },
  { href: "/anycast", label: "Anycast" },
  { href: "/license", label: "License" },
  { href: "/admins", label: "Administrators" },
  { href: "/audit", label: "Audit log" },
];

// Shell checks the session and renders the navigation around a page.
export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    get<Me>("/auth/me")
      .then((m) => {
        if (m.next !== "ready") window.location.href = "/login";
        else setMe(m);
      })
      .catch(() => (window.location.href = "/login"));
  }, []);
  if (!me) return <div className="auth-page muted">Loading…</div>;
  const logout = async () => {
    await post("/auth/logout").catch(() => {});
    window.location.href = "/login";
  };
  return (
    <div className="layout">
      <nav className="nav">
        <div className="brand">ISP NetControl</div>
        {NAV.map((n) => (
          <Link key={n.href} href={n.href} className={(n.href === "/" ? path === "/" : path.startsWith(n.href)) ? "active" : ""}>
            {n.label}
          </Link>
        ))}
        <div className="spacer" />
        <div className="who">{me.user.email}</div>
        <a href="#" onClick={(e) => { e.preventDefault(); logout(); }}>Sign out</a>
      </nav>
      <main className="main">{children}</main>
    </div>
  );
}

// useLoad fetches data for a page and exposes a reload function.
export function useLoad<T>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [code, setCode] = useState("");
  const reload = useCallback(() => {
    if (!path) return;
    get<T>(path)
      .then((d) => { setData(d); setError(""); setCode(""); })
      .catch((e: ApiError) => { setError(e.message); setCode(e.code); });
  }, [path]);
  useEffect(reload, [reload]);
  // licensed is false when the feature behind this page is not licensed.
  return { data, error: code === "license_required" ? "" : error, licenseError: code === "license_required" ? error : "", reload };
}

export function Alert({ kind, children }: { kind: "error" | "success" | "warn"; children: ReactNode }) {
  if (!children) return null;
  return <div className={`alert ${kind}`} role={kind === "error" ? "alert" : "status"}>{children}</div>;
}

// useAction wraps a mutation with busy/error/success state.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const run = async (fn: () => Promise<unknown>, success = "") => {
    setBusy(true); setError(""); setOk("");
    try {
      await fn();
      setOk(success);
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, ok, run, setError };
}

// LicenseRequired explains a 402 answer and links to the License page.
export function LicenseRequired({ message }: { message: string }) {
  return (
    <div className="alert warn">
      {message} <Link href="/license">Go to License</Link>
    </div>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const cls = status === "active" ? "ok" : status === "expired" ? "warn" : status === "revoked" ? "bad" : "muted";
  return <span className={`badge ${cls}`}>{status}</span>;
}
