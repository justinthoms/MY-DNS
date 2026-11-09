// Thin client for the Go API. The session lives in an HttpOnly cookie; the
// CSRF token is kept in memory and sent on every state-changing request.

export const API_BASE = "/api";

let csrfToken = "";

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export type Me = {
  user: { id: number; email: string; totp_enabled: boolean; must_change_password: boolean };
  csrf_token: string;
  next: "ready" | "totp_verify" | "totp_enroll" | "change_password";
};

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  let data: any = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (data && typeof data === "object" && typeof data.csrf_token === "string") csrfToken = data.csrf_token;
  if (!res.ok) {
    const err = new ApiError(res.status, data?.code ?? "error", data?.error ?? `Request failed (${res.status})`);
    if (typeof window !== "undefined" && (err.code === "unauthenticated" || err.code === "mfa_required" || err.code === "password_change_required")) {
      if (!window.location.pathname.startsWith("/login")) window.location.href = "/login";
    }
    throw err;
  }
  return data as T;
}

export const get = <T = any>(p: string) => api<T>("GET", p);
export const post = <T = any>(p: string, b: unknown = {}) => api<T>("POST", p, b);
export const put = <T = any>(p: string, b: unknown = {}) => api<T>("PUT", p, b);
export const del = <T = any>(p: string) => api<T>("DELETE", p);

// Times are shown in the viewer's own time zone (IST in India), labelled
// with the zone name. The API always sends UTC.
const partsFmt = new Intl.DateTimeFormat("en-IN", {
  year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  hourCycle: "h23", timeZoneName: "short",
});
function localParts(d: Date) {
  const p: Record<string, string> = {};
  for (const x of partsFmt.formatToParts(d)) p[x.type] = x.value;
  return p;
}
/** Name of the viewer's time zone, e.g. "IST". */
export const tzName = () => localParts(new Date()).timeZoneName ?? "local time";
/** 2026-11-09 */
export const fmtDate = (s?: string | null) => {
  if (!s) return "—";
  const p = localParts(new Date(s));
  return `${p.year}-${p.month}-${p.day}`;
};
/** 2026-11-09 13:58:10 IST */
export const fmtTime = (s?: string | null) => {
  if (!s) return "—";
  const p = localParts(new Date(s));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second} ${p.timeZoneName ?? ""}`.trim();
};
/** 13:58 / 11-09 13:58 / 11-09, for chart axes. */
export const fmtAxis = (d: Date, withDate: boolean, dateOnly = false) => {
  const p = localParts(d);
  if (dateOnly) return `${p.month}-${p.day}`;
  return withDate ? `${p.month}-${p.day} ${p.hour}:${p.minute}` : `${p.hour}:${p.minute}`;
};
/** 2026-11-09 13:58 IST, for chart tooltips and tables. */
export const fmtMinute = (s: string) => {
  const p = localParts(new Date(s));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute} ${p.timeZoneName ?? ""}`.trim();
};
