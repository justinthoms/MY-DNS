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

export const fmtDate = (s?: string | null) => (s ? new Date(s).toISOString().slice(0, 10) : "—");
export const fmtTime = (s?: string | null) => (s ? new Date(s).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "—");
