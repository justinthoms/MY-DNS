"use client";

import { FormEvent, useEffect, useState } from "react";
import { get, post, Me } from "@/lib/api";

type Enroll = { secret: string; otpauth_url: string; qr_png: string };

// SignIn walks an administrator through every step the API asks for:
// password, then TOTP enrolment (first time) or verification, then a forced
// password change for new accounts.
export default function SignIn({ product }: { product: string }) {
  const [step, setStep] = useState<Me["next"] | "password" | "loading">("loading");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [enroll, setEnroll] = useState<Enroll | null>(null);
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");

  const advance = (m: Me) => {
    setCode("");
    if (m.next === "ready") window.location.href = "/";
    else setStep(m.next);
  };

  useEffect(() => {
    get<Me>("/auth/me").then(advance).catch(() => setStep("password"));
  }, []);

  useEffect(() => {
    if (step === "totp_enroll" && !enroll) {
      get<Enroll>("/auth/totp/enroll").then(setEnroll).catch((e) => setError(e.message));
    }
  }, [step, enroll]);

  const submit = (fn: () => Promise<Me>) => async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      advance(await fn());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>{product}</h1>
        {error && <div className="alert error" role="alert">{error}</div>}

        {step === "loading" && <p className="muted">Loading…</p>}

        {step === "password" && (
          <form className="stack" onSubmit={submit(() => post<Me>("/auth/login", { email, password }))}>
            <label>Email<input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
            <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            <button disabled={busy}>Sign in</button>
          </form>
        )}

        {step === "totp_verify" && (
          <form className="stack" onSubmit={submit(() => post<Me>("/auth/totp/verify", { code }))}>
            <p className="muted">Enter the 6-digit code from your authenticator app.</p>
            <label>Code<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" required autoFocus value={code} onChange={(e) => setCode(e.target.value)} /></label>
            <button disabled={busy}>Verify</button>
          </form>
        )}

        {step === "totp_enroll" && (
          <form className="stack" onSubmit={submit(() => post<Me>("/auth/totp/enroll", { code }))}>
            <p>Two-factor authentication is required. Scan this code with an authenticator app (Google Authenticator, Authy, 1Password…), then enter the 6-digit code it shows.</p>
            {enroll ? (
              <>
                <img className="qr" src={enroll.qr_png} alt="TOTP QR code" />
                <p className="muted">Can't scan? Enter this key manually: <code>{enroll.secret}</code></p>
              </>
            ) : (
              <p className="muted">Generating…</p>
            )}
            <label>Code<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" required value={code} onChange={(e) => setCode(e.target.value)} /></label>
            <button disabled={busy || !enroll}>Turn on two-factor authentication</button>
          </form>
        )}

        {step === "change_password" && (
          <form
            className="stack"
            onSubmit={(e) => {
              if (newPw !== newPw2) {
                e.preventDefault();
                setError("The new passwords do not match.");
                return;
              }
              return submit(() => post<Me>("/auth/password", { current_password: password, new_password: newPw }))(e);
            }}
          >
            <p>Choose a new password (at least 12 characters) to replace the initial one.</p>
            {!password && (
              <label>Current password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            )}
            <label>New password<input type="password" autoComplete="new-password" minLength={12} required value={newPw} onChange={(e) => setNewPw(e.target.value)} /></label>
            <label>Repeat new password<input type="password" autoComplete="new-password" minLength={12} required value={newPw2} onChange={(e) => setNewPw2(e.target.value)} /></label>
            <button disabled={busy}>Save password</button>
          </form>
        )}
      </div>
    </div>
  );
}
