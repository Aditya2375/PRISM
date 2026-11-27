import { useState } from "react";
import { shakeClassName, useValidationShake } from "./authValidation";
import "./AdminLogin.css";
import "./AuthFormTheme.css";

const COPY = {
  admin: { h: "Operator login", p: "Sign in with the operator token printed when the PRISM service started.", label: "Operator token", probe: "/v1/overview",
    note: "The token stays in this tab's memory only. It is never saved, and it is forgotten after 15 idle minutes." },
  user: { h: "Device holder login", p: "Sign in with the session token printed by the local backend on your machine.", label: "Session token", probe: "/me",
    note: "Your private keys never leave this machine. This page talks to a small backend on 127.0.0.1 that holds them." },
};

export default function TokenLogin({ role, api, onSignedIn }) {
  const c = COPY[role];
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [shakeVersion, retriggerShake] = useValidationShake();
  async function submit(e) {
    e.preventDefault();
    if (!token.trim()) { setError("Enter the token first."); retriggerShake(); return; }
    setBusy(true);
    try { await api.signIn(token.trim(), c.probe); setToken(""); onSignedIn(); }
    catch (err) { setError(err.message); retriggerShake(); }
    finally { setBusy(false); }
  }
  return (
    <main className="login-screen">
      <div className="login-container">
        <div className="login-card">
          <div className="login-brand"><div className="login-brand-header">
            <img src="/images/prism-emblem.png" alt="" className="login-logo" /><h1>P.R.I.S.M</h1></div></div>
          <h2>{c.h}</h2>
          <p className="login-subtitle">{c.p}</p>
          <form onSubmit={submit} noValidate>
            <div className="form-group">
              <label htmlFor="tok">{c.label}</label>
              <input id="tok" type="password" autoComplete="off" spellCheck="false" autoFocus value={token} placeholder="Paste the token"
                className={error ? `auth-invalid ${shakeClassName(shakeVersion)}` : ""} aria-invalid={Boolean(error)} aria-describedby="tok-err"
                onChange={(e) => { setToken(e.target.value); setError(""); }} />
              <small id="tok-err" className="error-message" role="alert">{error}</small>
            </div>
            <button type="submit" className="login-button" disabled={busy}><img src="/images/login-arrow.png" alt="" /><span>{busy ? "Checking" : "Sign In"}</span></button>
          </form>
          <p className="login-subtitle" style={{ marginTop: 18, fontSize: 12 }}>{c.note}</p>
        </div>
      </div>
    </main>
  );
}
