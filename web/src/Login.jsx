import { useState } from "react";
import { Mark, Reveal } from "./ui";

const COPY = {
  admin: { h: "Operator console", p: "Sign in with the operator token printed when the service started.", label: "Operator token", probe: "/v1/overview",
    note: "The token stays in this tab's memory only. It is never saved, and it is forgotten after 15 idle minutes." },
  user: { h: "Device holder", p: "Sign in with the session token printed by the local backend on your machine.", label: "Session token", probe: "/me",
    note: "Your private keys never leave this machine. This page talks to a small backend on 127.0.0.1 that holds them." },
};

export default function Login({ role, api, onBack, onSignedIn }) {
  const c = COPY[role];
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault();
    if (!token.trim()) return setError("Enter the token first.");
    setBusy(true);
    try { await api.signIn(token.trim(), c.probe); setToken(""); onSignedIn(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return (
    <main className="center">
      <div className="glow" aria-hidden="true" />
      <Reveal className="login">
        <button className="link" onClick={onBack}>&larr; Back</button>
        <div className="login-brand"><Mark size={30} /><b>P.R.I.S.M</b></div>
        <h1>{c.h}</h1>
        <p className="muted">{c.p}</p>
        <form onSubmit={submit} noValidate>
          <label htmlFor="tok">{c.label}</label>
          <input id="tok" type="password" autoComplete="off" spellCheck="false" autoFocus value={token}
            className={error ? "bad" : ""} aria-describedby="tok-err"
            onChange={(e) => { setToken(e.target.value); setError(""); }} placeholder="Paste the token" />
          <small id="tok-err" className="err-line" role="alert" aria-live="polite">{error}</small>
          <button type="submit" className="btn primary" disabled={busy}>{busy ? "Checking" : "Sign in"}</button>
        </form>
        <p className="fine">{c.note}</p>
      </Reveal>
    </main>
  );
}
