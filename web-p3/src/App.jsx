import { useEffect, useState } from "react";
import "./App.css";
import "./extra.css";
import TokenLogin from "./TokenLogin";
import Selection from "./Selection";
import AdminDash from "./AdminDash";
import UserDash from "./UserDash";
import { operatorApi, userApi } from "./api";

// Addresses are fixed at build time: the operator service and the local user backend.
const SERVICE_URL = import.meta.env.VITE_PRISM_SERVICE ?? "http://127.0.0.1:8443";
const LOCAL_URL = import.meta.env.VITE_PRISM_LOCAL ?? "http://127.0.0.1:8788";
const adminApi = operatorApi(SERVICE_URL);
const localApi = userApi(LOCAL_URL);

export default function App() {
  const [view, setView] = useState("landing"); // landing | select | login
  const [role, setRole] = useState("");        // "admin" | "user"
  const [signedIn, setSignedIn] = useState(false);

  function signOut() { adminApi.signOut(); localApi.signOut(); setSignedIn(false); setRole(""); setView("landing"); }
  function go(v, r = role) { window.history.pushState({}, ""); setView(v); setRole(r); }
  useEffect(() => {
    const back = () => { if (!signedIn) { setView((v) => (v === "login" ? "select" : "landing")); } };
    window.addEventListener("popstate", back);
    return () => window.removeEventListener("popstate", back);
  }, [signedIn]);

  // Idle logout counts pointer and key activity only. Background refreshes do not.
  useEffect(() => {
    if (!signedIn) return undefined;
    const apis = [adminApi, localApi];
    const touch = () => apis.forEach((a) => a.touch());
    const events = ["pointerdown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, touch, { passive: true }));
    const stops = apis.map((a) => a.watch(signOut));
    return () => { events.forEach((e) => window.removeEventListener(e, touch)); stops.forEach((f) => f()); };
  }, [signedIn]); // eslint-disable-line react-hooks/exhaustive-deps

  if (signedIn) return role === "admin" ? <AdminDash api={adminApi} onSignOut={signOut} /> : <UserDash api={localApi} onSignOut={signOut} />;

  const showSelection = view === "select";
  const showLogin = view === "login";
  return (
    <div className={`app-wrapper ${showSelection ? "show-selection" : ""} ${showLogin ? "show-login" : ""}`}>
      <div className="intro-screen">
        <div className="intro-prism"><img src="/images/prism-emblem.png" alt="P.R.I.S.M emblem" /></div>
        <div className="intro-copy">
          <h1>P.R.I.S.M</h1>
          <p>Post-quantum Resilient Identity &amp; Security Management</p>
          <div className="landing-actions">
            <button className="landing-button landing-button-primary" onClick={() => go("select")}>Open console</button>
          </div>
        </div>
      </div>
      <div className="selection-wrapper">
        {showSelection && <Selection onSelect={(r) => go("login", r)} onBack={() => setView("landing")} />}
      </div>
      <div className="login-wrapper">
        {showLogin && <TokenLogin role={role} api={role === "admin" ? adminApi : localApi} onSignedIn={() => setSignedIn(true)} />}
      </div>
    </div>
  );
}
