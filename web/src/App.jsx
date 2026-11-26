import { useEffect, useState } from "react";
import Landing from "./Landing";
import Login from "./Login";
import Operator from "./Operator";
import Member from "./Member";
import { operatorApi, userApi } from "./api";

// Addresses are fixed at build time: the operator service and the local user backend.
const SERVICE_URL = import.meta.env.VITE_PRISM_SERVICE ?? "http://127.0.0.1:8443";
const LOCAL_URL = import.meta.env.VITE_PRISM_LOCAL ?? "http://127.0.0.1:8788";
const adminApi = operatorApi(SERVICE_URL);
const localApi = userApi(LOCAL_URL);

export default function App() {
  const [role, setRole] = useState("");        // "", "admin", "user"
  const [signedIn, setSignedIn] = useState(false);

  function signOut() {
    adminApi.signOut(); localApi.signOut();
    setSignedIn(false); setRole("");
  }
  function pick(r) { window.history.pushState({}, ""); setRole(r); window.scrollTo(0, 0); }
  useEffect(() => {
    const back = () => { if (!signedIn) setRole(""); };
    window.addEventListener("popstate", back);
    return () => window.removeEventListener("popstate", back);
  }, [signedIn]);

  if (!role) return <Landing onPick={pick} />;
  if (!signedIn) {
    return <Login role={role} api={role === "admin" ? adminApi : localApi} onBack={() => setRole("")} onSignedIn={() => setSignedIn(true)} />;
  }
  return role === "admin" ? <Operator api={adminApi} onSignOut={signOut} /> : <Member api={localApi} onSignOut={signOut} />;
}
