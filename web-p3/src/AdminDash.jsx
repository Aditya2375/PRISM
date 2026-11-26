import { useCallback, useEffect, useState } from "react";
import Shell, { PageHead, Pill, Table } from "./Shell";
import Limits from "./Limits";
import { clip, labelFor, shortHash, when } from "./format";

const isSecurity = (t) => t.startsWith("auth.") || t === "alert.raised" || t === "device.lost" || t === "device.revoked";

function Identity({ a }) {
  const rows = [["device", a.device], ["user", a.user], ["node", a.service], ["event", a.event], ["source", a.source]];
  return (
    <dl className="ad-ident">
      {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={!v || v === "unknown" ? "dim" : ""}>{clip(v || "unknown", 64)}</dd></div>)}
    </dl>
  );
}

function AlertCard({ a }) {
  const crit = a.severity === "critical";
  return (
    <article className={`ad-alert-card ${crit ? "" : "high"}`}>
      <header><Pill tone={crit ? "critical" : "high"}>{clip(a.severity, 16)}</Pill><b className="ad-mono">{clip(a.rule, 64)}</b>
        <small>evidence: audit {(a.evidence ?? []).map((n) => `#${Number(n)}`).join(", ")}</small></header>
      <p>{clip(a.explanation, 320)}</p>
      <Identity a={a} />
      <small>response: {clip(a.response, 140)}</small>
    </article>
  );
}

export default function AdminDash({ api, onSignOut }) {
  const [page, setPage] = useState("overview");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [verify, setVerify] = useState(null);
  const [checking, setChecking] = useState(false);
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");

  const load = useCallback(async () => {
    try {
      const [overview, alerts, audit] = await Promise.all([api.get("/v1/overview"), api.get("/v1/alerts"), api.get("/v1/audit?limit=100")]);
      setData({ overview, alerts: alerts.alerts ?? [], audit: audit.entries ?? [] });
      setError("");
    } catch (e) { setError(e.message); if (e.kind === "auth") onSignOut(); }
  }, [api, onSignOut]);
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);

  async function runVerify() {
    setChecking(true);
    try { setVerify(await api.get("/v1/audit/verify")); } catch (e) { setError(e.message); } finally { setChecking(false); }
  }

  const alerts = data?.alerts ?? [];
  const devices = Object.entries(data?.overview?.devices ?? {});
  const files = Object.entries(data?.overview?.files ?? {});
  const blocked = devices.filter(([, d]) => d.status !== "active").length;
  const audit = [...(data?.audit ?? [])].reverse();
  const nav = [
    ["Overview", [["overview", "Security overview", "grid"]]],
    ["Inventory", [["devices", "Devices", "devices"], ["files", "Files and keys", "key"]]],
    ["Monitoring", [["alerts", "Alerts", "alert", alerts.length], ["audit", "Audit log", "logs"]]],
    ["Reference", [["limits", "Limits and checks", "help"]]],
  ];
  const stats = [
    ["Users", Object.keys(data?.overview?.users ?? {}).length, "Accounts on this service"],
    ["Active devices", devices.length - blocked, "Allowed to act"],
    ["Blocked devices", blocked, "Lost or revoked"],
    ["Files", files.length, `${files.filter(([, f]) => f.needs_rotation).length} waiting for a new key`],
    ["Audit entries", Number(data?.overview?.audit_len) || 0, "Hash-chained"],
    ["Open alerts", alerts.length, alerts.length ? "Needs review" : "None raised"],
  ];
  const rows = audit.filter((e) => (filter === "all" || (filter === "security" ? isSecurity(e.type) : !isSecurity(e.type)))
    && `${e.type} ${e.actor} ${labelFor(e.type)}`.toLowerCase().includes(q.toLowerCase()));

  let body;
  if (!data) {
    body = error ? <p className="ad-note err" role="alert">{error}</p> : <div aria-busy="true"><div className="ad-skel" /><div className="ad-skel" /></div>;
  } else if (page === "overview") {
    body = (<>
      <PageHead label="OPERATOR CONSOLE" title="Security overview" desc="Live from the PRISM service. Nothing on this page is sample data." right={<Pill tone={alerts.length ? "high" : "active"}>{alerts.length ? `${alerts.length} open alert${alerts.length > 1 ? "s" : ""}` : "No open alerts"}</Pill>} />
      <div className="ad-stats">{stats.map(([t, v, s]) => (
        <div className={`ad-stat ${t === "Open alerts" && v ? "hot" : ""} ${t === "Blocked devices" && v ? "hot" : ""}`} key={t}><div>{t}</div><strong>{v}</strong><p>{s}</p></div>))}</div>
      <div className="ad-two">
        <section className="ad-panel"><div className="ad-panel-title"><h2>Latest alerts</h2><button onClick={() => setPage("alerts")}>View all</button></div>
          {alerts.length === 0 && <p className="ad-empty">No alerts. The detector is watching the audit log.</p>}
          {[...alerts].reverse().slice(0, 4).map((a) => (
            <div className="ad-alert-row" key={a.seq}><i className={a.severity} /><div><b>{clip(a.rule, 48)}</b><p>{clip(a.device || "unknown device", 40)} / {clip(a.user || "unknown user", 40)}</p></div><Pill tone={a.severity === "critical" ? "critical" : "high"}>{clip(a.severity, 12)}</Pill></div>))}
        </section>
        <section className="ad-panel"><div className="ad-panel-title"><h2>Recent activity</h2><button onClick={() => setPage("audit")}>View all</button></div>
          {audit.slice(0, 5).map((e) => (
            <div className="ad-event" key={e.seq}><span>.</span><div><b>{labelFor(e.type)}</b><p>{clip(e.actor, 40)}</p></div><small>{when(e.ts)}</small></div>))}
        </section>
      </div></>);
  } else if (page === "devices") {
    body = (<><PageHead label="INVENTORY" title="Devices" desc="Every enrolled device and whether it may act." />
      <section className="ad-panel"><Table headers={["DEVICE", "USER", "STATUS"]}>
        {devices.map(([id, d]) => (<tr key={id} className={d.status !== "active" ? "hl" : ""}><td className="ad-mono">{clip(id, 64)}</td><td>{clip(d.user, 64)}</td><td><Pill tone={d.status === "active" ? "active" : "lost"}>{clip(d.status, 16)}</Pill></td></tr>))}
      </Table>{devices.length === 0 && <p className="ad-empty">No devices yet.</p>}</section></>);
  } else if (page === "files") {
    body = (<><PageHead label="INVENTORY" title="Files and keys" desc="The service stores ciphertext and wrapped keys only. A file whose key must be replaced is re-keyed on its next authorised read." />
      <section className="ad-panel"><Table headers={["FILE", "KEY EPOCH", "SHARED WITH", "STATE"]}>
        {files.map(([id, f]) => (<tr key={id}><td className="ad-mono">{clip(id, 64)}</td><td className="ad-mono">{Number(f.epoch) || 0}</td><td>{(f.acl ?? []).map((u) => clip(u, 32)).join(", ")}</td>
          <td>{f.needs_rotation ? <Pill tone="needs-re-key">needs re-key</Pill> : <Pill tone="active">current</Pill>}</td></tr>))}
      </Table>{files.length === 0 && <p className="ad-empty">No files stored yet.</p>}</section></>);
  } else if (page === "alerts") {
    body = (<><PageHead label="MONITORING" title="Alerts" desc="Rule-based and explainable. Each alert points at the audit entries behind it." />
      {alerts.length === 0 && <section className="ad-panel"><p className="ad-empty">No alerts. The detector is watching the audit log.</p></section>}
      {[...alerts].reverse().map((a) => <AlertCard key={a.seq} a={a} />)}</>);
  } else if (page === "audit") {
    body = (<><PageHead label="MONITORING" title="Audit log" desc="Append-only and hash-chained. Newest first."
      right={<button className="ad-primary" onClick={runVerify} disabled={checking}>{checking ? "Checking" : "Verify chain"}</button>} />
      {verify && <div className="ad-callout" role="status">{verify.ok ? `Chain verified by the service. Head ${shortHash(verify.head)}. This is the service checking itself. For independent proof run python verifier/prism_verify.py audit.` : `Chain check failed: ${clip(verify.reason, 160)}`}</div>}
      <section className="ad-panel"><div className="ad-filters"><input placeholder="Search type or actor" aria-label="Search the log" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={filter} aria-label="Filter" onChange={(e) => setFilter(e.target.value)}><option value="all">All events</option><option value="security">Security</option><option value="admin">Administration</option></select>
        <small>{rows.length} shown</small></div>
        <Table headers={["#", "TIME (UTC)", "TYPE", "ACTOR", "WHAT HAPPENED", "HASH"]}>
          {rows.map((e) => (<tr key={e.seq} className={isSecurity(e.type) ? "hl" : ""}><td className="ad-mono">{Number(e.seq)}</td><td className="ad-mono">{when(e.ts)}</td><td className="ad-mono">{clip(e.type, 48)}</td><td>{clip(e.actor, 64)}</td><td>{labelFor(e.type)}</td><td className="ad-mono">{shortHash(e.hash)}</td></tr>))}
        </Table>{rows.length === 0 && <p className="ad-empty">Nothing matches.</p>}</section></>);
  } else {
    body = <Limits label="REFERENCE" />;
  }
  return <Shell nav={nav} page={page} setPage={setPage} role="Operator console" who="operator token" onSignOut={onSignOut} live={error ? "Service not reachable" : "Connected to the service"}>
    {error && data && <p className="ad-note err" role="alert">{error}</p>}{body}</Shell>;
}
