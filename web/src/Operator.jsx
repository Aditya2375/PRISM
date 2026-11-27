import { useCallback, useEffect, useRef, useState } from "react";
import { Card, Count, Pill, Reveal, TopBar } from "./ui";
import { clip, labelFor, shortHash, when } from "./format";

const FILTERS = [["all", "All"], ["security", "Security"], ["admin", "Administration"]];
const isSecurity = (t) => t.startsWith("auth.") || t === "alert.raised" || t === "device.lost" || t === "device.revoked";
const isAdmin = (t) => t.startsWith("user.") || t.startsWith("role.") || t.startsWith("device.") || t.startsWith("service.");

function Identity({ a }) {
  const rows = [["device", a.device], ["user", a.user], ["node", a.service], ["event", a.event], ["source", a.source]];
  return (
    <dl className="ident">
      {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={v === "unknown" || !v ? "dim" : ""}>{clip(v || "unknown", 64)}</dd></div>)}
    </dl>
  );
}

export default function Operator({ api, onSignOut }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [verify, setVerify] = useState(null);
  const [checking, setChecking] = useState(false);
  const [filter, setFilter] = useState("all");
  const seen = useRef(null);

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
    try { setVerify(await api.get("/v1/audit/verify")); } catch (e) { setError(e.message); }
    finally { setChecking(false); }
  }
  const out = <button className="btn ghost" onClick={onSignOut}>Sign out</button>;
  if (!data) {
    return (<><TopBar title="Operator console" right={out} />
      <main className="page">{error ? <p className="notice err" role="alert">{error}</p> : <div className="skel" aria-busy="true" aria-label="Loading"><i /><i /><i /></div>}</main></>);
  }
  const { overview, alerts, audit } = data;
  const devices = Object.entries(overview.devices ?? {});
  const files = Object.entries(overview.files ?? {});
  const lost = devices.filter(([, d]) => d.status !== "active").length;
  const top = audit.reduce((m, e) => Math.max(m, Number(e.seq) || 0), 0);
  const from = seen.current; seen.current = top;
  const rows = [...audit].reverse().filter((e) => filter === "all" || (filter === "security" ? isSecurity(e.type) : isAdmin(e.type) && !isSecurity(e.type)));

  const stats = [
    ["Users", Object.keys(overview.users ?? {}).length, ""],
    ["Active devices", devices.length - lost, ""],
    ["Blocked devices", lost, lost ? "bad" : ""],
    ["Files", files.length, ""],
    ["Audit entries", Number(overview.audit_len) || 0, ""],
    ["Open alerts", alerts.length, alerts.length ? "bad" : ""],
  ];
  return (
    <>
      <TopBar title="Operator console" nav={[["overview", "Overview"], ["alerts", "Alerts"], ["inventory", "Devices and files"], ["audit", "Audit log"]]}
        right={<><span className="live"><i />live, every 5 s</span>{out}</>} />
      <main className="page" id="top">
        {error && <p className="notice err" role="alert">{error}</p>}
        <section id="overview" className="stats" aria-label="Overview">
          {stats.map(([l, v, t], i) => (
            <Reveal key={l} delay={i * 40} className={`stat ${t}`}><b><Count value={v} /></b><span>{l}</span></Reveal>))}
        </section>

        <Card id="alerts" title="Alerts" tone={alerts.length ? "hot" : ""}
          aside={<span className="muted small">{alerts.length ? `${alerts.length} open` : "none"}</span>}>
          {alerts.length === 0 ? <p className="empty">No alerts. The detector is watching the audit log.</p> :
            [...alerts].reverse().map((a) => (
              <article key={a.seq} className={`alert ${a.severity === "critical" ? "crit" : ""}`}>
                <div className="alert-h"><Pill tone={a.severity === "critical" ? "crit" : "warn"}>{clip(a.severity, 16)}</Pill>
                  <b className="mono">{clip(a.rule, 64)}</b>
                  <span className="muted small">evidence: audit {(a.evidence ?? []).map((n) => `#${Number(n)}`).join(", ")}</span></div>
                <p>{clip(a.explanation, 320)}</p>
                <Identity a={a} />
                <div className="muted small">response: {clip(a.response, 140)}</div>
              </article>))}
        </Card>

        <div className="two" id="inventory">
          <Card title="Devices">
            <table><thead><tr><th>Device</th><th>User</th><th>Status</th></tr></thead><tbody>
              {devices.map(([id, d]) => (
                <tr key={id} className={d.status !== "active" ? "hl" : ""}><td className="mono">{clip(id, 64)}</td><td>{clip(d.user, 64)}</td>
                  <td><Pill tone={d.status === "active" ? "ok" : "crit"}>{clip(d.status, 16)}</Pill></td></tr>))}
            </tbody></table>
            {devices.length === 0 && <p className="empty">No devices yet.</p>}
          </Card>
          <Card title="Files">
            <table><thead><tr><th>File</th><th>Epoch</th><th>Shared with</th><th>State</th></tr></thead><tbody>
              {files.map(([id, f]) => (
                <tr key={id}><td className="mono">{clip(id, 64)}</td><td className="mono">{Number(f.epoch) || 0}</td>
                  <td>{(f.acl ?? []).map((u) => clip(u, 32)).join(", ")}</td>
                  <td>{f.needs_rotation ? <Pill tone="warn">needs re-key</Pill> : <Pill tone="ok">current</Pill>}</td></tr>))}
            </tbody></table>
            {files.length === 0 && <p className="empty">No files stored yet.</p>}
          </Card>
        </div>

        <Card id="audit" title="Audit log" aside={
          <div className="row">
            <div className="seg" role="group" aria-label="Filter the log">{FILTERS.map(([k, l]) => <button key={k} aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>)}</div>
            <button className="btn primary" onClick={runVerify} disabled={checking}>{checking ? "Checking" : "Verify chain"}</button>
          </div>}>
          {verify && (
            <p className={`notice ${verify.ok ? "good" : "err"}`} role="status">
              {verify.ok ? `Chain verified by the service. Head ${shortHash(verify.head)}.` : `Chain check failed: ${clip(verify.reason, 160)}`}
              {verify.ok && <span className="muted"> This is the service checking itself. For independent proof run verifier/prism_verify.py audit.</span>}
            </p>)}
          <div className="scroll"><table><thead><tr><th>#</th><th>Time</th><th>Type</th><th>Actor</th><th>What happened</th><th>Hash</th></tr></thead><tbody>
            {rows.map((e) => (
              <tr key={e.seq} className={`${isSecurity(e.type) ? "hl" : ""} ${from !== null && Number(e.seq) > from ? "fresh" : ""}`}>
                <td className="mono">{Number(e.seq)}</td><td className="mono">{when(e.ts)}</td><td className="mono">{clip(e.type, 48)}</td>
                <td>{clip(e.actor, 64)}</td><td>{labelFor(e.type)}</td><td className="mono dim">{shortHash(e.hash)}</td></tr>))}
          </tbody></table></div>
          {rows.length === 0 && <p className="empty">Nothing matches this filter.</p>}
        </Card>
      </main>
    </>
  );
}
