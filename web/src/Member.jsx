import { useCallback, useEffect, useRef, useState } from "react";
import { Card, Pill, TopBar } from "./ui";
import { clip, fingerprintGroups, labelFor, when } from "./format";
import { toBase64 } from "./api";

const MAX_BYTES = 4 * 1024 * 1024;

export default function Member({ api, onSignOut }) {
  const [me, setMe] = useState(null);
  const [files, setFiles] = useState([]);
  const [devices, setDevices] = useState([]);
  const [activity, setActivity] = useState([]);
  const [msg, setMsg] = useState({ kind: "", text: "" });
  const fileInput = useRef(null);
  const [name, setName] = useState("");
  const [share, setShare] = useState("");
  const [pubText, setPubText] = useState("");
  const [preview, setPreview] = useState(null);
  const [typedFp, setTypedFp] = useState("");
  const [limited, setLimited] = useState(true);

  const fail = useCallback((e) => {
    setMsg({ kind: "err", text: e.message });
    if (e.kind === "auth") onSignOut();
  }, [onSignOut]);

  const load = useCallback(async () => {
    try {
      const [m, f, d, a] = await Promise.all([api.get("/me"), api.get("/files"), api.get("/devices"), api.get("/activity?limit=10")]);
      setMe(m); setFiles(f.files ?? []); setDevices(d.devices ?? []); setActivity(a.entries ?? []);
    } catch (e) { fail(e); }
  }, [api, fail]);

  useEffect(() => { load(); }, [load]);

  async function upload() {
    const f = fileInput.current?.files?.[0];
    if (!f || !name.trim()) return setMsg({ kind: "err", text: "Choose a file and give it a name." });
    if (f.size > MAX_BYTES) return setMsg({ kind: "err", text: "That file is too large (limit 4 MB)." });
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      await api.post("/files", { file_id: name.trim(), acl: share.split(",").map((s) => s.trim()).filter(Boolean), content_b64: toBase64(bytes) });
      setMsg({ kind: "good", text: "Encrypted on this machine and stored." });
      setName(""); setShare(""); fileInput.current.value = "";
      load();
    } catch (e) { fail(e); }
  }

  async function download(id) {
    try {
      const bytes = await api.getBytes("/files/" + encodeURIComponent(id));
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url; a.download = id.replace(/[^A-Za-z0-9._-]/g, "_"); a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { fail(e); }
  }

  async function removeFile(id) {
    if (!window.confirm(`Delete ${id} for everyone who can read it? This cannot be undone.`)) return;
    try { await api.post("/files/delete", { file_id: id }); setMsg({ kind: "good", text: `${id} was deleted.` }); load(); }
    catch (e) { fail(e); }
  }

  async function reportLost(device) {
    if (!window.confirm(`Report ${device} as lost? It loses access at once and your files are flagged for re-keying.`)) return;
    try { await api.post("/devices/lost", { device, reason: "reported from the web screen" }); setMsg({ kind: "good", text: `${device} is now blocked.` }); load(); }
    catch (e) { fail(e); }
  }

  function parsePub() {
    try { const p = JSON.parse(pubText); return p && typeof p === "object" ? p : null; } catch { return null; }
  }
  async function doPreview() {
    const pub = parsePub();
    if (!pub) return setMsg({ kind: "err", text: "Paste the JSON that `keygen` printed on the new device." });
    try { setPreview(await api.post("/devices/preview", { pub })); setMsg({ kind: "", text: "" }); } catch (e) { fail(e); }
  }
  async function doEnroll() {
    try {
      await api.post("/devices/enroll", { pub: parsePub(), expect_fingerprint: typedFp.trim(), limited });
      setMsg({ kind: "good", text: "Device enrolled with a verified fingerprint." });
      setPreview(null); setPubText(""); setTypedFp(""); load();
    } catch (e) { fail(e); }
  }

  if (!me) {
    return (
      <main className="dash"><Head title="Member console" right={null} />
        {msg.text ? <p className="err" role="alert">{msg.text}</p> : <div className="skel" aria-busy="true" aria-label="Connecting to the local backend"><i /><i /><i /></div>}
      </main>);
  }
  const groups = fingerprintGroups(preview?.fingerprint);

  return (
    <main className="dash">
      <Head title={me.role === "admin" ? "Admin" : "Member"} right={<button className="ghost" onClick={onSignOut}>Sign out</button>} />
      <div style={{ marginBottom: 24 }}><h1>{clip(me.user, 64)}</h1>
        <div className="note" style={{ margin: 0 }}>signed in on <span className="mono">{clip(me.device, 64)}</span> as {clip(me.role, 16)}. Keys stay on this machine.</div></div>
      {msg.text && <p className={msg.kind} role={msg.kind === "err" ? "alert" : "status"}>{msg.text}</p>}

      <div className="grid">
        <section className="card"><h2>My files</h2>
          <table className="files-table"><thead><tr><th>File</th><th>Version</th><th>State</th><th /></tr></thead><tbody>
            {files.map((f) => (
              <tr key={f.file_id}><td className="mono">{clip(f.file_id, 64)}</td><td>epoch {Number(f.epoch) || 0}</td>
                <td>{f.needs_rotation ? <span className="pill warn">re-key pending</span> : <span className="pill ok">current</span>}</td>
                <td className="actions">{f.has_key ? <button className="ghost" onClick={() => download(f.file_id)}>Download</button> : <span className="note">no key on this device yet</span>}
                  {f.can_rotate && <button className="ghost danger" onClick={() => removeFile(f.file_id)}>Delete</button>}</td></tr>))}
          </tbody></table>
          {files.length === 0 && <div className="empty">No files yet. Upload one and it is encrypted here first.</div>}
        </section>
        <section className="card"><h2>Upload</h2>
          <div className="row"><input ref={fileInput} type="file" aria-label="File to upload" /></div>
          <div className="row" style={{ marginTop: 10 }}>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="file name" aria-label="File name" maxLength={64} />
            <input value={share} onChange={(e) => setShare(e.target.value)} placeholder="share with (user names, comma separated)" aria-label="Share with" style={{ flex: 1 }} />
          </div>
          <div style={{ marginTop: 12 }}><button onClick={upload}>Encrypt and upload</button></div>
          <p className="note">The file is encrypted on this machine. The server only ever receives ciphertext.</p>
        </section>
      </div>

      <div className="grid">
        <section className="card"><h2>My devices</h2>
          <table><thead><tr><th>Device</th><th>Status</th><th /></tr></thead><tbody>
            {devices.map((d) => (
              <tr key={d.device} className={d.status !== "active" ? "hl" : ""}><td className="mono">{clip(d.device, 64)}{d.this ? " (this one)" : ""}</td>
                <td><span className={`pill ${d.status === "active" ? "active" : "lost"}`}>{clip(d.status, 16)}</span></td>
                <td>{d.status !== "active" ? <span className="note">blocked</span>
                  : me.role === "admin" && !d.this && !d.limited ? <span className="note">full admin device: removed by another admin or the operator</span>
                  : <button className="danger" onClick={() => reportLost(d.device)}>Report lost</button>}</td></tr>))}
          </tbody></table>
          <p className="note">A lost device keeps anything it already decrypted. Reporting it stops all later access.{me.role === "admin" && " Phones enrolled as limited can be removed here. A full admin device is removed by another admin, or offline by the operator with kig revoke-device, so a stolen device cannot lock you out."}</p>
        </section>
        {me.role === "admin" && (
          <section className="card"><h2>Enrol a new device</h2>
            {me.fingerprint && (
              <div className="rootbox"><small>Your device fingerprint (a new device pins this as its root)</small>
                <span className="mono">{clip(me.fingerprint, 100)}</span></div>)}
            <p className="note" style={{ marginTop: 0 }}>Give that fingerprint to the new device’s owner by voice or in person, never through this service. 1. On the new device run keygen and paste the JSON it prints. 2. Read the fingerprint it shows on its own screen and type it here.</p>
            <textarea value={pubText} onChange={(e) => setPubText(e.target.value)} rows={3} style={{ width: "100%" }} aria-label="New device public data" />
            <div style={{ margin: "8px 0" }}><button className="ghost" onClick={doPreview}>Show fingerprint</button></div>
            {groups.length === 8 && (<>
              <div className="fp mono">{groups.map((g) => <span key={g}>{g}</span>)}</div>
              <div className="row"><input className="mono" value={typedFp} onChange={(e) => setTypedFp(e.target.value)} placeholder="fingerprint shown on the new device" aria-label="Fingerprint shown on the new device" style={{ flex: 1 }} autoComplete="off" />
                <button onClick={doEnroll}>Compare and enrol</button></div>
              <label className="note" style={{ display: "flex", gap: 10, alignItems: "center", cursor: "pointer" }}>
                <input type="checkbox" checked={limited} onChange={(e) => setLimited(e.target.checked)} style={{ width: 16, height: 16, padding: 0 }} />
                Limited device (a phone): acts as a plain member, so you can remove it from here if it is lost.</label>
              <p className="note">A mismatch is refused. There is no way to skip the check from this screen.</p></>)}
          </section>)}
      </div>

      <section className="card"><h2>My recent activity</h2>
        <table><thead><tr><th>Time</th><th>What happened</th><th>Device</th></tr></thead><tbody>
          {activity.map((e) => (
            <tr key={e.seq} className={e.type.startsWith("auth.") ? "hl" : ""}><td className="mono">{when(e.ts)}</td><td>{labelFor(e.type)}{e.data?.file ? `: ${clip(e.data.file, 64)}` : ""}</td><td className="mono">{clip(e.data?.device ?? e.actor, 64)}</td></tr>))}
        </tbody></table>
        {activity.length === 0 && <div className="empty">Nothing yet.</div>}
      </section>
    </main>
  );
}
