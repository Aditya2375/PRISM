import { useCallback, useEffect, useRef, useState } from "react";
import Shell, { Modal, PageHead, Pill, Table } from "./Shell";
import Limits from "./Limits";
import { clip, fingerprintGroups, labelFor, when } from "./format";
import { toBase64 } from "./api";

const MAX_BYTES = 4 * 1024 * 1024;

export default function UserDash({ api, onSignOut }) {
  const [page, setPage] = useState("overview");
  const [me, setMe] = useState(null);
  const [files, setFiles] = useState([]);
  const [devices, setDevices] = useState([]);
  const [activity, setActivity] = useState([]);
  const [msg, setMsg] = useState({ kind: "", text: "" });
  const [confirm, setConfirm] = useState(null);
  const closeConfirm = useCallback(() => setConfirm(null), []);
  const fileInput = useRef(null);
  const [name, setName] = useState("");
  const [share, setShare] = useState("");
  const [pubText, setPubText] = useState("");
  const [preview, setPreview] = useState(null);
  const [typedFp, setTypedFp] = useState("");
  const [limited, setLimited] = useState(true);

  const fail = useCallback((e) => { setMsg({ kind: "err", text: e.message }); if (e.kind === "auth") onSignOut(); }, [onSignOut]);
  const load = useCallback(async () => {
    try {
      const [m, f, d, a] = await Promise.all([api.get("/me"), api.get("/files"), api.get("/devices"), api.get("/activity?limit=25")]);
      setMe(m); setFiles(f.files ?? []); setDevices(d.devices ?? []); setActivity(a.entries ?? []);
    } catch (e) { fail(e); }
  }, [api, fail]);
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);

  async function upload() {
    const f = fileInput.current?.files?.[0];
    if (!f || !name.trim()) return setMsg({ kind: "err", text: "Choose a file and give it a name." });
    if (f.size > MAX_BYTES) return setMsg({ kind: "err", text: "That file is over 4 MB, the limit of this screen." });
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      await api.post("/files", { file_id: name.trim(), acl: share.split(",").map((s) => s.trim()).filter(Boolean), content_b64: toBase64(bytes) });
      setMsg({ kind: "good", text: "Encrypted on this machine and stored." });
      setName(""); setShare(""); fileInput.current.value = ""; load();
    } catch (e) { fail(e); }
  }
  async function download(id) {
    try {
      const bytes = await api.getBytes("/files/" + encodeURIComponent(id));
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
      const a = document.createElement("a"); a.href = url; a.download = id.replace(/[^A-Za-z0-9._-]/g, "_"); a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { fail(e); }
  }
  async function removeFile(id) {
    setConfirm(null);
    try { await api.post("/files/delete", { file_id: id }); setMsg({ kind: "good", text: `${id} was deleted.` }); load(); } catch (e) { fail(e); }
  }
  async function reportLost(device) {
    setConfirm(null);
    try { await api.post("/devices/lost", { device, reason: "reported from the web screen" }); setMsg({ kind: "good", text: `${device} is now blocked.` }); load(); } catch (e) { fail(e); }
  }
  const parsePub = () => { try { const p = JSON.parse(pubText); return p && typeof p === "object" ? p : null; } catch { return null; } };
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

  const pending = files.filter((f) => f.needs_rotation).length;
  const lostCount = devices.filter((d) => d.status !== "active").length;
  const nav = [
    ["Overview", [["overview", "Overview", "grid"]]],
    ["My data", [["files", "My files", "key"], ["devices", "My devices", "devices", lostCount], ["enrol", "Enrol a device", "verify"]]],
    ["Record", [["activity", "My activity", "logs"], ["limits", "Limits and checks", "help"]]],
  ];
  const groups = fingerprintGroups(preview?.fingerprint);
  const filesTable = (
    <Table headers={["FILE", "KEY EPOCH", "STATE", ""]}>
      {files.map((f) => (<tr key={f.file_id}><td className="ad-mono">{clip(f.file_id, 64)}</td><td>epoch {Number(f.epoch) || 0}</td>
        <td>{f.needs_rotation ? <Pill tone="needs-re-key">re-key pending</Pill> : <Pill tone="active">current</Pill>}</td>
        <td>{f.has_key ? <button className="ad-row-btn" onClick={() => download(f.file_id)}>Download</button> : <span className="ad-note">no key on this device yet</span>}
          {f.can_rotate && <button className="ad-row-btn danger" onClick={() => setConfirm({ title: `Delete ${clip(f.file_id, 40)}?`, text: "It is removed for everyone who can read it. This cannot be undone.", go: () => removeFile(f.file_id), label: "Delete" })}>Delete</button>}</td></tr>))}
    </Table>
  );

  let body;
  if (!me) body = msg.text ? <p className="ad-note err" role="alert">{msg.text}</p> : <div aria-busy="true"><div className="ad-skel" /><div className="ad-skel" /></div>;
  else if (page === "overview") {
    body = (<><PageHead label="DEVICE HOLDER" title={clip(me.user, 48)} desc={`Signed in on ${clip(me.device, 48)} as ${clip(me.role, 16)}. Your keys stay on this machine.`} />
      <div className="ad-stats">{[["Files", files.length, "You can read"], ["Waiting for a new key", pending, "Re-keyed on the next read"], ["Devices", devices.length - lostCount, `${lostCount} blocked`]].map(([t, v, s]) => (
        <div className="ad-stat" key={t}><div>{t}</div><strong>{v}</strong><p>{s}</p></div>))}</div>
      <section className="ad-panel"><div className="ad-panel-title"><h2>My files</h2><button onClick={() => setPage("files")}>Open</button></div>{filesTable}
        {files.length === 0 && <p className="ad-empty">No files yet.</p>}</section></>);
  } else if (page === "files") {
    body = (<><PageHead label="MY DATA" title="My files" desc="Files are encrypted on this machine before they leave it. The service only ever receives ciphertext." />
      <section className="ad-panel">{filesTable}{files.length === 0 && <p className="ad-empty">No files yet. Upload one below.</p>}</section>
      <section className="ad-panel" style={{ marginTop: 14 }}><div className="ad-panel-title"><h2>Upload</h2></div>
        <div className="ad-form"><input ref={fileInput} type="file" aria-label="File to upload" />
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="file name" aria-label="File name" maxLength={64} />
          <input value={share} onChange={(e) => setShare(e.target.value)} placeholder="share with (user names, comma separated)" aria-label="Share with" />
          <div><button className="ad-primary" onClick={upload}>Encrypt and upload</button></div></div></section></>);
  } else if (page === "devices") {
    body = (<><PageHead label="MY DATA" title="My devices" desc="Report a lost device and it loses access at once. Your files are flagged for a new key." />
      <section className="ad-panel"><Table headers={["DEVICE", "STATUS", ""]}>
        {devices.map((d) => (<tr key={d.device} className={d.status !== "active" ? "hl" : ""}><td className="ad-mono">{clip(d.device, 64)}{d.this ? " (this one)" : ""}</td>
          <td><Pill tone={d.status === "active" ? "active" : "lost"}>{clip(d.status, 16)}</Pill></td>
          <td>{d.status !== "active" ? <span className="ad-note">blocked</span>
            : me.role === "admin" && !d.this && !d.limited ? <span className="ad-note">full admin device: removed by another admin or the operator</span>
            : <button className="ad-row-btn danger" onClick={() => setConfirm({ title: `Report ${clip(d.device, 40)} as lost?`, text: "It loses access at once. This cannot be undone from here.", go: () => reportLost(d.device), label: "Report lost" })}>Report lost</button>}</td></tr>))}
      </Table><p className="ad-note">A lost device keeps anything it already decrypted.</p></section></>);
  } else if (page === "enrol") {
    body = (<><PageHead label="MY DATA" title="Enrol a device" desc="The fingerprint is compared by a person, out of band. There is no way to skip the check from this screen." />
      <section className="ad-panel"><div className="ad-form">
        {me.fingerprint && <div><label>Your device fingerprint (a new device pins this as its root)</label><div className="ad-fp"><span>{clip(me.fingerprint, 100)}</span></div></div>}
        <label htmlFor="pub">1. On the new device run keygen and paste the JSON it prints.</label>
        <textarea id="pub" rows={4} value={pubText} onChange={(e) => setPubText(e.target.value)} />
        <div><button className="ad-primary" onClick={doPreview}>Show fingerprint</button></div>
        {groups.length === 8 && (<>
          <label>2. This is the fingerprint of the key you pasted. Read the one on the new device and type it in.</label>
          <div className="ad-fp">{groups.map((g) => <span key={g}>{g}</span>)}</div>
          <input value={typedFp} onChange={(e) => setTypedFp(e.target.value)} placeholder="fingerprint shown on the new device" aria-label="Fingerprint shown on the new device" autoComplete="off" />
          <label><input type="checkbox" checked={limited} onChange={(e) => setLimited(e.target.checked)} style={{ width: 16, display: "inline", marginRight: 8 }} />Limited device (a phone): acts as a plain member, so it can be removed from here if lost.</label>
          <div><button className="ad-primary" onClick={doEnroll}>Compare and enrol</button></div>
          <p className="ad-note">A mismatch is refused.</p></>)}
      </div></section></>);
  } else if (page === "activity") {
    body = (<><PageHead label="RECORD" title="My activity" desc="Entries from the service's audit log that involve you. Newest first." />
      <section className="ad-panel"><Table headers={["TIME (UTC)", "WHAT HAPPENED", "DEVICE"]}>
        {activity.map((e) => (<tr key={e.seq} className={e.type.startsWith("auth.") ? "hl" : ""}><td className="ad-mono">{when(e.ts)}</td>
          <td>{labelFor(e.type)}{e.data?.file ? `: ${clip(e.data.file, 64)}` : ""}</td><td className="ad-mono">{clip(e.data?.device ?? e.actor, 64)}</td></tr>))}
      </Table>{activity.length === 0 && <p className="ad-empty">Nothing yet.</p>}</section></>);
  } else body = <Limits label="RECORD" />;

  return (
    <Shell nav={nav} page={page} setPage={setPage} role={me?.role === "admin" ? "Device holder, admin" : "Device holder"} who={me ? me.user : ""} onSignOut={onSignOut} live="Connected to your local backend" toast={msg.kind === "good" ? msg.text : ""}>
      {msg.kind === "err" && me && <p className="ad-note err" role="alert">{msg.text}</p>}
      {body}
      {confirm && <Modal title={confirm.title} close={closeConfirm}><p className="ad-modal-copy">{confirm.text}</p>
        <footer><button data-autofocus onClick={() => setConfirm(null)}>Cancel</button><button className="ad-danger" onClick={confirm.go}>{confirm.label}</button></footer></Modal>}
    </Shell>
  );
}
