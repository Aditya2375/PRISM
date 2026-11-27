import { Mark, Reveal } from "./ui";

const STEPS = [
  ["A file is shared", "Asha stores a file and shares it with Ravi. It is encrypted on her machine, the service only ever sees ciphertext, and each device holds its own wrapped copy of the key."],
  ["The phone is lost", "She enrolled the phone as a limited device, so it can never act as an admin. She reports it lost from her laptop and the service blocks it."],
  ["The thief tries", "A request signed by the lost phone is denied and nothing is released. A critical alert names the device, the user, the node and the audit entries behind it."],
  ["The key is replaced", "The next read by Asha or Ravi writes a fresh file key for the remaining devices only."],
  ["Anyone can check", "Every step is a signed, hash-chained audit entry that the standalone verifier checks without the service."],
];

export default function Landing({ onPick }) {
  return (
    <main className="landing" id="top">
      <div className="glow" aria-hidden="true" /><div className="grid-bg" aria-hidden="true" />
      <header className="land-top"><div className="brand"><Mark size={22} /><b>P.R.I.S.M</b></div>
        <span className="muted small">DevForge Yugaantar, Track 4</span></header>
      <section className="hero">
        <Reveal><Mark size={64} draw /></Reveal>
        <Reveal delay={80} as="h1">Cut off a lost device.<br /><span>Then prove it.</span></Reveal>
        <Reveal delay={160} as="p" className="lead">Post-quantum key management for shared files. When a device is lost its access ends on every node, the file key is replaced, an alert says who, where and why, and the record can be checked by someone who does not trust the service.</Reveal>
        <Reveal delay={240} className="choices">
          <button className="choice beam" onClick={() => onPick("admin")}>
            <span className="eyebrow">Operator</span><b>Operator console</b>
            <small>Alerts, devices, files and the signed audit log. Verify the chain.</small><i aria-hidden="true">&rarr;</i>
          </button>
          <button className="choice beam" onClick={() => onPick("user")}>
            <span className="eyebrow">Device holder</span><b>My files and devices</b>
            <small>Upload, download, enrol a device, report one lost. Keys stay on this machine.</small><i aria-hidden="true">&rarr;</i>
          </button>
        </Reveal>
      </section>
      <section className="story" aria-labelledby="sh">
        <h2 id="sh" className="eyebrow">The lost-phone story</h2>
        <ol>{STEPS.map(([t, d], i) => <Reveal as="li" key={t} delay={i * 60}><span className="n">{i + 1}</span><div><b>{t}</b><p>{d}</p></div></Reveal>)}</ol>
        <p className="limits">Honest limits. A lost device keeps whatever it already decrypted. A client that has not pinned a root fingerprint trusts the first one it sees. A stolen device enrolled as admin-capable stays an admin until the operator removes it, so enrol phones as limited. Cluster nodes in this build share one machine and one clock.</p>
      </section>
    </main>
  );
}
