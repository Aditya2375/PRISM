import { PageHead } from "./Shell";

// What this build does not do. Kept next to the console so the screen never reads stronger than the code.
export default function Limits({ label }) {
  return (
    <>
      <PageHead label={label} title="Limits and checks" desc="What the console shows, and what it does not prove." />
      <section className="ad-panel">
        <h2>Limits we state</h2>
        <ul className="ad-list">
          <li>A lost or revoked device keeps everything it already decrypted. Reporting it stops later access and replaces the file key for the remaining devices.</li>
          <li>The root of trust is trusted on first use unless a root fingerprint was pinned out of band.</li>
          <li>The cluster nodes in this build share one machine, one clock and loopback. Sync is plain HTTP and needs TLS between hosts.</li>
          <li>A stolen full admin device is an admin until the host removes it. A limited device (a phone) never acts as an admin.</li>
          <li>Detection is rule based. It catches five kinds of events and misses slow attacks, probing with valid credentials and a valid insider.</li>
          <li>An alert names a device and user only when an enrolled device failed a signature check. Otherwise it says unknown. Treat it as a lead, not proof.</li>
          <li>"Verify chain" is the service checking its own log. For independent proof run <span className="ad-mono">python verifier/prism_verify.py audit</span>.</li>
        </ul>
      </section>
    </>
  );
}
