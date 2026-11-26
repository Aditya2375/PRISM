import "./Selection.css";
import { Icon } from "./Shell";

export default function Selection({ onSelect, onBack }) {
  return (
    <main className="selection-screen">
      <div className="selection-container">
        <h1>Welcome to P.R.I.S.M</h1>
        <p className="selection-subtitle">Choose the console you want to open.</p>
        <div className="selection-options">
          <button className="selection-card" onClick={() => onSelect("user")}>
            <span className="selection-icon"><Icon name="devices" /></span><h2>Device holder</h2>
            <p>Your files and devices. Upload, download, enrol a device, report one lost.</p>
          </button>
          <button className="selection-card" onClick={() => onSelect("admin")}>
            <span className="selection-icon"><Icon name="verify" /></span><h2>Operator</h2>
            <p>Alerts, devices, files and the signed audit log.</p>
          </button>
        </div>
        <div className="selection-back"><button onClick={onBack}>Back</button></div>
      </div>
    </main>
  );
}
