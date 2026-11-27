// Everything shown from the API goes through these helpers and is rendered as text by React.
// Never use dangerouslySetInnerHTML, never build a link or a style from API strings.

export function clip(v, n = 200) {
  const s = typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
  // strip control and bidirectional override characters that can disguise text
  const clean = s.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, "\ufffd");
  return clean.length > n ? clean.slice(0, n) + "\u2026" : clean;
}

export function when(ts) {
  if (typeof ts !== "number" || !Number.isFinite(ts)) return "";
  const d = new Date(ts * 1000);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(11, 19);
}

export function shortHash(h) {
  return typeof h === "string" && /^[0-9a-f]{16,}$/.test(h) ? `${h.slice(0, 8)}\u2026${h.slice(-4)}` : "";
}

const LABELS = {
  "service.bootstrapped": "service started, first admin created",
  "device.enrolled": "device enrolled",
  "user.created": "user created",
  "file.created": "file stored",
  "device.lost": "device reported lost",
  "access.granted": "file read",
  "alert.raised": "alert raised",
  "auth.revoked_device_use": "blocked: a lost or revoked device tried to act",
};
export const labelFor = (t) => LABELS[t] ?? clip(t, 64);

export function fingerprintGroups(fp) {
  return typeof fp === "string" && /^[0-9a-f]{8}(-[0-9a-f]{8}){7}$/.test(fp) ? fp.split("-") : [];
}
