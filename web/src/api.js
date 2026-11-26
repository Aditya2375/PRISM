// Thin client for the PRISM service (operator side) and the local user backend (device-holder side).
// The token lives in a closure variable only: never in storage, a cookie, the URL or the DOM.

const OPERATOR_HEADER = "X-KIG-Operator-Token";
const SESSION_HEADER = "X-PRISM-Session";
const TIMEOUT_MS = 8000;
const IDLE_MS = 15 * 60 * 1000;

export class ApiError extends Error {
  constructor(kind, message, status = 0) {
    super(message);
    this.kind = kind; // "auth" | "denied" | "refused" | "network" | "bad_reply"
    this.status = status;
  }
}

function words(status, body) {
  const reason = body && typeof body.reason === "string" ? body.reason.slice(0, 200) : "";
  if (status === 401) return new ApiError("auth", "The token was not accepted.", status);
  if (status === 403) return new ApiError("denied", reason || "You are not allowed to do that.", status);
  if (status === 409) return new ApiError("denied", reason || "That conflicts with the current state.", status);
  if (status === 422) return new ApiError("refused", reason || "This device refused the data it received.", status);
  if (status === 502) return new ApiError("network", "The PRISM service did not answer.", status);
  return new ApiError("denied", reason || `The request failed (${status}).`, status);
}

export function createApi({ baseUrl, headerName, now = () => Date.now(), fetchImpl = (...a) => globalThis.fetch(...a), idleMs = IDLE_MS }) {
  if (!/^https?:\/\/[^/?#]+$/.test(baseUrl)) throw new Error("baseUrl must be an origin such as http://127.0.0.1:8443");
  let token = null;
  let last = 0;

  function expired() {
    return token !== null && now() - last > idleMs;
  }

  async function request(method, path, { json, raw = false } = {}) {
    if (token === null || expired()) {
      token = null;
      throw new ApiError("auth", "Signed out. Enter the token again.");
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    let res;
    try {
      res = await fetchImpl(baseUrl + path, {
        method,
        headers: { [headerName]: token, ...(json !== undefined ? { "Content-Type": "application/json" } : {}) },
        body: json !== undefined ? JSON.stringify(json) : undefined,
        signal: ctl.signal,
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch {
      throw new ApiError("network", "Could not reach the server. Is it running?");
    } finally {
      clearTimeout(timer);
    }
    last = now();
    if (!res.ok) {
      let body = null;
      try { body = await res.json(); } catch { /* not JSON */ }
      const err = words(res.status, body);
      if (err.kind === "auth") token = null;
      throw err;
    }
    if (raw) return new Uint8Array(await res.arrayBuffer());
    try { return await res.json(); } catch { throw new ApiError("bad_reply", "The server sent an unreadable reply."); }
  }

  return {
    // Sets the token, then proves it with one call; a wrong token is forgotten at once.
    async signIn(t, probePath) {
      if (typeof t !== "string" || t.length < 8 || t.length > 256 || /[\s\r\n]/.test(t)) throw new ApiError("auth", "That does not look like a token.");
      token = t; last = now();
      try { return await request("GET", probePath); } catch (e) { token = null; throw e; }
    },
    signOut() { token = null; },
    get signedIn() { return token !== null && !expired(); },
    get: (p) => request("GET", p),
    post: (p, json) => request("POST", p, { json }),
    getBytes: (p) => request("GET", p, { raw: true }),
  };
}

export const operatorApi = (baseUrl) => createApi({ baseUrl, headerName: OPERATOR_HEADER });
export const userApi = (baseUrl) => createApi({ baseUrl, headerName: SESSION_HEADER });

export function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
