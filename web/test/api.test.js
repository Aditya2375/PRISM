import test from "node:test";
import assert from "node:assert/strict";
import { createApi, ApiError, toBase64 } from "../src/api.js";
import { clip, when, shortHash, fingerprintGroups, labelFor } from "../src/format.js";

const ok = (body, status = 200) => async () => new Response(JSON.stringify(body), { status });

test("token is sent only as the header, never in the URL, and cookies are not used", async () => {
  let seen;
  const api = createApi({ baseUrl: "http://127.0.0.1:8443", headerName: "X-KIG-Operator-Token", fetchImpl: async (u, o) => { seen = { u, o }; return new Response("{}"); } });
  await api.signIn("a-token-that-is-long", "/v1/overview");
  assert.equal(seen.o.headers["X-KIG-Operator-Token"], "a-token-that-is-long");
  assert.ok(!seen.u.includes("a-token"));
  assert.equal(seen.o.credentials, "omit");
  assert.equal(seen.o.referrerPolicy, "no-referrer");
});

test("a wrong token is forgotten and reported in plain words", async () => {
  const api = createApi({ baseUrl: "http://127.0.0.1:8443", headerName: "H", fetchImpl: ok({ detail: "x" }, 401) });
  await assert.rejects(api.signIn("not-the-token", "/v1/overview"), (e) => e instanceof ApiError && e.kind === "auth");
  assert.equal(api.signedIn, false);
  await assert.rejects(api.get("/v1/overview"), (e) => e.kind === "auth");
});

test("idle time signs out", async () => {
  let t = 0;
  const api = createApi({ baseUrl: "http://127.0.0.1:1", headerName: "H", now: () => t, idleMs: 1000, fetchImpl: ok({}) });
  await api.signIn("a-token-that-is-long", "/x");
  t = 999; await api.get("/x");
  t = 2100; assert.equal(api.signedIn, false);
  await assert.rejects(api.get("/x"), (e) => e.kind === "auth");
});

test("bad tokens are refused before any request", async () => {
  let called = false;
  const api = createApi({ baseUrl: "http://127.0.0.1:1", headerName: "H", fetchImpl: async () => { called = true; return new Response("{}"); } });
  for (const bad of ["", "short", "has space in it 1234", "line\nbreak12345", "x".repeat(300), null, 5]) {
    await assert.rejects(api.signIn(bad, "/x"));
  }
  assert.equal(called, false);
});

test("baseUrl must be a bare origin", () => {
  for (const bad of ["http://h/", "http://h/path", "ftp://h", "javascript:alert(1)", "http://h?x", "//h"]) {
    assert.throws(() => createApi({ baseUrl: bad, headerName: "H" }));
  }
});

test("errors map to words and server text is capped", async () => {
  const long = "r".repeat(5000);
  for (const [status, kind] of [[403, "denied"], [409, "denied"], [422, "refused"], [502, "network"], [500, "denied"]]) {
    const api = createApi({ baseUrl: "http://127.0.0.1:1", headerName: "H", fetchImpl: async (u) => u.endsWith("/p") ? new Response("{}") : new Response(JSON.stringify({ reason: long }), { status }) });
    await api.signIn("a-token-that-is-long", "/p");
    await assert.rejects(api.get("/x"), (e) => e.kind === kind && e.message.length <= 200);
  }
});

test("network failure and unreadable replies are handled", async () => {
  let mode = "ok";
  const api = createApi({ baseUrl: "http://127.0.0.1:1", headerName: "H", fetchImpl: async () => { if (mode === "down") throw new TypeError("x"); return new Response(mode === "junk" ? "<html>" : "{}"); } });
  await api.signIn("a-token-that-is-long", "/p");
  mode = "down"; await assert.rejects(api.get("/x"), (e) => e.kind === "network");
  mode = "junk"; await assert.rejects(api.get("/x"), (e) => e.kind === "bad_reply");
});

test("a request that hangs is aborted", async () => {
  const api = createApi({ baseUrl: "http://127.0.0.1:1", headerName: "H", fetchImpl: (u, o) => u.endsWith("/p") ? Promise.resolve(new Response("{}")) : new Promise((_, rej) => o.signal.addEventListener("abort", () => rej(new Error("aborted")))) });
  await api.signIn("a-token-that-is-long", "/p");
  const t0 = Date.now();
  await assert.rejects(api.get("/hang"), (e) => e.kind === "network");
  assert.ok(Date.now() - t0 < 9500);
});

test("format helpers neutralise hostile strings", () => {
  const evil = "<img src=x onerror=alert(1)>\u202egnp.exe\u0000" + "A".repeat(1000);
  const out = clip(evil);
  assert.ok(out.length <= 201 && !/[\u202e\u0000]/.test(out));
  assert.equal(clip(null), ""); assert.equal(clip({ a: 1 }).length > 0, true);
  assert.equal(when(NaN), ""); assert.equal(when("x"), ""); assert.equal(when(1800000001), "08:00:01");
  assert.equal(shortHash("5a846b1a9a8533dd0000"), "5a846b1a\u20260000"); assert.equal(shortHash("<script>"), "");
  assert.deepEqual(fingerprintGroups("1".repeat(8) + ("-" + "a".repeat(8)).repeat(7)).length, 8);
  assert.deepEqual(fingerprintGroups("zzz"), []);
  assert.equal(labelFor("device.lost"), "device reported lost");
  assert.ok(labelFor("<b>" + "x".repeat(100)).length <= 65);
});

test("toBase64 handles large and empty input", () => {
  assert.equal(toBase64(new Uint8Array()), "");
  const big = new Uint8Array(200000).fill(65);
  assert.equal(Buffer.from(toBase64(big), "base64").length, 200000);
});
