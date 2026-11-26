"""Optional local backend for a browser UI used by an ordinary device holder.

A browser cannot make the ML-DSA signatures the service requires, so the private keys stay in a Python
process on the user's own machine. This process loads one device key file, speaks to the PRISM service with
`kig.client.Client`, and offers a small JSON API to a page on the same machine.

  python -m kig.webapi --key asha-laptop.json --url http://127.0.0.1:8443 [--port 8788]

It binds to 127.0.0.1 only. Every request needs the session token printed at start-up, in the
`X-PRISM-Session` header. It never returns a key, a wrapped key, the passphrase or the operator token. It is
a convenience layer: every check that matters (signatures, manifests, pins, access) still happens in the
client and the service. CORS is off unless origins are listed in KIG_CORS_ORIGINS (same rules as the service).
"""
from __future__ import annotations

import argparse
import hmac
import os
import secrets
import sys
import threading
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response

from . import crypto as c
from . import vault
from .api import _check_origin, read_capped
from .client import Client, Device, device_fingerprint
from .service import MAX_FILE_BYTES, Denied

MAX_BODY = MAX_FILE_BYTES * 2
HEADER = "x-prism-session"


def _tr_error(e: Exception) -> JSONResponse:
    return JSONResponse({"error": "service_unreachable", "reason": "the PRISM service did not answer"}, status_code=502)


def create_web_app(client: Client, token: str, cors_origins: list[str] | None = None,
                   port: int | None = None) -> FastAPI:
    if len(token) < 32:
        raise ValueError("the session token must be at least 32 characters")
    app = FastAPI(title="PRISM local user backend", docs_url=None, redoc_url=None, openapi_url=None)
    lock = threading.Lock()                       # the client keeps rollback state; one call at a time
    if cors_origins is None:
        raw = os.environ.get("KIG_CORS_ORIGINS", "")
        cors_origins = [o.strip() for o in raw.split(",") if o.strip()]
        if raw and not cors_origins:
            raise ValueError("KIG_CORS_ORIGINS is set but lists no origin; unset it or give exact origins")
    for o in cors_origins:
        _check_origin(o)
    @app.middleware("http")
    async def guard(request: Request, call_next):
        # DNS rebinding: a page on another name that resolves to 127.0.0.1 must not reach this process
        host = request.headers.get("host", "").lower()
        if host.startswith("["):
            name, _, rest = host.partition("]")
            name, hp = name + "]", rest[1:] if rest.startswith(":") else ""
            if rest and not rest.startswith(":"):
                name = "bad"
        else:
            name, _, hp = host.partition(":")
        if name not in ("127.0.0.1", "localhost", "[::1]") or (hp and port is not None and hp != str(port)):
            return JSONResponse({"error": "bad_host", "reason": "use http://127.0.0.1"}, status_code=400)
        if request.method != "OPTIONS":
            if not hmac.compare_digest(request.headers.get(HEADER, "").encode(), token.encode()):
                return JSONResponse({"error": "unauthorized", "reason": "session token required"}, status_code=401)
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    # added after the guard so it is the outermost layer: even a 401 or a bad-host answer carries the CORS headers,
    # otherwise the browser reports an opaque network error instead of the reason
    if cors_origins:
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_credentials=False,
                           allow_methods=["GET", "POST"], allow_headers=["content-type", HEADER])

    def run(fn):
        try:
            with lock:
                return fn()
        except Denied as e:
            return JSONResponse({"error": e.code, "reason": e.reason}, status_code=e.status if 400 <= e.status < 600 else 502)
        except (c.CryptoError, vault.VaultError) as e:
            # a refusal made by this machine, e.g. a manifest that does not verify: say so, release nothing
            return JSONResponse({"error": "refused", "reason": str(e)[:300]}, status_code=422)
        except OSError as e:
            return _tr_error(e)

    async def body(request: Request) -> dict[str, Any]:
        raw = await read_capped(request, MAX_BODY)
        import json
        try:
            d = json.loads(raw)
        except (ValueError, RecursionError):
            raise Denied("bad_request", "invalid JSON", 400) from None
        if not isinstance(d, dict):
            raise Denied("bad_request", "body must be an object", 400)
        return d

    @app.exception_handler(Denied)
    async def _denied(_: Request, exc: Denied) -> JSONResponse:
        return JSONResponse({"error": exc.code, "reason": exc.reason}, status_code=exc.status)

    @app.get("/me")
    def me():
        return run(lambda: client.call("whoami"))

    @app.get("/files")
    def files():
        return run(lambda: client.call("list_files"))

    @app.post("/files")
    async def upload(request: Request):
        d = await body(request)
        file_id, acl, b64 = d.get("file_id"), d.get("acl", []), d.get("content_b64")
        if not isinstance(file_id, str) or not isinstance(b64, str) or not isinstance(acl, list) \
                or not all(isinstance(u, str) for u in acl) or len(acl) > 64:
            raise Denied("bad_request", "file_id (string), acl (list of strings) and content_b64 (string) are required", 400)
        try:
            data = c.b64d(b64)
        except c.CryptoError:
            raise Denied("bad_request", "content_b64 is not base64", 400) from None
        if len(data) > MAX_FILE_BYTES - 1024:
            raise Denied("too_large", "file too large", 413)
        return run(lambda: client.put_file(file_id, data, acl=acl))

    @app.get("/files/{file_id}")
    def download(file_id: str):
        r = run(lambda: client.fetch(file_id))
        if isinstance(r, JSONResponse):
            return r
        return Response(r, media_type="application/octet-stream",
                        headers={"Content-Disposition": "attachment; filename=\"download.bin\""})

    @app.get("/devices")
    def devices():
        return run(lambda: client.call("my_devices"))

    @app.post("/devices/lost")
    async def lost(request: Request):
        d = await body(request)
        dev, reason = d.get("device"), d.get("reason", "")
        if not isinstance(dev, str) or not isinstance(reason, str):
            raise Denied("bad_request", "device and reason must be strings", 400)
        return run(lambda: client.call("report_lost", device=dev, reason=reason[:200]))

    def _pub(d: dict[str, Any]) -> dict[str, str]:
        raw = d.get("pub")
        allowed = {"device", "user", "sign_pub", "kem_pub"}
        if not isinstance(raw, dict) or set(raw) != allowed or not all(isinstance(raw[k], str) for k in allowed):
            raise Denied("bad_request", f"pub must hold exactly {sorted(allowed)} as strings", 400)
        return dict(raw)

    @app.post("/devices/preview")
    async def preview(request: Request):
        """The fingerprint of a new device's public data, to compare with what that device itself shows."""
        pub = _pub(await body(request))
        try:
            fp = device_fingerprint(pub["device"], pub["user"], c.b64d(pub["sign_pub"]), c.b64d(pub["kem_pub"]))
        except c.CryptoError:
            raise Denied("bad_request", "keys are not base64", 400) from None
        return {"device": pub["device"], "user": pub["user"], "fingerprint": fp}

    @app.post("/devices/enroll")
    async def enroll(request: Request):
        d = await body(request)
        args = _pub(d)
        expect, unverified = d.get("expect_fingerprint"), d.get("unverified", False)
        if unverified is True:
            if expect is not None:
                raise Denied("bad_request", "give a fingerprint or set unverified, not both", 400)
        elif not isinstance(expect, str) or not expect.strip():
            raise Denied("bad_request", "expect_fingerprint is required unless unverified is true", 400)
        else:
            args["expect_fingerprint"] = expect
        return run(lambda: client.call("enroll_device", **args))   # the service allows this to admins only

    @app.get("/activity")
    def activity(limit: int = 20):
        return run(lambda: client.call("my_activity", limit=max(1, min(limit, 100))))

    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kig.webapi", description=__doc__.split("\n")[0])
    ap.add_argument("--key", required=True, help="this device's key file")
    ap.add_argument("--url", required=True, help="the PRISM service")
    ap.add_argument("--port", type=int, default=8788)
    a = ap.parse_args(argv)
    if not 1 <= a.port <= 65535:
        print("refused: bad port", file=sys.stderr)
        return 2
    from .cli import _post as _cli_post
    try:
        dev = Device.load(a.key)
    except (OSError, vault.VaultError, c.CryptoError) as e:
        print(f"refused: cannot load the key file: {e}", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(32)
    app = create_web_app(Client(dev, _cli_post(a.url, timeout=10), state_path=str(a.key) + ".state"), token, port=a.port)
    print(f"PRISM local backend for {dev.user}/{dev.device_id} on http://127.0.0.1:{a.port}", file=sys.stderr)
    print(f"session token (send as {HEADER}): {token}", file=sys.stderr)
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
