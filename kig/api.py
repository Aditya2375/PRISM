"""HTTP API. One signed-command endpoint plus operator read endpoints.

* ``POST /v1/command``: a device-signed envelope (the only way to change state
  or fetch key material).
* ``GET /v1/...`` operator reads need the operator token stored in
  ``<data_dir>/operator.token`` (created at first start, mode 0600).
* Binds to 127.0.0.1 by default.
"""
from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import crypto as c
from .service import MAX_FILE_BYTES, Denied, GuardService

MAX_BODY = MAX_FILE_BYTES * 2


def _operator_token(data_dir: Path) -> str:
    p = data_dir / "operator.token"
    if not p.exists():
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_urlsafe(32))
    return p.read_text().strip()


def create_app(data_dir: str | Path, service: GuardService | None = None,
               trust_proxy: bool | None = None) -> FastAPI:
    data_dir = Path(data_dir)
    if trust_proxy is None:
        trust_proxy = os.environ.get("KIG_TRUSTED_PROXY") == "1"
    hops = 1
    if trust_proxy:
        raw_hops = os.environ.get("KIG_PROXY_HOPS", "1").strip() or "1"
        if not raw_hops.isdigit() or not 1 <= int(raw_hops) <= 16:
            raise ValueError(f"KIG_PROXY_HOPS must be an integer from 1 to 16, got {raw_hops[:20]!r}")
        hops = int(raw_hops)
    svc = service or GuardService(data_dir)
    token = _operator_token(data_dir)
    app = FastAPI(title="Key Identity Guard", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.service = svc

    def operator(x_kig_operator_token: str = Header(default="")) -> None:
        if not hmac.compare_digest(x_kig_operator_token.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="operator token required")

    @app.exception_handler(Denied)
    async def _denied(_: Request, exc: Denied) -> JSONResponse:
        return JSONResponse({"error": exc.code, "reason": exc.reason}, status_code=exc.status)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "audit_len": len(svc.audit.entries)}

    @app.get("/v1/server-key")
    def server_key() -> dict[str, str]:
        return {"alg": "ML-DSA-65", "public_key": c.b64e(svc.pub)}

    @app.post("/v1/command")
    async def command(request: Request) -> dict[str, Any]:
        raw = await request.body()
        if len(raw) > MAX_BODY:
            raise Denied("too_large", "request body too large", 413)
        try:
            import json

            env = json.loads(raw)
        except (ValueError, RecursionError):   # RecursionError: absurdly nested input
            raise Denied("bad_request", "invalid JSON", 400) from None
        if not isinstance(env, dict):
            raise Denied("bad_request", "envelope must be an object", 400)
        src = request.client.host if request.client else "unknown"
        if trust_proxy:
            # Only behind reverse proxies you control. Each proxy APPENDS the address it saw, so the
            # client-supplied (spoofable) entries are on the left. Take the entry added by the
            # outermost trusted proxy: hop N counted from the right (KIG_PROXY_HOPS, default 1).
            chain = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
            if len(chain) >= hops:
                src = chain[-hops][:64]
        return svc.handle(env, source=src)

    @app.get("/v1/overview", dependencies=[Depends(operator)])
    def overview() -> dict[str, Any]:
        return svc.overview()

    @app.get("/v1/metrics", dependencies=[Depends(operator)])
    def metrics(format: str = "json"):
        m = svc.metrics()
        if format != "prometheus":
            return m
        from fastapi.responses import PlainTextResponse
        out = [f"prism_users {m['users']}", f"prism_files {m['files']}",
               f"prism_files_needing_rotation {m['files_needing_rotation']}", f"prism_audit_entries {m['audit_entries']}"]
        out += [f'prism_devices{{status="{k}"}} {v}' for k, v in sorted(m["devices_by_status"].items())]
        out += [f'prism_audit_events_total{{type="{k}"}} {v}' for k, v in sorted(m["audit_events"].items())]
        return PlainTextResponse("\n".join(out) + "\n")

    @app.get("/v1/audit", dependencies=[Depends(operator)])
    def audit(since: int = 0, limit: int = 500) -> dict[str, Any]:
        rows = svc.audit.since(since)[: max(1, min(limit, 1000))]
        return {"entries": rows, "total": len(svc.audit.entries)}

    @app.get("/v1/audit/verify", dependencies=[Depends(operator)])
    def audit_verify() -> dict[str, Any]:
        ok, why = svc.audit.verify()
        return {"ok": ok, "reason": why, "head": svc.audit.head}

    @app.get("/v1/alerts", dependencies=[Depends(operator)])
    def alerts() -> dict[str, Any]:
        return {"alerts": svc.alerts()}

    return app
