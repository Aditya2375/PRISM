"""One public address for the web console, in front of two private backends.

Hosted demo only. It serves the built console, forwards a short allow-list of paths to the PRISM service
(operator reads) and to the local user backend (device holder), limits each client address, and caps body size.
Anything not on the list is a 404. It holds no keys and no tokens: callers still send their own token, and the
backends check it.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.staticfiles import StaticFiles

SERVICE = os.environ.get("HOSTED_SERVICE_URL", "http://127.0.0.1:8443")
LOCAL = os.environ.get("HOSTED_LOCAL_URL", "http://127.0.0.1:8788")
MAX_BODY = int(os.environ.get("HOSTED_MAX_BODY", str(64 * 1024)))       # bytes, per request
RATE = int(os.environ.get("HOSTED_RATE", "120"))                         # requests per window, per client
WINDOW = float(os.environ.get("HOSTED_WINDOW_S", "60"))
FAIL_RATE = int(os.environ.get("HOSTED_FAIL_RATE", "10"))                # rejected token attempts per window
FORWARD_HEADERS = ("x-kig-operator-token", "x-prism-session", "content-type")

# (method, exact path or prefix ending in "/") -> which backend
SERVICE_ALLOW = {("GET", "/v1/overview"), ("GET", "/v1/alerts"), ("GET", "/v1/audit"), ("GET", "/v1/audit/verify")}
LOCAL_ALLOW = {("GET", "/me"), ("GET", "/files"), ("GET", "/devices"), ("GET", "/activity"),
               ("POST", "/files"), ("POST", "/files/delete"), ("POST", "/devices/lost"),
               ("POST", "/devices/preview"), ("POST", "/devices/enroll")}


def route_for(method: str, path: str):
    if (method, path) in SERVICE_ALLOW:
        return SERVICE
    if (method, path) in LOCAL_ALLOW or (method == "GET" and path.startswith("/files/") and "/" not in path[7:] and len(path) > 7):
        return LOCAL
    return None


class Limiter:
    """Sliding window per key. In memory, per process. Enough for a demo that is torn down."""

    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock(); q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        if len(self.hits) > 5000:           # drop idle keys so memory stays bounded
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > self.window]:
                self.hits.pop(k, None)
        return True


def client_ip(request: Request) -> str:
    # Behind the host's proxy the real address is the last entry the host appended.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def build_app(static_dir: str | None = None, *, client: httpx.AsyncClient | None = None, limiter: Limiter | None = None,
              fail_limiter: Limiter | None = None) -> Starlette:
    lim = limiter or Limiter(RATE, WINDOW)
    fails = fail_limiter or Limiter(FAIL_RATE, WINDOW)
    http = client or httpx.AsyncClient(timeout=15.0)

    async def forward(request: Request) -> Response:
        path = request.url.path
        base = route_for(request.method, path)
        if base is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        ip = client_ip(request)
        if not lim.allow(ip):
            return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": "30"})
        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
            return JSONResponse({"error": "too_large"}, status_code=413)
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY:
                return JSONResponse({"error": "too_large"}, status_code=413)
        headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
        url = base + path + (("?" + request.url.query) if request.url.query else "")
        try:
            r = await http.request(request.method, url, content=body or None, headers=headers)
        except httpx.HTTPError:
            return JSONResponse({"error": "backend_unavailable"}, status_code=502)
        if r.status_code in (401, 403) and not fails.allow(ip):
            return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": "60"})
        out = {k: v for k, v in r.headers.items() if k.lower() in ("content-type", "content-disposition")}
        out["Cache-Control"] = "no-store"
        return Response(r.content, status_code=r.status_code, headers=out)

    async def health(_: Request) -> Response:
        return JSONResponse({"ok": True})

    routes = [Route("/healthz", health)]
    paths = sorted({p for _, p in SERVICE_ALLOW | LOCAL_ALLOW})
    for p in paths:
        routes.append(Route(p, forward, methods=["GET", "POST"]))
    routes.append(Route("/files/{file_id}", forward, methods=["GET"]))
    if static_dir and Path(static_dir).is_dir():
        from starlette.routing import Mount
        routes.append(Mount("/", app=StaticFiles(directory=static_dir, html=True)))
    return Starlette(routes=routes)
