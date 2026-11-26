"""One public address for the web console, in front of two private backends.

Hosted demo only. It serves the built console, forwards a short allow-list of paths to the PRISM service
(operator reads) and to the local user backend (device holder), limits each client address, and caps body size.
Anything not on the list is a 404. It holds no keys and no tokens: callers still send their own token, and the
backends check it.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import OrderedDict, deque
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
FAIL_RATE = int(os.environ.get("HOSTED_FAIL_RATE", "10"))                # rejected token attempts per window, per client
GLOBAL_RATE = int(os.environ.get("HOSTED_GLOBAL_RATE", "600"))           # requests per window, all clients together
GLOBAL_FAIL_RATE = int(os.environ.get("HOSTED_GLOBAL_FAIL_RATE", "100"))  # rejected token replies per window, all clients
TRUST_PROXY = os.environ.get("HOSTED_TRUST_PROXY") == "1"                # only behind a host that sets X-Forwarded-For itself
BODY_TIMEOUT_S = float(os.environ.get("HOSTED_BODY_TIMEOUT_S", "10"))
MAX_REPLY = int(os.environ.get("HOSTED_MAX_REPLY", str(2 * 1024 * 1024)))
MAX_KEYS = 5000
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                    "X-Frame-Options": "DENY"}
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
    """Sliding window per key. In memory, per process. Enough for a demo that is torn down.

    The key table is bounded: past MAX_KEYS the least recently used key is dropped, in constant time.
    """

    def __init__(self, limit: int, window: float, clock=time.monotonic, max_keys: int = MAX_KEYS):
        self.limit, self.window, self.clock, self.max_keys = limit, window, clock, max_keys
        self.hits: OrderedDict[str, deque] = OrderedDict()

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self.hits.get(key)
        if q is None:
            q = self.hits[key] = deque()
            while len(self.hits) > self.max_keys:
                self.hits.popitem(last=False)
        else:
            self.hits.move_to_end(key)
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


def client_ip(request: Request, trust_proxy: bool | None = None) -> str:
    """The peer address. Behind a host that sets X-Forwarded-For itself, the last entry is the one the host added."""
    if TRUST_PROXY if trust_proxy is None else trust_proxy:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def build_app(static_dir: str | None = None, *, client: httpx.AsyncClient | None = None, limiter: Limiter | None = None,
              fail_limiter: Limiter | None = None, global_limiter: Limiter | None = None,
              global_fail_limiter: Limiter | None = None, trust_proxy: bool | None = None) -> Starlette:
    lim = limiter or Limiter(RATE, WINDOW)
    fails = fail_limiter or Limiter(FAIL_RATE, WINDOW)
    glob = global_limiter or Limiter(GLOBAL_RATE, WINDOW)
    glob_fails = global_fail_limiter or Limiter(GLOBAL_FAIL_RATE, WINDOW)
    http = client or httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0))

    def too_many(retry: str = "30") -> Response:
        return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": retry})

    async def read_body(request: Request) -> bytes | None:
        body = bytearray()
        async def pull():
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    return False
            return True
        try:
            ok = await asyncio.wait_for(pull(), BODY_TIMEOUT_S)
        except asyncio.TimeoutError:
            return None
        return bytes(body) if ok else b"\xff" * (MAX_BODY + 1)

    async def forward(request: Request) -> Response:
        path = request.url.path
        base = route_for(request.method, path)
        if base is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        ip = client_ip(request, trust_proxy)
        if not glob.allow("all") or not lim.allow(ip):
            return too_many()
        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
            return JSONResponse({"error": "too_large"}, status_code=413)
        body = await read_body(request)
        if body is None:
            return JSONResponse({"error": "request_timeout"}, status_code=408)
        if len(body) > MAX_BODY:
            return JSONResponse({"error": "too_large"}, status_code=413)
        headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
        url = base + path + (("?" + request.url.query) if request.url.query else "")
        try:
            req = http.build_request(request.method, url, content=body or None, headers=headers)
            r = await http.send(req, stream=True)
            try:
                if int(r.headers.get("content-length", "0")) > MAX_REPLY:
                    return JSONResponse({"error": "backend_unavailable"}, status_code=502)
                content = bytearray()
                async for chunk in r.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_REPLY:
                        return JSONResponse({"error": "backend_unavailable"}, status_code=502)
            finally:
                await r.aclose()
        except (httpx.HTTPError, ValueError):
            return JSONResponse({"error": "backend_unavailable"}, status_code=502)
        if r.status_code in (401, 403) and (not fails.allow(ip) or not glob_fails.allow("all")):
            return too_many("60")
        out = {k: v for k, v in r.headers.items() if k.lower() in ("content-type", "content-disposition")}
        out["Cache-Control"] = "no-store"
        return Response(bytes(content), status_code=r.status_code, headers=out)

    async def health(_: Request) -> Response:
        return JSONResponse({"ok": True})

    routes = [Route("/healthz", health)]
    for p in sorted({p for _, p in SERVICE_ALLOW | LOCAL_ALLOW}):
        routes.append(Route(p, forward, methods=["GET", "POST"]))
    routes.append(Route("/files/{file_id}", forward, methods=["GET"]))
    if static_dir and Path(static_dir).is_dir():
        from starlette.routing import Mount
        routes.append(Mount("/", app=StaticFiles(directory=static_dir, html=True)))

    class Headers:
        """Security headers on every reply, console and API."""
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                return await self.app(scope, receive, send)
            async def wrapped(message):
                if message["type"] == "http.response.start":
                    h = [(k, v) for k, v in message.get("headers", []) if k.decode().lower() not in {x.lower() for x in SECURITY_HEADERS}]
                    h += [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
                    message = {**message, "headers": h}
                await send(message)
            await self.app(scope, receive, wrapped)

    return Headers(Starlette(routes=routes))
