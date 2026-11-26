import httpx
import pytest
from starlette.testclient import TestClient

from hosted.proxy import Limiter, build_app, route_for


def fake_backend(seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url), dict(request.headers)))
        return httpx.Response(200, json={"ok": True}) if request.headers.get("x-kig-operator-token") == "good" else httpx.Response(401, json={"error": "auth"})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_allow_list_only():
    assert route_for("GET", "/v1/overview")
    assert route_for("GET", "/files/abc")
    assert route_for("POST", "/devices/lost")
    for m, p in [("POST", "/v1/overview"), ("GET", "/v1/call"), ("GET", "/v1/config"), ("DELETE", "/files"),
                 ("GET", "/files/a/b"), ("GET", "/files/"), ("GET", "/../etc/passwd"), ("GET", "/devices/enroll")]:
        assert route_for(m, p) is None, (m, p)


def test_unlisted_path_is_404_and_never_reaches_backend():
    seen = []
    c = TestClient(build_app(client=fake_backend(seen)))
    assert c.get("/v1/admin/anything").status_code == 404
    assert c.post("/v1/overview").status_code in (404, 405)
    assert seen == []


def test_forwards_only_token_and_content_type_headers():
    seen = []
    c = TestClient(build_app(client=fake_backend(seen)))
    r = c.get("/v1/overview", headers={"x-kig-operator-token": "good", "cookie": "a=b", "authorization": "x", "x-forwarded-for": "9.9.9.9"})
    assert r.status_code == 200
    h = seen[0][2]
    assert "cookie" not in h and "authorization" not in h and "x-forwarded-for" not in h
    assert h["x-kig-operator-token"] == "good"


def test_rate_limit_per_client():
    seen = []
    c = TestClient(build_app(client=fake_backend(seen), limiter=Limiter(3, 60)))
    codes = [c.get("/v1/overview", headers={"x-kig-operator-token": "good", "x-forwarded-for": "1.1.1.1"}).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    # a different client is not affected
    assert c.get("/v1/overview", headers={"x-kig-operator-token": "good", "x-forwarded-for": "2.2.2.2"}).status_code == 200


def test_failed_token_attempts_get_cut_off_sooner():
    seen = []
    c = TestClient(build_app(client=fake_backend(seen), limiter=Limiter(1000, 60), fail_limiter=Limiter(3, 60)))
    codes = [c.get("/v1/overview", headers={"x-kig-operator-token": "bad", "x-forwarded-for": "3.3.3.3"}).status_code for _ in range(6)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429, 429]


def test_body_cap_declared_and_streamed():
    seen = []
    c = TestClient(build_app(client=fake_backend(seen)))
    big = b"x" * (64 * 1024 + 1)
    r = c.post("/files", content=big, headers={"x-prism-session": "s", "content-type": "application/json"})
    assert r.status_code == 413
    assert seen == []


def test_limiter_window_expires():
    t = [0.0]
    lim = Limiter(2, 10, clock=lambda: t[0])
    assert lim.allow("a") and lim.allow("a") and not lim.allow("a")
    t[0] = 11
    assert lim.allow("a")


def test_backend_down_is_502_not_a_leak():
    def boom(request):
        raise httpx.ConnectError("down")
    c = TestClient(build_app(client=httpx.AsyncClient(transport=httpx.MockTransport(boom))))
    r = c.get("/v1/overview")
    assert r.status_code == 502 and r.json() == {"error": "backend_unavailable"}
