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
    c = TestClient(build_app(client=fake_backend(seen), limiter=Limiter(3, 60), trust_proxy=True))
    codes = [c.get("/v1/overview", headers={"x-kig-operator-token": "good", "x-forwarded-for": "1.1.1.1"}).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    # a different client is not affected
    assert c.get("/v1/overview", headers={"x-kig-operator-token": "good", "x-forwarded-for": "2.2.2.2"}).status_code == 200


def test_failed_token_attempts_get_cut_off_sooner():
    seen = []
    c = TestClient(build_app(client=fake_backend(seen), limiter=Limiter(1000, 60), fail_limiter=Limiter(3, 60), trust_proxy=True))
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


def test_spoofed_forwarded_for_does_not_dodge_limits_unless_proxy_is_trusted():
    c = TestClient(build_app(client=fake_backend([]), limiter=Limiter(3, 60), trust_proxy=False))
    codes = [c.get("/v1/overview", headers={"x-kig-operator-token": "good", "x-forwarded-for": f"7.7.7.{i}"}).status_code for i in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_global_limits_cap_the_total_even_for_many_clients():
    c = TestClient(build_app(client=fake_backend([]), limiter=Limiter(1000, 60), global_limiter=Limiter(4, 60), trust_proxy=True))
    codes = [c.get("/v1/overview", headers={"x-kig-operator-token": "good", "x-forwarded-for": f"8.8.8.{i}"}).status_code for i in range(6)]
    assert codes == [200] * 4 + [429] * 2
    c = TestClient(build_app(client=fake_backend([]), limiter=Limiter(1000, 60), fail_limiter=Limiter(1000, 60),
                             global_fail_limiter=Limiter(3, 60), trust_proxy=True))
    codes = [c.get("/v1/overview", headers={"x-kig-operator-token": "bad", "x-forwarded-for": f"6.6.6.{i}"}).status_code for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]


def test_security_headers_on_api_and_console(tmp_path):
    (tmp_path / "index.html").write_text("<html></html>")
    c = TestClient(build_app(str(tmp_path), client=fake_backend([])))
    for r in (c.get("/"), c.get("/v1/overview", headers={"x-kig-operator-token": "good"}), c.get("/nope")):
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"


def test_limiter_table_is_bounded():
    lim = Limiter(5, 60, max_keys=10)
    for i in range(100):
        lim.allow(f"k{i}")
    assert len(lim.hits) == 10


def test_oversized_backend_reply_is_refused(monkeypatch):
    import hosted.proxy as hp
    monkeypatch.setattr(hp, "MAX_REPLY", 100)
    def handler(request):
        return httpx.Response(200, content=b"x" * 500)
    c = TestClient(build_app(client=httpx.AsyncClient(transport=httpx.MockTransport(handler))))
    assert c.get("/v1/overview").status_code == 502


def test_one_abusive_client_cannot_use_up_the_global_budget():
    c = TestClient(build_app(client=fake_backend([]), limiter=Limiter(3, 60), global_limiter=Limiter(10, 60), trust_proxy=True))
    h = {"x-kig-operator-token": "good"}
    for _ in range(200):
        c.get("/v1/overview", headers={**h, "x-forwarded-for": "1.1.1.1"})
    assert c.get("/v1/overview", headers={**h, "x-forwarded-for": "3.3.3.3"}).status_code == 200


def test_rejected_tokens_from_one_client_do_not_use_up_the_global_failure_budget():
    c = TestClient(build_app(client=fake_backend([]), limiter=Limiter(1000, 60), fail_limiter=Limiter(3, 60),
                             global_fail_limiter=Limiter(5, 60), trust_proxy=True))
    for _ in range(100):
        c.get("/v1/overview", headers={"x-kig-operator-token": "bad", "x-forwarded-for": "1.1.1.1"})
    assert c.get("/v1/overview", headers={"x-kig-operator-token": "bad", "x-forwarded-for": "3.3.3.3"}).status_code == 401


def _health_client(service_status, local_status, calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/healthz":
            if service_status is None:
                raise httpx.ConnectError("down")
            return httpx.Response(service_status, json={})
        if request.url.path == "/me":
            if local_status is None:
                raise httpx.ConnectError("down")
            return httpx.Response(local_status, json={})
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_health_is_ok_only_when_both_backends_answer():
    calls = []
    c = TestClient(build_app(client=_health_client(200, 401, calls)))
    r = c.get("/healthz")
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_health_fails_when_a_backend_is_down():
    for svc, loc, down in [(None, 401, ["service"]), (200, None, ["local"]), (500, 200, ["service", "local"])]:
        c = TestClient(build_app(client=_health_client(svc, loc, [])))
        r = c.get("/healthz")
        assert r.status_code == 503 and r.json() == {"ok": False, "down": down}, (svc, loc)


def test_health_result_is_cached_briefly():
    calls = []
    c = TestClient(build_app(client=_health_client(200, 401, calls)))
    for _ in range(10):
        assert c.get("/healthz").status_code == 200
    assert len(calls) == 2                      # one probe per backend, not one per request
