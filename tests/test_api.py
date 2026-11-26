import json

from fastapi.testclient import TestClient

from kig.api import create_app
from kig.client import Client, Device
from kig.service import GuardService
from conftest import Clock


def make(tmp_path):
    clock = Clock()
    svc = GuardService(tmp_path / "d", clock=clock)
    clock.tick(1)
    d = Device.generate("admin-1", "root")
    svc.bootstrap("root", "admin-1", d.sign_pub, d.kem_pub)
    app = create_app(tmp_path / "d", svc)
    tc = TestClient(app)

    def transport(env):
        r = tc.post("/v1/command", content=json.dumps(env))
        if r.status_code != 200:
            raise AssertionError((r.status_code, r.json()))
        return r.json()

    return tc, Client(d, transport, clock), (tmp_path / "d" / "operator.token").read_text().strip()


def test_command_roundtrip_and_operator_reads(tmp_path):
    tc, cl, token = make(tmp_path)
    cl.put_file("f1", b"hello")
    assert cl.fetch("f1") == b"hello"
    assert tc.get("/v1/alerts").status_code == 401
    assert tc.get("/v1/audit", headers={"X-KIG-Operator-Token": "nope"}).status_code == 401
    h = {"X-KIG-Operator-Token": token}
    assert tc.get("/v1/audit/verify", headers=h).json()["ok"] is True
    assert tc.get("/v1/overview", headers=h).json()["files"]["f1"]["epoch"] == 1
    assert tc.get("/v1/metrics").status_code == 401
    m = tc.get("/v1/metrics", headers=h).json()
    assert m["files"] == 1 and m["devices_by_status"]["active"] >= 1 and m["audit_events"]
    prom = tc.get("/v1/metrics?format=prometheus", headers=h).text
    assert "prism_files 1" in prom and 'prism_devices{status="active"}' in prom
    assert "f1" not in prom and "asha" not in prom
    assert tc.get("/v1/server-key").json()["alg"] == "ML-DSA-65"
    assert tc.get("/healthz").json()["ok"]


def test_bad_inputs(tmp_path):
    tc, cl, token = make(tmp_path)
    assert tc.post("/v1/command", content=b"not json").status_code == 400
    assert tc.post("/v1/command", content=b"[1,2]").status_code == 400
    r = tc.post("/v1/command", content=json.dumps({"cmd": "fetch"}))
    assert r.status_code == 400 and r.json()["error"] == "bad_request"
    r = tc.post("/v1/command", content=json.dumps(cl.envelope("fetch", {"file_id": "missing"})))
    assert r.status_code == 404


def test_every_reply_carries_security_headers(tmp_path):
    tc, cl, token = make(tmp_path)
    for r in (tc.get("/healthz"), tc.get("/v1/overview"), tc.post("/v1/command", content=b"nope"), tc.get("/nope")):
        h = r.headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer" and "default-src 'none'" in h["content-security-policy"]
        assert h["cache-control"] == "no-store"
        assert "strict-transport-security" not in h                     # no trusted proxy configured


def test_hsts_only_behind_a_trusted_proxy_that_says_https(tmp_path):
    from kig.api import create_app
    app = create_app(tmp_path / "d", None, trust_proxy=True)
    tc = TestClient(app)
    assert "strict-transport-security" not in tc.get("/healthz").headers
    assert "max-age" in tc.get("/healthz", headers={"x-forwarded-proto": "https"}).headers["strict-transport-security"]
