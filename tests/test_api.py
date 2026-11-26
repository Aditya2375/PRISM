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


def test_scheduled_backup_endpoint(tmp_path, monkeypatch):
    from kig import backup as bk
    tc, cl, token = make(tmp_path)
    h = {"X-KIG-Operator-Token": token}
    assert tc.post("/v1/backup").status_code == 401
    assert tc.post("/v1/backup", headers=h).status_code == 409                  # not configured
    keys, out = tmp_path / "keys", tmp_path / "bk"
    bk.keygen(keys, passphrase="")
    monkeypatch.setenv("KIG_BACKUP_PUB", str(keys / "backup.pub"))
    monkeypatch.setenv("KIG_BACKUP_DIR", str(tmp_path / "d" / "inside"))
    assert tc.post("/v1/backup", headers=h).status_code == 409                  # inside the data directory: refused
    monkeypatch.setenv("KIG_BACKUP_DIR", str(out))
    r = tc.post("/v1/backup", headers=h)
    assert r.status_code == 200 and r.json()["counter"] == 1
    assert tc.post("/v1/backup", headers=h).status_code == 429                  # default minimum gap
    monkeypatch.setenv("KIG_BACKUP_MIN_INTERVAL", "0")
    r2 = tc.post("/v1/backup", headers=h)
    assert r2.json()["counter"] == 2 and r2.json()["file"] != r.json()["file"]
    files = sorted(p.name for p in out.iterdir())
    assert len(files) == 2 and all(f.endswith(".bak") for f in files)
    assert (out / r.json()["file"]).stat().st_mode & 0o077 == 0                 # owner-only
    monkeypatch.setenv("KIG_BACKUP_MAX_FILES", "2")
    assert tc.post("/v1/backup", headers=h).status_code == 409                  # directory cap
