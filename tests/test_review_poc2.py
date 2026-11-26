"""Round-2 PoCs. Each asserts the SAFE behaviour; FAIL = confirmed finding."""
import json, os
import pytest
from kig import crypto as c, backup
from kig.client import Client, Device
from kig.service import Denied, GuardService, SimulatedCrash
from conftest import World, Clock


def _junk(w, dev, src):
    env = w.bob.envelope("whoami"); env["device"] = dev
    try:
        w.svc.handle(env, source=src)
    except Denied:
        pass


def test_G1_log_budget_can_be_exhausted_to_hide_revoked_device_use(w):
    w.admin.call("revoke_device", device="bob-laptop")
    w.clock.tick(1)
    for i in range(12):                       # 12 sources x 3 lines > 30 total lines per minute
        for j in range(3):
            _junk(w, f"ghost-{i}-{j}", f"10.1.1.{i}")
    n0 = len(w.svc.audit.entries)
    with pytest.raises(Denied) as e:
        w.svc.handle(w.bob.envelope("whoami"), source="10.9.9.9")   # revoked device is used
    assert e.value.code == "revoked"
    types = [x["type"] for x in w.svc.audit.entries[n0:]]
    assert "auth.revoked_device_use" in types, "critical R1 event was swallowed by the shared unauthenticated log budget"


def test_G2_suppression_summary_raises_R3_alert(w):
    for i in range(40):
        _junk(w, f"ghost-{i}", "10.2.2.2")
    w.clock.tick(61)
    w.svc.handle(w.admin.envelope("whoami"), source="10.3.3.3")
    assert any(x["rule"] == "R3-AUTH-FAILURE-BURST" and x["subject"] == "unauthenticated" for x in w.svc.alerts()), \
        "auth.failures_suppressed is appended with audit.append (not _log) so the detector never sees it"


def test_G3_crash_during_bootstrap_must_not_brick_data_dir(tmp_path):
    clock = Clock(); svc = GuardService(tmp_path / "d", clock=clock); clock.tick(1)
    dev = Device.generate("a-1", "a"); svc.crash_at = "after_audit"
    with pytest.raises(SimulatedCrash):
        svc.bootstrap("a", "a-1", dev.sign_pub, dev.kem_pub)
    GuardService(tmp_path / "d", clock=clock)      # restart must work (or re-bootstrap must be possible)


def test_G4_x_forwarded_for_spoofing_defeats_source_limits(tmp_path):
    from fastapi.testclient import TestClient
    from kig.api import create_app
    app = create_app(tmp_path / "d", trust_proxy=True)
    cl = TestClient(app, raise_server_exceptions=False)
    codes = set()
    for i in range(1300):
        r = cl.post("/v1/command", json={"cmd": "x"}, headers={"x-forwarded-for": f"7.7.{i // 250}.{i % 250}, 10.0.0.1"})
        codes.add(r.status_code)
    # a real proxy APPENDS the true peer; the right-most trusted hop is the only safe one. All 1300 got through:
    r = cl.post("/v1/command", json={"cmd": "x"}, headers={"x-forwarded-for": "7.7.9.9, 10.0.0.1"})
    src_keys = [k for k in app.state.service._rate if k.startswith("src:")]
    assert len(src_keys) < 10, f"{len(src_keys)} distinct 'sources' were accepted from attacker-supplied headers"


def test_G5_missing_pub_file_must_not_overwrite_signing_key(w):
    d = w.svc.dir; old = (d / "server_sign.key").read_bytes()
    os.unlink(d / "server_sign.pub")
    try:
        GuardService(d, clock=w.clock)
    except Exception:
        pass
    assert (d / "server_sign.key").read_bytes() == old, "signing key silently regenerated and overwritten"


def test_G6_deleted_backup_counter_resets_monotonic_counter(w, tmp_path):
    bp, bs = c.kem_keygen()
    m1 = backup.create(w.svc, bp, tmp_path / "1.bak"); m2 = backup.create(w.svc, bp, tmp_path / "2.bak")
    os.unlink(w.svc.dir / "backup.counter")
    m3 = backup.create(w.svc, bp, tmp_path / "3.bak")
    assert m3["counter"] > m2["counter"], "counter lives in an unsigned deletable file"


def test_G7_tail_truncation_with_rebuilt_anchor_is_accepted(w):
    d = w.svc.dir
    for i in range(3):
        _junk(w, f"ghost-{i}", f"10.4.4.{i}")      # entries after the last state persist (not covered by state.applied)
    p = d / "audit.jsonl"; lines = p.read_bytes().splitlines(keepends=True)
    keep = lines[:-3]; p.write_bytes(b"".join(keep))
    last = json.loads(keep[-1])
    (d / "audit.head").write_text(json.dumps({"seq": last["seq"], "hash": last["hash"], "sig": last["sig"]}))
    with pytest.raises(Exception):
        GuardService(d, clock=w.clock)


def test_G8_legit_user_behind_shared_source_is_starved_by_junk(w):
    for i in range(1200):
        _junk(w, f"g{i}", "192.0.2.1")
    w.clock.tick(1)
    assert w.svc.handle(w.bob.envelope("whoami"), source="192.0.2.1")["user"] == "bob"
