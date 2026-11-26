"""Behaviour added after the independent review."""
import json

from test_backup import bk  # noqa: F401

import pytest

from kig import backup as b
from kig import crypto as c
from kig.client import Client, Device
from kig.service import Denied, GuardService, StateCorrupt


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except Denied as e:
        return e.code
    return None


def test_missing_state_with_existing_data_refuses_to_start_and_keeps_blobs(w, tmp_path):
    d = tmp_path / "data"
    blobs = sorted(p.name for p in (d / "blobs").rglob("*") if p.is_file())
    assert blobs
    (d / "state.json").unlink()
    with pytest.raises(StateCorrupt):
        GuardService(d, clock=w.clock)
    assert blobs == sorted(p.name for p in (d / "blobs").rglob("*") if p.is_file())


def test_replica_fields_survive_restart(w, tmp_path):
    w.svc.read_only = True
    w.svc.snapshot_version = 7
    w.svc.epoch_floor["report"] = (3, w.clock())
    w.svc._persist()
    svc2 = GuardService(tmp_path / "data", clock=w.clock)
    assert svc2.snapshot_version == 7 and svc2.epoch_floor["report"][0] == 3


def test_torn_revoked_log_tail_is_cut_not_glued(w, tmp_path):
    d = tmp_path / "data"
    with open(d / "revoked.log", "ab") as fh:
        fh.write(b"half-written-dev\t18000")
    svc2 = GuardService(d, clock=w.clock)
    w.clock.tick(1)
    Client(w.alice_laptop, svc2.handle, w.clock).call("revoke_device", device="alice-phone")
    for line in (d / "revoked.log").read_text().splitlines():
        dev, ts = line.split("\t")
        float(ts)
    assert "half-written-dev" not in (d / "revoked.log").read_text()


def test_huge_timestamp_and_deep_json_are_clean_4xx_not_500(w, tmp_path):
    e = w.bob.envelope("whoami")
    e["ts"] = 10 ** 400
    assert code(w.svc.handle, e, "x") in ("bad_request", "stale", "unauthorized", "bad_envelope")
    from fastapi.testclient import TestClient
    from kig.api import create_app
    app = create_app(tmp_path / "data", service=w.svc)
    r = TestClient(app).post("/v1/command", content="[" * 100000, headers={"content-type": "application/json"})
    assert 400 <= r.status_code < 500


def test_wrong_commitment_is_refused_by_the_client(w):
    w.svc.state["files"]["report"]["commit"] = "0" * 64
    w.svc._persist()
    w.clock.tick(1)
    with pytest.raises(Exception):
        w.bob.fetch("report")


def test_member_cannot_rotate_but_owner_and_admin_can(w):
    r = w.bob.call("fetch", file_id="report")
    assert r["can_rotate"] is False
    assert code(w.bob.call, "rotate", file_id="report", expected_epoch=1, ciphertext="", wraps={}, commit="0" * 64) == "forbidden"
    assert w.admin.call("fetch", file_id="report")["can_rotate"] is True


def test_enrolling_a_device_flags_shared_files_for_rotation(w):
    new = Device.generate("bob-phone", "bob")
    w.admin.call("enroll_device", **new.public_args())
    assert w.svc.state["files"]["report"]["needs_rotation"]


def test_client_seen_epoch_persists_and_blocks_rollback(w, tmp_path):
    sp = tmp_path / "seen.json"
    cl = Client(w.bob_laptop, w.svc.handle, w.clock, state_path=sp)
    cl.fetch("report")
    assert json.loads(sp.read_text())["report"] == 1
    sp.write_text(json.dumps({"report": 5}))
    cl2 = Client(w.bob_laptop, w.svc.handle, w.clock, state_path=sp)
    w.clock.tick(1)
    with pytest.raises(Exception):
        cl2.fetch("report")


def test_restore_without_any_rollback_evidence_is_refused(w, tmp_path, bk):
    out, pub, sec = bk
    d = tmp_path / "data"
    with pytest.raises(b.BackupError):
        b.restore(out, tmp_path / "r1", pub, sec, d / "server_sign.pub", d / "server_sign.key", live_revoked_log=d / "revoked.log")
    with pytest.raises(b.BackupError):
        b.restore(out, tmp_path / "r2", pub, sec, d / "server_sign.pub", d / "server_sign.key", min_counter=1)


def test_failed_restore_leaves_no_partial_directory(w, tmp_path, bk):
    out, pub, sec = bk
    d = tmp_path / "data"
    with pytest.raises(Exception):
        b.restore(out, tmp_path / "r3", pub, sec, d / "server_sign.pub", d / "nonexistent.key", accept_rollback=True)
    assert not (tmp_path / "r3").exists() and not (tmp_path / "r3.partial").exists()
