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


def test_rotate_pending_cli_rekeys_flagged_files(w, tmp_path, capsys):
    from kig import cli
    new = Device.generate("bob-phone", "bob")
    w.admin.call("enroll_device", **new.public_args())
    assert w.svc.state["files"]["report"]["needs_rotation"]
    w.alice_laptop.save(tmp_path / "a.json")
    cli_send = lambda env: w.svc.handle(env, "cli")
    orig, orig_client = cli._post, cli.Client
    cli._post = lambda url: cli_send
    cli.Client = lambda dev, send, **kw: orig_client(dev, send, w.clock, **kw)
    try:
        w.clock.tick(1)
        cli.main(["rotate-pending", "--url", "http://x", "--key", str(tmp_path / "a.json")])
    finally:
        cli._post, cli.Client = orig, orig_client
    assert not w.svc.state["files"]["report"]["needs_rotation"]
    assert json.loads(capsys.readouterr().out)["rotated"] == ["report"]


def test_restore_records_which_checks_were_accepted_in_the_audit_chain(w, tmp_path, bk):
    out, pub, sec = bk
    d = tmp_path / "data"
    b.restore(out, tmp_path / "r", pub, sec, d / "server_sign.pub", d / "server_sign.key", accept_rollback=True)
    svc2 = GuardService(tmp_path / "r", clock=w.clock)
    e = [x for x in svc2.audit.entries if x["type"] == "restore.completed"]
    assert len(e) == 1 and set(e[0]["data"]["unchecked"]) == {"counter", "revocations"}
    assert svc2.audit.verify() == (True, "ok")


def test_accepting_counter_rollback_does_not_waive_the_revocation_check(w, tmp_path, bk):
    out, pub, sec = bk
    d = tmp_path / "data"
    with pytest.raises(b.BackupError):
        b.restore(out, tmp_path / "r", pub, sec, d / "server_sign.pub", d / "server_sign.key", accept_counter_rollback=True)
    with pytest.raises(b.BackupError):
        b.restore(out, tmp_path / "r", pub, sec, d / "server_sign.pub", d / "server_sign.key", live_revoked_log=d / "revoked.log")


def test_backup_counter_is_in_signed_state(w, tmp_path):
    pub, _ = c.kem_keygen()
    b.create(w.svc, pub, tmp_path / "1.bak")
    assert GuardService(tmp_path / "data", clock=w.clock).state["backup_counter"] == 1


def test_proxy_hops_pick_the_address_the_trusted_proxy_appended(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from kig.api import create_app
    monkeypatch.setenv("KIG_PROXY_HOPS", "2")
    app = create_app(tmp_path / "d", trust_proxy=True)
    cl = TestClient(app, raise_server_exceptions=False)
    for i in range(5):
        cl.post("/v1/command", json={"cmd": "x"}, headers={"x-forwarded-for": f"9.9.9.{i}, 203.0.113.5, 10.0.0.1"})
    assert [k for k in app.state.service._rate if k.startswith("srcfail:")] == ["srcfail:203.0.113.5"]


def test_post_auth_log_extras_are_capped_but_first_line_per_device_is_kept(w):
    from kig.service import POST_AUTH_EXTRA_LOG_MIN
    assert POST_AUTH_EXTRA_LOG_MIN <= 300
    stolen = Client(w.alice_phone, w.svc.handle, w.clock)
    w.admin.call("report_lost", device="alice-phone")
    n = len(w.svc.audit.entries)
    w.svc._ua_post = POST_AUTH_EXTRA_LOG_MIN          # global extras budget already used up this minute
    code(stolen.fetch, "report")
    assert any(e["type"] == "auth.revoked_device_use" for e in w.svc.audit.entries[n:])
    m = len(w.svc.audit.entries)
    for _ in range(5):
        code(stolen.fetch, "report")
    assert not any(e["type"] == "auth.revoked_device_use" for e in w.svc.audit.entries[m:])


def test_replica_generation_orders_snapshots_before_version(tmp_path):
    from kig.service import GuardService
    from conftest import Clock
    clock = Clock(); p = GuardService(tmp_path / "p", clock=clock); clock.tick(1)
    a = Device.generate("a-1", "a"); p.bootstrap("a", "a-1", a.sign_pub, a.kem_pub)
    rep = GuardService(tmp_path / "r", clock=clock, name="r", read_only=True)
    assert rep.install_snapshot(p.export_snapshot(), p.pub) is True
    p.state["restore_generation"] = 1                     # a restored primary with a shorter log
    assert rep.install_snapshot(p.export_snapshot(), p.pub) is True
    assert GuardService(tmp_path / "r", clock=clock, name="r", read_only=True).snapshot_generation == 1
    p.state["restore_generation"] = 0
    assert rep.install_snapshot(p.export_snapshot(), p.pub) is False


def test_bad_proxy_hops_fails_at_startup(tmp_path, monkeypatch):
    from kig.api import create_app
    monkeypatch.setenv("KIG_PROXY_HOPS", "0")
    with pytest.raises(ValueError):
        create_app(tmp_path / "d", trust_proxy=True)


def test_restoring_the_same_backup_twice_advances_the_generation(w, tmp_path, bk):
    out, pub, sec = bk
    d = tmp_path / "data"
    gens = []
    for name in ("r1", "r2"):
        b.restore(out, tmp_path / name, pub, sec, d / "server_sign.pub", d / "server_sign.key", accept_rollback=True)
        gens.append(GuardService(tmp_path / name, clock=w.clock).state["restore_generation"])
    assert gens[1] > gens[0]
