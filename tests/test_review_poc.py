"""Adversarial review PoCs. Each test ASSERTS THE SAFE BEHAVIOUR, so a FAILURE = a confirmed finding."""
import json, os
from pathlib import Path
import pytest
from kig import backup, crypto as c, vault
from kig.client import Client, Device
from kig.service import Denied, GuardService
from kig.audit import AuditError
from conftest import World, Clock, code


def test_F1_missing_state_json_must_not_wipe_and_rebootstrap(w, tmp_path):
    d = w.svc.dir
    assert any((d / "blobs").rglob("*")) 
    os.unlink(d / "state.json")
    try:
        svc2 = GuardService(d, clock=w.clock)
    except Exception:
        return  # refusing to start is the safe outcome
    blobs = [p for p in (d / "blobs").rglob("*") if p.is_file()]
    assert blobs, "all ciphertext blobs were garbage-collected after state.json vanished"
    assert svc2.state["users"], "service came up with an empty identity directory (re-bootstrap possible)"


def test_F2_restore_with_passphrase_sealed_service_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISM_PASSPHRASE", "correct horse")
    clock = Clock(); svc = GuardService(tmp_path / "live", clock=clock); clock.tick(1)
    dev = Device.generate("a-1", "a"); svc.bootstrap("a", "a-1", dev.sign_pub, dev.kem_pub)
    bp, bs = c.kem_keygen(); out = tmp_path / "b.json"; backup.create(svc, bp, out)
    dest = tmp_path / "dest"
    backup.restore(out, dest, bp, bs, svc.dir / "server_sign.pub", svc.dir / "server_sign.key", min_counter=1, accept_rollback=True)
    GuardService(dest, clock=clock)  # must open


def test_F2b_failed_restore_leaves_dest_unusable(tmp_path):
    clock = Clock(); svc = GuardService(tmp_path / "live", clock=clock); clock.tick(1)
    dev = Device.generate("a-1", "a"); svc.bootstrap("a", "a-1", dev.sign_pub, dev.kem_pub)
    bp, bs = c.kem_keygen(); out = tmp_path / "b.json"; backup.create(svc, bp, out)
    dest = tmp_path / "dest"
    bad_key = tmp_path / "bad.key"; bad_key.write_bytes(b"x" * 10)
    with pytest.raises(Exception):
        backup.restore(out, dest, bp, bs, svc.dir / "server_sign.pub", bad_key, min_counter=1, accept_rollback=True)
    # retry with the right key must work; instead dest is half-written and refused
    backup.restore(out, dest, bp, bs, svc.dir / "server_sign.pub", svc.dir / "server_sign.key", min_counter=1, accept_rollback=True)


def test_F3_old_backup_into_fresh_dir_resurrects_revoked_device(w, tmp_path):
    bp, bs = c.kem_keygen()
    old = tmp_path / "old.bak"; backup.create(w.svc, bp, old)
    w.admin.call("revoke_device", device="bob-laptop")
    new = tmp_path / "new.bak"; backup.create(w.svc, bp, new)
    dest = tmp_path / "dr"   # disaster recovery into a clean dir: no live dir, no live revoked.log
    try:
        backup.restore(old, dest, bp, bs, w.svc.dir / "server_sign.pub", w.svc.dir / "server_sign.key")
    except backup.BackupError:
        return
    svc = GuardService(dest, clock=w.clock)
    assert svc.state["devices"]["bob-laptop"]["status"] != "active", "stale backup re-activated a revoked device"


def test_F4_server_can_defeat_client_rollback_check_with_grace_field(w):
    cl = w.bob
    w.admin.rotate("report"); cl.fetch("report")
    assert cl.seen_epoch["report"] == 2
    r = w.bob.call("fetch", file_id="report", epoch=1)      # epoch-1 material the server still holds
    assert r["epoch"] == 1 and "grace_remaining_s" in r
    r_plain = {k: v for k, v in r.items() if k != "grace_remaining_s"}
    cl.send = lambda env: r_plain
    with pytest.raises(c.CryptoError):
        cl.fetch("report")                                   # honest rollback IS caught
    r_forged = dict(r); r_forged["grace_remaining_s"] = 1.0  # server-controlled field
    cl.send = lambda env: r_forged
    with pytest.raises(c.CryptoError):                       # SAFE behaviour; the forged field bypasses it today
        cl.fetch("report")


def test_F5_torn_revoked_log_swallows_next_revocation(w):
    d = w.svc.dir
    with open(d / "revoked.log", "ab") as fh:
        fh.write(b"alice-pho")             # torn, unacknowledged partial line (crash mid-append)
    svc = GuardService(d, clock=w.clock); w.clock.tick(1)
    svc.bootstrap if False else None
    adm = Client(w.alice_laptop, svc.handle, w.clock)
    adm.call("revoke_device", device="bob-laptop")
    svc2 = GuardService(d, clock=w.clock)
    assert "bob-laptop" in svc2.revoked, "revocation was glued onto the torn line and lost from revoked.log"


def test_F6_overflow_ts_is_clean_400(w):
    env = w.admin.envelope("whoami"); env["ts"] = 10 ** 400
    with pytest.raises(Denied) as e:
        w.svc.handle(env)
    assert e.value.status == 400


def test_F6b_deep_json_is_clean_400(tmp_path):
    from fastapi.testclient import TestClient
    from kig.api import create_app
    app = create_app(tmp_path / "d")
    cl = TestClient(app, raise_server_exceptions=False)
    r = cl.post("/v1/command", content=b"[" * 200000)
    assert r.status_code == 400


def test_F7_attacker_sharing_source_ip_can_lock_victim(w):
    # same source address = NAT, corporate proxy, or any reverse proxy (client.host is the proxy)
    for _ in range(3):
        env = w.bob.envelope("whoami"); env["sig"] = c.b64e(b"\0" * 3309)
        with pytest.raises(Denied):
            w.svc.handle(env, source="10.0.0.1")
    w.clock.tick(1)
    assert w.svc.handle(w.bob.envelope("whoami"), source="10.0.0.1")["user"] == "bob"


def test_F7b_client_retry_of_same_envelope_locks_itself(w):
    env = w.bob.envelope("whoami")
    w.svc.handle(env, source="1.1.1.1")
    with pytest.raises(Denied):
        w.svc.handle(env, source="1.1.1.1")   # legit network retry
    w.clock.tick(1)
    assert w.svc.handle(w.bob.envelope("whoami"), source="1.1.1.1")["user"] == "bob"


def test_F8_install_snapshot_failure_must_not_mutate_live_state(w, tmp_path):
    rep = GuardService(tmp_path / "rep", clock=w.clock, name="r", read_only=True)
    snap = w.svc.export_snapshot(have=set(w.svc.blob_hashes()))  # caller claims to hold blobs it lacks
    before = json.dumps(rep.state, sort_keys=True)
    with pytest.raises(Denied):
        rep.install_snapshot(snap, w.svc.pub)
    assert json.dumps(rep.state, sort_keys=True) == before


def test_F9_replica_restart_accepts_older_signed_snapshot(w, tmp_path):
    rep_dir = tmp_path / "rep"
    rep = GuardService(rep_dir, clock=w.clock, name="r", read_only=True)
    old = w.svc.export_snapshot(); rep.install_snapshot(old, w.svc.pub)
    w.admin.call("disable_user", user="bob") if False else None
    w.admin.rotate("report", acl=["alice"])        # bob removed from ACL
    new = w.svc.export_snapshot(); rep.install_snapshot(new, w.svc.pub)
    rep2 = GuardService(rep_dir, clock=w.clock, name="r", read_only=True)   # restart
    assert rep2.install_snapshot(old, w.svc.pub) is False, "older signed snapshot (bob in ACL) was re-installed"


def test_F10_new_device_of_existing_user_is_never_flagged_for_wrapping(w):
    phone2 = Device.generate("bob-phone", "bob")
    w.admin.call("enroll_device", **phone2.public_args())
    files = Client(phone2, w.svc.handle, w.clock).call("list_files")["files"]
    assert files[0]["needs_rotation"], "file the new device cannot decrypt is not flagged; it is silently inaccessible"


def test_F11_unauthenticated_flood_grows_signed_audit_log_unboundedly(w):
    n0 = len(w.svc.audit.entries)
    for i in range(300):
        env = w.bob.envelope("whoami"); env["device"] = f"ghost-{i}"
        with pytest.raises(Denied):
            w.svc.handle(env, source=f"9.9.9.{i % 250}")
    assert len(w.svc.audit.entries) - n0 < 50, f"{len(w.svc.audit.entries)-n0} fsynced+signed entries from unauthenticated traffic"


def test_F12_any_acl_member_can_destroy_a_file_for_everyone_else(w):
    bad = w.bob._wrap_for(c.random_key(), "report", 2, w.bob._recipients(["alice", "bob"]))
    with pytest.raises(Denied) as e:
        w.bob.call("rotate", file_id="report", expected_epoch=1, ciphertext=c.b64e(os.urandom(64)), wraps=bad,
                   commit="0" * 64)
    assert e.value.code == "forbidden"
    w.clock.tick(31)
    assert w.admin.fetch("report") == b"top secret payroll", "member's garbage rotation destroyed the file for the owner"


def test_F13_audit_tail_truncation_plus_ckpt_delete_goes_undetected(w):
    d = w.svc.dir
    for i in range(2):
        env = w.bob.envelope("whoami"); env["device"] = f"ghost-{i}"
        with pytest.raises(Denied):
            w.svc.handle(env)
    p = d / "audit.jsonl"; lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:-2]))
    (d / "audit.ckpt").unlink(missing_ok=True)
    with pytest.raises(AuditError):
        GuardService(d, clock=w.clock)
