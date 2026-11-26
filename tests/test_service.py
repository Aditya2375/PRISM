import copy

import pytest

from kig.service import GRACE_S
from kig import crypto as c
from kig.client import Client, Device
from kig.service import GuardService

from conftest import code


def alerts(w, rule=None):
    return [a for a in w.svc.alerts() if rule is None or a["rule"] == rule]


def test_normal_operation(w):
    assert w.bob.fetch("report") == b"top secret payroll"
    assert w.admin.fetch("report") == b"top secret payroll"
    types = [e["type"] for e in w.svc.audit.entries]
    assert types.count("access.granted") == 2
    assert w.svc.audit.verify() == (True, "ok")


def test_service_never_holds_plaintext_or_dek(w):
    blob = str(w.svc.state)
    assert "top secret" not in blob
    f = w.svc.state["files"]["report"]
    # wraps exist only for devices that existed at creation (admin laptop, phone, bob)
    assert set(f["wraps"]) == {"alice-laptop", "alice-phone", "bob-laptop"}


def test_lost_device_scenario(w):
    # The user's phone is reported lost: access is cut, file keys rotate, operator sees it.
    stolen = Client(w.alice_phone, w.svc.handle, w.clock)
    assert stolen.fetch("report", auto_rotate=False) == b"top secret payroll"
    w.clock.tick(5)
    r = w.admin.call("report_lost", device="alice-phone", reason="phone stolen")
    assert r["files_needing_rotation"] == ["report"]
    assert "alice-phone" not in w.svc.state["files"]["report"]["wraps"]
    w.clock.tick(5)
    assert code(stolen.fetch, "report") == "revoked"
    crit = alerts(w, "R1-REVOKED-DEVICE-USE")
    assert len(crit) == 1 and crit[0]["severity"] == "critical"
    lost_seq = next(e["seq"] for e in w.svc.audit.entries if e["type"] == "device.lost")
    assert lost_seq in crit[0]["evidence"]
    # a member's fetch reads but cannot re-key; the next fetch by the owner or an admin does
    assert w.bob.fetch("report") == b"top secret payroll"
    assert w.svc.state["files"]["report"]["needs_rotation"]
    assert w.admin.fetch("report") == b"top secret payroll"
    f = w.svc.state["files"]["report"]
    assert f["epoch"] == 2 and not f["needs_rotation"]
    assert set(f["wraps"]) == {"alice-laptop", "bob-laptop"}
    assert w.svc.audit.verify() == (True, "ok")


def test_old_wrap_cannot_decrypt_new_epoch(w):
    old = w.svc.state["files"]["report"]["wraps"]["alice-phone"]
    w.admin.call("revoke_device", device="alice-phone")
    w.admin.fetch("report")  # rotates
    new_ct = c.b64d(w.svc._load_blob(w.svc.state["files"]["report"]["ct"]))
    phone = Client(w.alice_phone, w.svc.handle, w.clock)
    dek_old = phone._unwrap(old, "report", 1)
    try:
        c.aead_decrypt(dek_old, new_ct, b"kig/v1/file|report|2")
        raise AssertionError("old key decrypted new epoch")
    except c.CryptoError:
        pass


def test_replay_and_stale_and_bad_signature(w):
    env = w.bob.envelope("fetch", {"file_id": "report"})
    w.svc.handle(env)
    assert code(w.svc.handle, copy.deepcopy(env), "attacker-ip") == "replay"
    assert alerts(w, "R2-REPLAY")
    assert w.bob.fetch("report") == b"top secret payroll"  # victim is not locked out
    old = w.bob.envelope("fetch", {"file_id": "report"})
    w.clock.tick(60)
    assert code(w.svc.handle, old) == "stale"
    forged = w.bob.envelope("fetch", {"file_id": "report"})
    forged["args"]["file_id"] = "other"
    assert code(w.svc.handle, forged) == "unauthorized"


def test_auth_failure_burst_alerts_but_never_locks_anyone_out(w):
    for _ in range(3):
        e = w.bob.envelope("fetch", {"file_id": "report"})
        e["sig"] = c.b64e(b"x" * 3309)
        code(w.svc.handle, e, "attacker-ip")
    burst = alerts(w, "R3-AUTH-FAILURE-BURST")
    assert len(burst) == 1 and len(burst[0]["evidence"]) == 3
    good = w.bob.envelope("fetch", {"file_id": "report"})
    assert code(w.svc.handle, good, "attacker-ip") is None          # same source, valid signature: served
    assert w.bob.fetch("report") == b"top secret payroll"


def test_unknown_device_cannot_do_anything(w):
    rogue = Client(Device.generate("rogue", "alice"), w.svc.handle, w.clock)
    assert code(rogue.fetch, "report") == "unauthorized"


def test_authorization_rules(w):
    assert code(w.bob.call, "create_user", user="eve", role="admin") == "forbidden"
    assert code(w.bob.call, "revoke_device", device="alice-laptop") == "forbidden"
    assert code(w.bob.call, "set_role", user="bob", role="admin") == "forbidden"
    w.admin.call("create_user", user="carol")
    cd = Device.generate("carol-pc", "carol")
    w.admin.call("enroll_device", **cd.public_args())
    carol = Client(cd, w.svc.handle, w.clock)
    assert code(carol.fetch, "report") == "forbidden"  # not in acl



def test_privilege_escalation_alert(w):
    w.admin.call("create_user", user="mallory")
    cd = Device.generate("mallory-pc", "mallory")
    w.admin.call("enroll_device", **cd.public_args())
    w.clock.tick(30)
    w.admin.call("set_role", user="mallory", role="admin")
    a = alerts(w, "R4-PRIVILEGE-ESCALATION")
    assert len(a) == 1 and a[0]["severity"] == "critical"  # fresh account
    assert a[0]["subject"] == "mallory"


def test_cannot_demote_last_admin_or_disable_self(w):
    assert code(w.admin.call, "set_role", user="alice", role="member") == "conflict"
    assert code(w.admin.call, "disable_user", user="alice") == "conflict"


def test_disable_user_revokes_all_devices(w):
    w.admin.call("disable_user", user="bob")
    assert w.svc.state["devices"]["bob-laptop"]["status"] == "revoked"
    assert code(w.bob.fetch, "report") == "revoked"


def test_rotation_conflict_and_idempotent_revoke(w):
    r1 = w.admin.call("revoke_device", device="alice-phone")
    r2 = w.admin.call("revoke_device", device="alice-phone")
    assert r2["already"] == "revoked" and r1["ok"]
    e = w.admin.fetch("report", auto_rotate=False)
    assert e == b"top secret payroll"
    w.admin.rotate("report")
    # a client holding the old epoch is rejected, not silently overwriting
    stale_args = dict(file_id="report", expected_epoch=1, ciphertext="AA==", wraps={})
    assert code(w.admin.call, "rotate", **stale_args) == "conflict"


def test_acl_change_requires_owner_or_admin_and_removes_access(w):
    w.admin.rotate("report", acl=["alice"])
    assert code(w.bob.fetch, "report") == "forbidden"
    assert set(w.svc.state["files"]["report"]["wraps"]) == {"alice-laptop", "alice-phone"}


def test_restart_persists_state_and_chain(w, tmp_path):
    w.admin.call("revoke_device", device="alice-phone")
    svc2 = GuardService(tmp_path / "data", clock=w.clock)
    assert svc2.state["devices"]["alice-phone"]["status"] == "revoked"
    assert svc2.audit.verify() == (True, "ok")
    w.clock.tick(1)
    admin2 = Client(w.alice_laptop, svc2.handle, w.clock)
    assert admin2.fetch("report") == b"top secret payroll"


def test_replay_across_restart_is_refused(w, tmp_path):
    env = w.bob.envelope("fetch", {"file_id": "report"})
    w.svc.handle(env)
    w.clock.tick(1)
    svc2 = GuardService(tmp_path / "data", clock=w.clock)
    assert code(svc2.handle, copy.deepcopy(env)) == "stale"


def test_crash_between_audit_and_state_fails_closed(w, tmp_path):
    # Simulate: audit entry for the revocation was written, state file was not.
    svc = w.svc
    svc.audit.append(w.clock(), "device.lost", "alice-laptop",
                     {"device": "alice-phone", "user": "alice", "by": "alice", "reason": "", "files_needing_rotation": []})
    svc2 = GuardService(tmp_path / "data", clock=w.clock)
    assert svc2.state["devices"]["alice-phone"]["status"] == "lost"
    assert "alice-phone" not in svc2.state["files"]["report"]["wraps"]
    assert svc2.state["files"]["report"]["needs_rotation"]


def test_malformed_envelopes_are_rejected_not_crashing(w):
    for bad in ({}, {"cmd": 1}, {"cmd": "x", "device": "d", "ts": "no", "nonce": "n", "args": {}, "sig": "!!"},
                {"cmd": "fetch", "device": "bob-laptop", "ts": True, "nonce": "n", "args": {}, "sig": ""}):
        assert code(w.svc.handle, bad) in ("bad_request",)


def test_device_ids_never_reused(w):
    again = Device.generate("alice-phone", "alice")
    assert code(w.admin.call, "enroll_device", **again.public_args()) == "conflict"


def test_bootstrap_only_once(w):
    d = Device.generate("x", "x")
    assert code(w.svc.bootstrap, "x", "x", d.sign_pub, d.kem_pub) == "already_bootstrapped"


def test_nan_and_bool_fields_rejected(w):
    import json as _j
    from kig import crypto as cc
    body = {"cmd": "whoami", "device": "bob-laptop", "ts": float("nan"), "nonce": "n1", "args": {}}
    body["sig"] = cc.b64e(cc.sign(w.bob_laptop.sign_sec, "cmd", cc.canonical(body)))
    assert code(w.svc.handle, body) == "bad_request"
    r = w.admin.fetch("report", auto_rotate=False)
    assert code(w.admin.call, "rotate", file_id="report", expected_epoch=True, ciphertext="AA==", wraps={}) == "conflict"


def test_unauthenticated_floods_cannot_grow_the_audit_log(w):
    n = len(w.svc.audit.entries)
    for i in range(500):
        e = w.bob.envelope("fetch", {"file_id": "report"})
        e["sig"] = c.b64e(b"x" * 3309)
        e["device"] = f"ghost-{i}" if i % 2 else "bob-laptop"
        code(w.svc.handle, e, f"10.0.0.{i % 200}")
    assert len(w.svc.audit.entries) - n <= 80
    w.clock.tick(61)
    code(w.svc.handle, w.bob.envelope("whoami"), "x")                # next minute: one summary line
    assert any(e["type"] == "auth.failures_suppressed" and e["data"]["count"] > 400 for e in w.svc.audit.entries)


def test_identical_retry_is_refused_quietly_and_never_penalised(w):
    env = w.bob.envelope("whoami")
    w.svc.handle(env, "1.1.1.1")
    n = len(w.svc.audit.entries)
    assert code(w.svc.handle, copy.deepcopy(env), "1.1.1.1") == "replay"
    assert len(w.svc.audit.entries) == n and not alerts(w, "R2-REPLAY")
    assert w.svc.handle(w.bob.envelope("whoami"), "1.1.1.1")["user"] == "bob"
    # the same envelope from a different address IS suspicious: logged and alerted, still not a lockout
    assert code(w.svc.handle, copy.deepcopy(env), "6.6.6.6") == "replay"
    assert alerts(w, "R2-REPLAY")
    assert w.svc.handle(w.bob.envelope("whoami"), "6.6.6.6")["user"] == "bob"


def test_revoked_use_logs_are_bounded_but_alert_once(w):
    stolen = Client(w.alice_phone, w.svc.handle, w.clock)
    w.admin.call("report_lost", device="alice-phone")
    for _ in range(50):
        code(stolen.fetch, "report")
    assert len(alerts(w, "R1-REVOKED-DEVICE-USE")) == 1
    assert 1 <= sum(e["type"] == "auth.revoked_device_use" for e in w.svc.audit.entries) <= 3


def test_per_device_rate_limit_is_silent_and_recovers(w):
    from kig.service import DEVICE_RATE_PER_MIN
    n = len(w.svc.audit.entries)
    outcomes = [code(w.bob.call, "whoami") for _ in range(DEVICE_RATE_PER_MIN + 20)]
    assert outcomes.count("rate_limited") >= 15
    assert len(w.svc.audit.entries) == n
    w.clock.tick(61)
    assert w.bob.call("whoami")["user"] == "bob"


def test_audit_truncation_detected_on_restart(w, tmp_path):
    import pytest
    from kig.audit import AuditError
    w.admin.call("revoke_device", device="alice-phone")
    p = tmp_path / "data" / "audit.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-2]) + "\n")  # drop the newest entries (chain still valid)
    with pytest.raises(AuditError):
        GuardService(tmp_path / "data", clock=w.clock)


def test_user_text_cannot_forge_a_second_event_or_actor(w):
    evil = 'x"}\n{"seq":99,"type":"device.enrolled","actor":"alice-laptop","data":{}}\r\n'
    before = len(w.svc.audit.entries)
    w.admin.call("revoke_device", device="alice-phone", reason=evil)
    assert w.svc.audit.verify() == (True, "ok")
    raw = (w.svc.dir / "audit.jsonl").read_text().splitlines()
    assert len(raw) == len(w.svc.audit.entries)           # exactly one line per event
    new = w.svc.audit.entries[before:]
    assert all(e["actor"] in ("alice-laptop", "detector") for e in new)
    assert [e["type"] for e in new if e["type"] == "device.revoked"] == ["device.revoked"]
    # a hostile device id string cannot become the recorded actor of a real device
    rogue = Client(Device.generate("alice-laptop\nfake", "alice"), w.svc.handle, w.clock)
    assert code(rogue.fetch, "report") == "unauthorized"
    assert w.svc.audit.entries[-1]["actor"] == "unknown"


def test_client_detects_version_rollback(w):
    assert w.bob.fetch("report", auto_rotate=False) == b"top secret payroll"
    w.admin.rotate("report")
    assert w.bob.fetch("report", auto_rotate=False) == b"top secret payroll"
    f = w.svc.state["files"]["report"]
    f["epoch"] = 1                                   # a malicious server serves the old version again
    f["wraps"] = f["prev"]["wraps"]; f["ct"] = f["prev"]["ct"]
    from kig import crypto as c
    with pytest.raises(c.CryptoError, match="rollback"):
        w.bob.fetch("report", auto_rotate=False)


def test_torn_revoked_log_line_is_ignored(w, tmp_path):
    w.admin.call("revoke_device", device="bob-laptop")
    with open(tmp_path / "data" / "revoked.log", "a") as fh:
        fh.write("alice-lap")                         # torn, never acknowledged
    svc2 = GuardService(tmp_path / "data", clock=w.clock)
    assert svc2.revoked == {"bob-laptop"}


def test_ciphertext_blobs_are_content_addressed_verified_and_collected(w, tmp_path):
    f = w.svc.state["files"]["report"]
    assert "ciphertext" not in f and len(f["ct"]) == 64
    assert (tmp_path / "data" / "blobs" / f["ct"][:2] / f["ct"]).exists()
    assert len((tmp_path / "data" / "state.json").read_bytes()) < 40000
    w.admin.rotate("report")
    w.admin.rotate("report")
    blobs = [p for p in (tmp_path / "data" / "blobs").rglob("*") if p.is_file()]
    assert len(blobs) == 2                      # current + previous only; older ones removed
    # silent bit rot or tampering on disk fails closed and is logged
    cur = tmp_path / "data" / "blobs" / w.svc.state["files"]["report"]["ct"][:2] / w.svc.state["files"]["report"]["ct"]
    raw = bytearray(cur.read_bytes()); raw[-1] ^= 1; cur.write_bytes(bytes(raw))
    assert code(w.bob.fetch, "report", False) == "storage_corrupt"
    assert any(e["type"] == "storage.corrupt" for e in w.svc.audit.entries)


def test_orphan_blob_from_a_crash_is_collected_on_restart(w, tmp_path):
    w.svc._store_blob(b"orphan bytes from an interrupted put")
    GuardService(tmp_path / "data", clock=w.clock)
    assert len([p for p in (tmp_path / "data" / "blobs").rglob("*") if p.is_file()]) == 1
