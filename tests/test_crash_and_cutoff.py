import json

import pytest

from kig.service import GuardService, SimulatedCrash, GRACE_S
from kig.client import Client

from conftest import World, code


def restart(w, tmp_path):
    return GuardService(tmp_path / "data", clock=w.clock)


# ---- rotation cutoff ------------------------------------------------------

def test_grace_then_cutoff(w):
    w.admin.rotate("report")                                  # epoch 1 -> 2
    # in-flight transfer of the old version still works inside the grace window
    assert w.bob.fetch("report", auto_rotate=False, epoch=1) == b"top secret payroll"
    assert any(e["type"] == "access.granted_grace" for e in w.svc.audit.entries)
    w.clock.tick(GRACE_S + 1)
    assert code(w.bob.fetch, "report", False, 1) == "key_version_retired"  # past cutoff
    assert w.bob.fetch("report") == b"top secret payroll"      # current version unaffected


def test_revoked_device_gets_no_grace(w):
    w.admin.call("revoke_device", device="bob-laptop")
    w.admin.rotate("report")
    assert code(w.bob.fetch, "report", False, 1) == "revoked"
    assert w.svc.state["files"]["report"]["prev"]["wraps"].keys().isdisjoint({"bob-laptop"})


def test_unknown_epoch_rejected(w):
    assert code(w.bob.fetch, "report", False, 7) == "key_version_retired"


# ---- crash recovery -------------------------------------------------------

@pytest.mark.parametrize("point", ["after_revoked_journal", "after_audit", "before_state_rename"])
def test_crash_during_revocation_never_loses_it(w, tmp_path, point):
    w.svc.crash_at = point
    with pytest.raises(SimulatedCrash):
        w.admin.call("report_lost", device="alice-phone", reason="stolen")
    svc2 = restart(w, tmp_path)
    assert svc2.state["devices"]["alice-phone"]["status"] in ("lost", "revoked")
    assert "alice-phone" not in svc2.state["files"]["report"]["wraps"]
    assert svc2.audit.verify() == (True, "ok")
    stolen = Client(w.alice_phone, svc2.handle, w.clock)
    w.clock.tick(1)
    assert code(stolen.fetch, "report") == "revoked"


def _state_files(d):
    return (d / "state.json").read_text(), ((d / "state.wal").read_text() if (d / "state.wal").exists() else "")


def _put_state_files(d, snap, wal):
    (d / "state.json").write_text(snap)
    (d / "state.wal").write_text(wal)


def test_state_file_rollback_cannot_resurrect_a_revoked_device(w, tmp_path):
    stale = _state_files(tmp_path / "data")
    w.admin.call("revoke_device", device="alice-phone")
    _put_state_files(tmp_path / "data", *stale)   # attacker or bad restore
    # the audit log is now ahead of state, and revoked.log has the device
    svc2 = restart(w, tmp_path)
    assert svc2.state["devices"]["alice-phone"]["status"] != "active"
    assert "alice-phone" not in svc2.state["files"]["report"]["wraps"]


def test_tampered_state_file_is_refused_not_used(w, tmp_path):
    from kig.service import StateCorrupt
    d = tmp_path / "data"
    w.svc.store.force_snapshot = True
    w.svc._persist()                                           # full snapshot on disk
    good = _state_files(d)
    st = json.loads(good[0])
    st["users"]["bob"]["role"] = "admin"                       # privilege edit on disk
    (d / "state.json").write_text(json.dumps(st))
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)
    (d / "state.json").write_text("{not json")
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)


def test_tampered_or_reordered_journal_is_refused(w, tmp_path):
    from kig.service import StateCorrupt
    d = tmp_path / "data"
    snap, wal = _state_files(d)
    lines = wal.splitlines()
    assert len(lines) >= 3
    doc = json.loads(lines[1])
    doc["e"]["sec"].setdefault("users", {})["bob"] = {"role": "admin", "active": True}
    bad = [lines[0], json.dumps(doc)] + lines[2:]
    _put_state_files(d, snap, "\n".join(bad) + "\n")
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)
    _put_state_files(d, snap, "\n".join([lines[1], lines[0]] + lines[2:]) + "\n")   # reordered
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)
    _put_state_files(d, snap, "\n".join([lines[0]] + lines[2:]) + "\n")             # entry removed from the middle
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)


def test_torn_journal_tail_is_dropped_and_next_write_is_clean(w, tmp_path):
    d = tmp_path / "data"
    with open(d / "state.wal", "ab") as fh:
        fh.write(b'{"e": {"base": "x", "seq"')
    svc2 = restart(w, tmp_path)
    w.clock.tick(1)
    Client(w.alice_laptop, svc2.handle, w.clock).call("create_user", user="carol", role="member")
    assert restart(w, tmp_path).state["users"]["carol"]["role"] == "member"


def test_revoked_set_is_enforced_when_state_is_restored_from_old_signed_copy(w, tmp_path):
    d = tmp_path / "data"
    old = _state_files(d)                                       # valid, signed, but before the revoke
    w.admin.call("revoke_device", device="alice-phone")
    _put_state_files(d, *old)
    svc2 = restart(w, tmp_path)
    assert svc2.state["devices"]["alice-phone"]["status"] != "active"


def test_rolling_back_state_and_audit_together_is_refused_at_start(w, tmp_path):
    import pytest
    from kig.audit import AuditError
    d = tmp_path / "data"
    old = _state_files(d)
    w.admin.call("revoke_device", device="alice-phone")
    _put_state_files(d, *old)
    lines = (d / "audit.jsonl").read_text().splitlines()
    n = next(i for i, l in enumerate(lines) if json.loads(l)["type"] == "device.revoked")
    (d / "audit.jsonl").write_text("\n".join(lines[:n]) + "\n")   # audit also rolled back: head anchor disagrees
    with pytest.raises(AuditError):
        restart(w, tmp_path)


def test_torn_audit_append_is_recovered(w, tmp_path):
    p = tmp_path / "data" / "audit.jsonl"
    with open(p, "ab") as fh:
        fh.write(b'{"seq": 99, "ts": 1, "pre')                 # crash mid-append
    svc2 = restart(w, tmp_path)
    assert svc2.audit.verify() == (True, "ok")
    assert svc2.audit.entries[-1]["type"] == "service.recovered"
    assert svc2.audit.entries[-1]["data"]["dropped_torn_bytes"] > 0
    w.clock.tick(1)
    assert Client(w.bob_laptop, svc2.handle, w.clock).fetch("report") == b"top secret payroll"


def test_crash_during_rotation_leaves_last_consistent_version(w, tmp_path):
    w.svc.crash_at = "before_state_rename"
    with pytest.raises(SimulatedCrash):
        w.admin.rotate("report")
    svc2 = restart(w, tmp_path)
    w.clock.tick(1)
    # whichever version survived, every eligible device can still read the file
    f = svc2.state["files"]["report"]
    assert f["epoch"] in (1, 2)
    for dev in (w.alice_laptop, w.bob_laptop):
        assert Client(dev, svc2.handle, w.clock).fetch("report", auto_rotate=False) == b"top secret payroll"


def test_corruption_in_middle_of_audit_is_not_silently_repaired(w, tmp_path):
    import kig.audit as a
    p = tmp_path / "data" / "audit.jsonl"
    lines = p.read_text().splitlines()
    lines[2] = lines[2][:-10]
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(a.AuditError):
        restart(w, tmp_path)


# ---- rotation crash matrix --------------------------------------------------

ROT_POINTS = ["rotate_before_prepare", "rotate_after_prepare", "rotate_mid_commit", "rotate_after_commit"]


@pytest.mark.parametrize("point", ROT_POINTS)
def test_rotation_crash_leaves_one_consistent_version(w, tmp_path, point):
    w.admin.call("revoke_device", device="alice-phone")
    revoked_before = set(w.svc.revoked)
    w.svc.crash_at = point
    with pytest.raises(SimulatedCrash):
        w.admin.rotate("report")
    svc2 = restart(w, tmp_path)
    f = svc2.state["files"]["report"]
    assert f["epoch"] in (1, 2)
    assert f["epoch"] == (2 if point in ("rotate_mid_commit", "rotate_after_commit") else 1)
    assert svc2.revoked == revoked_before
    assert svc2.audit.verify() == (True, "ok")
    assert not any(e["type"] == "file.rotate_prepared" for e in svc2.audit.entries) or any(
        e["type"] in ("file.rotated", "file.rotate_recovered", "file.rotate_aborted") for e in svc2.audit.entries)
    w.clock.tick(1)
    assert Client(w.bob_laptop, svc2.handle, w.clock).fetch("report") == b"top secret payroll"
