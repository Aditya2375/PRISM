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
    assert code(w.bob.fetch, "report", False, 1) == "expired"  # past cutoff
    assert w.bob.fetch("report") == b"top secret payroll"      # current version unaffected


def test_revoked_device_gets_no_grace(w):
    w.admin.call("revoke_device", device="bob-laptop")
    w.admin.rotate("report")
    assert code(w.bob.fetch, "report", False, 1) == "revoked"
    assert w.svc.state["files"]["report"]["prev"]["wraps"].keys().isdisjoint({"bob-laptop"})


def test_unknown_epoch_rejected(w):
    assert code(w.bob.fetch, "report", False, 7) == "expired"


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


def test_state_file_rollback_cannot_resurrect_a_revoked_device(w, tmp_path):
    stale_state = (tmp_path / "data" / "state.json").read_text()
    w.admin.call("revoke_device", device="alice-phone")
    (tmp_path / "data" / "state.json").write_text(stale_state)   # attacker or bad restore
    # the audit log is now ahead of state, and revoked.log has the device
    svc2 = restart(w, tmp_path)
    assert svc2.state["devices"]["alice-phone"]["status"] != "active"
    assert "alice-phone" not in svc2.state["files"]["report"]["wraps"]


def test_tampered_state_file_is_refused_not_used(w, tmp_path):
    from kig.service import StateCorrupt
    d = tmp_path / "data"
    st = json.loads((d / "state.json").read_text())
    st["devices"]["alice-phone"]["status"] = "active"
    st["devices"]["alice-phone"]["status"] = "active"
    st["users"]["bob"]["role"] = "admin"                       # privilege edit on disk
    (d / "state.json").write_text(json.dumps(st))
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)
    (d / "state.json").write_text("{not json")
    with pytest.raises(StateCorrupt):
        restart(w, tmp_path)


def test_revoked_set_is_enforced_when_state_is_restored_from_old_signed_copy(w, tmp_path):
    d = tmp_path / "data"
    old = (d / "state.json").read_text()                        # valid, signed, but before the revoke
    w.admin.call("revoke_device", device="alice-phone")
    (d / "state.json").write_text(old)
    lines = (d / "audit.jsonl").read_text().splitlines()
    n = next(i for i, l in enumerate(lines) if json.loads(l)["type"] == "device.revoked")
    (d / "audit.jsonl").write_text("\n".join(lines[:n]) + "\n")   # audit also rolled back
    svc2 = restart(w, tmp_path)
    assert svc2.state["devices"]["alice-phone"]["status"] != "active"


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
