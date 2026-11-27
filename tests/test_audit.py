import json

import pytest

from kig import audit, crypto as c


def make(tmp_path):
    pub, sec = c.sig_keygen()
    return audit.AuditLog(tmp_path / "a.jsonl", sec, pub), pub, sec


def test_chain_verifies_and_survives_restart(tmp_path):
    log, pub, sec = make(tmp_path)
    for i in range(5):
        log.append(1000 + i, "t", "a", {"i": i})
    assert log.verify() == (True, "ok")
    again = audit.AuditLog(tmp_path / "a.jsonl", sec, pub)
    assert len(again.entries) == 5 and again.head == log.head


def test_edit_delete_reorder_detected(tmp_path):
    log, pub, sec = make(tmp_path)
    for i in range(4):
        log.append(1000 + i, "t", "a", {"i": i})
    e = json.loads(json.dumps(log.entries))
    e[1]["data"]["i"] = 99
    assert not audit.verify_chain(e, pub)[0]
    e = json.loads(json.dumps(log.entries))
    del e[1]
    assert not audit.verify_chain(e, pub)[0]
    e = json.loads(json.dumps(log.entries))
    e[1], e[2] = e[2], e[1]
    assert not audit.verify_chain(e, pub)[0]
    other_pub, _ = c.sig_keygen()
    assert not audit.verify_chain(log.entries, other_pub)[0]


def test_tampered_file_refuses_to_load(tmp_path):
    log, pub, sec = make(tmp_path)
    log.append(1, "t", "a", {"x": 1})
    log.append(2, "t", "a", {"x": 2})
    p = tmp_path / "a.jsonl"
    lines = p.read_text().splitlines()
    p.write_text(lines[1] + "\n")
    with pytest.raises(audit.AuditError):
        audit.AuditLog(p, sec, pub)


# ---- hostile log content and tampering (cut-list from the threat model)
import json as _json
from kig.audit import AuditLog, AuditError, verify_chain
CHECKPOINT_EVERY = 8
from kig import crypto as _c


def _log(tmp_path, n=20, details=None):
    pub, sec = _c.sig_keygen()
    lg = AuditLog(tmp_path / "audit.jsonl", sec, pub)
    for i in range(n):
        lg.append(float(i), "t", "actor-real", details or {"i": i})
    return lg, pub, sec


@pytest.mark.parametrize("evil", [
    "line\r\nseq=999 actor=admin", "a\u2028b\u2029c\x85d", 'x","actor":"admin','{"actor":"admin","type":"user.disabled"}',
    "A" * 200000, "\x00\x1b[2J", "\ud83d\ude00 \u202e",
])
def test_hostile_details_stay_one_record(tmp_path, evil):
    lg, pub, sec = _log(tmp_path, 3, {"note": evil})
    lines = (tmp_path / "audit.jsonl").read_bytes().split(b"\n")
    assert len([l for l in lines if l]) == 3
    assert all(e["actor"] == "actor-real" for e in lg.entries)
    assert AuditLog(tmp_path / "audit.jsonl", sec, pub).verify()[0]


def test_tail_truncation_detected_by_checkpoint(tmp_path):
    lg, pub, sec = _log(tmp_path, CHECKPOINT_EVERY * 2 + 3)
    p = tmp_path / "audit.jsonl"
    lines = p.read_bytes().split(b"\n")
    p.write_bytes(b"\n".join(lines[: CHECKPOINT_EVERY + 2]) + b"\n")   # cut below the checkpoint
    with pytest.raises(AuditError):
        AuditLog(p, sec, pub)


def test_middle_deletion_and_reorder_detected(tmp_path):
    lg, pub, sec = _log(tmp_path, 12)
    e = [dict(x) for x in lg.entries]
    assert verify_chain(e[:5] + e[6:], pub)[0] is False
    assert verify_chain(e[:3] + [e[4], e[3]] + e[5:], pub)[0] is False
    forged = dict(e[4]); forged["actor"] = "admin"
    assert verify_chain(e[:4] + [forged] + e[5:], pub)[0] is False


def test_verify_log_cli_reports_first_bad_seq(tmp_path, capsys):
    from kig import cli
    lg, pub, sec = _log(tmp_path, 12)
    (tmp_path / "server_sign.pub").write_bytes(pub)
    p = tmp_path / "audit.jsonl"
    lines = p.read_bytes().split(b"\n")
    d = _json.loads(lines[6]); d["actor"] = "admin"; lines[6] = _json.dumps(d).encode()
    p.write_bytes(b"\n".join(lines))
    assert cli.main(["verify-log", "--data", str(tmp_path)]) == 1
    assert "first_bad_seq=6" in capsys.readouterr().out


def test_deleted_anchor_and_external_head(tmp_path):
    lg, pub, sec = _log(tmp_path, 5)
    head = lg.head
    assert lg.verify(expect_head=head) == (True, "ok")
    assert lg.verify(expect_head="0" * 64)[0] is False
    (tmp_path / "audit.head").unlink()
    with pytest.raises(AuditError):
        AuditLog(tmp_path / "audit.jsonl", sec, pub)


def test_failed_append_leaves_no_torn_line(tmp_path, monkeypatch):
    lg, pub, sec = _log(tmp_path, 3)
    size = (tmp_path / "audit.jsonl").stat().st_size
    import os as _os
    real = _os.fsync
    monkeypatch.setattr("kig.audit.os.fsync", lambda fd: (_ for _ in ()).throw(OSError(28, "No space left")))
    with pytest.raises(OSError):
        lg.append(9.0, "t", "a", {})
    monkeypatch.setattr("kig.audit.os.fsync", real)
    assert (tmp_path / "audit.jsonl").stat().st_size == size
    assert AuditLog(tmp_path / "audit.jsonl", sec, pub).verify()[0]
