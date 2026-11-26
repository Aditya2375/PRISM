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
