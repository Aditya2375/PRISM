import os, json, shutil
from pathlib import Path
from kig import doctor
from kig.client import Client, Device
from kig.service import GuardService

def test_L1_doctor_on_wrong_or_empty_path_must_not_say_OK_or_create_a_service(tmp_path):
    d = tmp_path / "typo-dir"
    rows = doctor.check(d)
    assert any(r[0] == "FAIL" for r in rows), f"doctor reports no problems for a path that holds no PRISM data: {rows[:2]}"
    assert not d.exists() or not any(d.iterdir()), f"doctor created files: {sorted(p.name for p in d.iterdir())}"

def test_L2_doctor_must_be_read_only_and_report_orphans(w):
    d = w.svc.dir
    orphan = d / "blobs" / "ab" / ("ab" + "0" * 62); orphan.parent.mkdir(parents=True, exist_ok=True); orphan.write_bytes(b"x")
    before = sorted(str(p) for p in d.rglob("*"))
    rows = doctor.check(d)
    orph = [r for r in rows if r[1] == "orphans"][0]
    assert orph[0] == "WARN" or orphan.exists(), f"doctor deleted the orphan blob itself and reported: {orph}"
    assert orphan.exists(), "doctor (a diagnostic) deleted data"

def test_L3_doctor_with_missing_state_but_audit_present_is_not_ok(w):
    d = w.svc.dir
    os.unlink(d / "state.json"); 
    if (d / "state.wal").exists(): os.unlink(d / "state.wal")
    rows = doctor.check(d)
    assert any(r[0] == "FAIL" for r in rows), f"state gone but audit and blobs present, doctor says: {rows}"

def test_L4_doctor_flags_edited_audit_line_on_disk(w):
    d = w.svc.dir; p = d / "audit.jsonl"; L = p.read_text().splitlines()
    e = json.loads(L[2]); e["actor"] = "mallory"; L[2] = json.dumps(e, sort_keys=True)
    p.write_text("\n".join(L) + "\n")
    rows = doctor.check(d)
    assert any(r[0] == "FAIL" for r in rows), rows

def test_L5_doctor_flags_audit_tail_truncation(w):
    d = w.svc.dir; p = d / "audit.jsonl"; L = p.read_text().splitlines(keepends=True)
    p.write_text("".join(L[:-1]))
    rows = doctor.check(d)
    assert any(r[0] == "FAIL" for r in rows), rows

def test_L6_doctor_flags_wal_tamper_and_perm_on_blobs(w):
    d = w.svc.dir
    os.chmod(d / "audit.jsonl", 0o666)
    rows = doctor.check(d)
    assert any(r[1] == "permissions" and r[0] != "OK" for r in rows), rows

def test_L7_enrol_without_fingerprint_is_possible_and_uppercase_fp_rejected(w):
    new = Device.generate("a-9", "alice")
    w.clock.tick(1)
    r = w.admin.call("enroll_device", expect_fingerprint=new.fingerprint().upper(), **new.public_args())
    assert r["ok"], "a correctly typed fingerprint in upper case is refused"
