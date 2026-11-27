import json, os, shutil
from kig import cli, doctor
from kig.client import Device, Client
from test_cli_enroll import _setup

def test_M1_unverified_enrol_cannot_be_recorded_as_verified_via_pub_file(w, tmp_path, monkeypatch, capsys):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    a = new.public_args(); a["expect_fingerprint"] = new.fingerprint()     # attacker-supplied file content
    pub.write_text(json.dumps(a))
    # adapted: a pub file carrying its own expect_fingerprint is refused outright (extra key), so nothing is enrolled
    assert cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub), "--unverified"]) == 2
    assert not [e for e in w.svc.audit.entries if e["type"] == "device.enrolled" and e["data"].get("device") == "a-77"]

def test_M2_pub_file_may_not_carry_extra_fields(w, tmp_path, monkeypatch):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    a = new.public_args(); a["by"] = "x"; a["role"] = "admin"
    pub.write_text(json.dumps(a))
    r = cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub), "--unverified"])
    assert r != 0, "unknown fields in the public-key file are forwarded to enroll_device"

def test_M3_doctor_leaves_no_copy_of_server_key_in_tmp(w, tmp_path, monkeypatch):
    t = tmp_path / "tmpdir"; t.mkdir(); monkeypatch.setenv("TMPDIR", str(t)); import tempfile; tempfile.tempdir = None
    seen = []
    orig = shutil.copy2
    doctor.check(w.svc.dir)
    assert not any(t.iterdir()), "temp copy left behind"
