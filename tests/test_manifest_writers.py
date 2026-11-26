import json

import pytest

from kig import cli, crypto as c
from kig.client import Client, Device, manifest_msg


def test_legitimately_enrolled_second_writer_is_accepted_and_pinned(w):
    w.admin.fetch("report", auto_rotate=False)                       # pins alice-laptop for this file
    second = Device.generate("alice-tablet", "alice")
    w.admin.call("enroll_device", **second.public_args())
    w.clock.tick(1)
    tab = Client(second, w.svc.handle, w.clock)
    w.admin.rotate("report")                                         # rewrap so the tablet holds a key
    tab.fetch("report", auto_rotate=False)
    tab.rotate("report")                                             # the tablet now writes a version
    assert w.admin.fetch("report", auto_rotate=False)                # original client accepts it via the enrolment proof
    assert "alice-tablet" in w.admin.pins["writers"]["report"]


def test_writer_with_proof_signed_by_unpinned_key_is_refused(w):
    w.admin.fetch("report", auto_rotate=False)
    f = w.svc.state["files"]["report"]
    evil = Device.generate("evil-dev", "alice")
    env = Client(evil, lambda e: e, w.clock).envelope("enroll_device", evil.public_args())   # self-signed "enrolment"
    w.svc.state["devices"]["evil-dev"] = dict(w.svc.state["devices"]["alice-laptop"], sign_pub=c.b64e(evil.sign_pub),
                                              kem_pub=c.b64e(evil.kem_pub), enrolled_proof=env)
    sig = c.sign(evil.sign_sec, "manifest", manifest_msg("report", f["epoch"], f["acl"], f["owner"], f["commit"],
                                                       "evil-dev", "alice"))
    f["manifest"] = {"writer": "evil-dev", "sig": c.b64e(sig)}
    with pytest.raises(c.CryptoError, match="never pinned"):
        w.admin.fetch("report", auto_rotate=False)


def test_cli_runs_share_pins_and_epochs(w, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_post", lambda url: w.svc.handle)
    real = cli.Client
    monkeypatch.setattr(cli, "Client", lambda dev, tr, clock=None, **kw: real(dev, tr, w.clock, **kw))
    key = tmp_path / "admin.json"; w.admin.dev.save(key)
    src = tmp_path / "in.txt"; src.write_text("hello")
    assert cli.main(["put", "--url", "x", "--key", str(key), "--file-id", "cli-doc", "--path", str(src)]) == 0
    out = tmp_path / "out.txt"
    assert cli.main(["get", "--url", "x", "--key", str(key), "--file-id", "cli-doc", "--out", str(out)]) == 0
    assert out.read_text() == "hello"
    pins = json.loads((tmp_path / "admin.json.state.pins").read_text())
    assert "cli-doc" in pins["owners"] and "cli-doc" in pins["writers"]
    # a second run, as a new process would, refuses a changed owner
    w.svc.state["files"]["cli-doc"]["owner"] = "mallory"
    assert cli.main(["get", "--url", "x", "--key", str(key), "--file-id", "cli-doc", "--out", str(out)]) == 3


def test_admin_proven_by_the_owner_may_write_but_a_member_may_not(w):
    w.admin.fetch("report", auto_rotate=False)                       # pins alice-laptop (the owner's device)
    w.admin.call("create_user", user="carol", role="admin")
    carol = Device.generate("carol-laptop", "carol")
    w.admin.call("enroll_device", **carol.public_args())
    w.clock.tick(1)
    w.admin.call("report_lost", device="alice-phone", reason="x")    # something that needs a rotation by carol
    w.admin.rotate("report", acl=["alice", "bob", "carol"])
    cc = Client(carol, w.svc.handle, w.clock)
    cc.fetch("report", auto_rotate=False)
    cc.rotate("report")                                              # carol writes a version
    assert w.admin.fetch("report", auto_rotate=False)                # alice's client accepts: owner created carol admin
    assert "carol" in w.admin.pins["admins"]["report"]


def test_member_writer_without_admin_proof_is_refused(w):
    w.admin.fetch("report", auto_rotate=False)
    f = w.svc.state["files"]["report"]
    acl = sorted(set(f["acl"]) | {"mallory"})
    sig = c.sign(w.bob_laptop.sign_sec, "manifest",
                 manifest_msg("report", f["epoch"], acl, f["owner"], f["commit"], "bob-laptop", "bob"))
    f["acl"] = acl; f["manifest"] = {"writer": "bob-laptop", "sig": c.b64e(sig)}
    # bob's device was enrolled by alice's device, so the enrolment proof is valid; his authority is what is missing
    with pytest.raises(c.CryptoError, match="neither the file's owner nor an admin"):
        w.admin.fetch("report", auto_rotate=False)
