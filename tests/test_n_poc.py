import json, pytest
from kig import crypto as c
from kig.client import Client, Device, manifest_msg

def test_N1_unpinned_forged_writer_can_rewrite_acl(w):
    w.admin.fetch("report", auto_rotate=False)                 # admin pinned alice-laptop as the writer
    f = w.svc.state["files"]["report"]
    evil = Device.generate("evil-dev", "mallory")              # server invents a device, never enrolled by any admin
    w.svc.state["devices"]["evil-dev"] = dict(w.svc.state["devices"]["alice-laptop"], sign_pub=c.b64e(evil.sign_pub),
                                              kem_pub=c.b64e(evil.kem_pub), user="mallory")
    acl = sorted(set(f["acl"]) | {"mallory"})
    sig = c.sign(evil.sign_sec, "manifest", manifest_msg("report", f["epoch"], acl, f["owner"], f["commit"], "evil-dev"))
    f["acl"] = acl; f["manifest"] = {"writer": "evil-dev", "sig": c.b64e(sig)}
    with pytest.raises(c.CryptoError):
        w.admin.fetch("report", auto_rotate=False)             # safe: client must refuse a writer it never pinned for this file

def test_N2_cli_client_keeps_no_pins_or_epochs():
    import inspect, kig.cli as cli
    src = inspect.getsource(cli)
    assert "state_path" in src, "kig CLI builds Client without state_path: pins and rollback epochs are not persisted between invocations"

def test_N3_member_device_can_sign_acl_change_client_accepts(w):
    # bob is a plain member (not owner, not admin). Colluding/compromised bob device + malicious service.
    w.admin.fetch("report", auto_rotate=False)
    f = w.svc.state["files"]["report"]
    acl = sorted(set(f["acl"]) | {"mallory"})
    sig = c.sign(w.bob_laptop.sign_sec, "manifest",
                 manifest_msg("report", f["epoch"], acl, f["owner"], f["commit"], "bob-laptop", "bob"))
    f["acl"] = acl; f["manifest"] = {"writer": "bob-laptop", "sig": c.b64e(sig), "writer_user": "bob"}
    with pytest.raises(c.CryptoError):
        w.admin.fetch("report", auto_rotate=False)   # client must refuse a writer who is neither owner nor admin
