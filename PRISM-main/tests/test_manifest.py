"""Signed manifest: the ACL, owner, version and key commitment of every file version carry a device signature."""
import pytest
from kig import crypto as c
from kig.client import Client, Device
from kig.service import Denied


def _forge(w, fn):
    f = w.svc.state["files"]["report"]
    fn(f)


def test_normal_flow_still_works(w):
    assert w.admin.fetch("report", auto_rotate=False)


def test_service_side_acl_edit_is_caught_by_client(w):
    _forge(w, lambda f: f["acl"].append("mallory"))
    with pytest.raises(c.CryptoError, match="manifest signature invalid"):
        w.admin.fetch("report", auto_rotate=False)


def test_owner_swap_is_caught(w):
    _forge(w, lambda f: f.update(owner="mallory"))
    with pytest.raises(c.CryptoError):
        w.admin.fetch("report", auto_rotate=False)


def test_commit_swap_is_caught(w):
    _forge(w, lambda f: f.update(commit="0" * 64))
    with pytest.raises(c.CryptoError):
        w.admin.fetch("report", auto_rotate=False)


def test_missing_manifest_is_refused(w):
    _forge(w, lambda f: f.pop("manifest"))
    with pytest.raises(c.CryptoError, match="no signed manifest"):
        w.admin.fetch("report", auto_rotate=False)


def test_unsigned_write_is_rejected_by_service(w):
    with pytest.raises(Denied):
        w.admin.call("put_file", file_id="x", acl=["alice"], ciphertext=c.b64e(b"z" * 40), wraps={},
                     commit="0" * 64)


def test_signature_from_another_version_cannot_be_replayed(w):
    w.admin.rotate("report")
    f = w.svc.state["files"]["report"]
    f["manifest"] = dict(f["prev"]["manifest"])          # old version's signature on the new version
    with pytest.raises(c.CryptoError):
        w.admin.fetch("report", auto_rotate=False)


def test_acl_removal_is_signed_and_visible_after_rotation(w):
    w.admin.rotate("report", acl=["alice"])
    assert w.admin.fetch("report", auto_rotate=False)
    assert w.svc.state["files"]["report"]["acl"] == ["alice"]


def test_signer_key_swap_is_caught_after_pinning(w):
    w.admin.fetch("report", auto_rotate=False)           # pins the writer's key
    writer = w.svc.state["files"]["report"]["manifest"]["writer"]
    assert w.admin.pins["signers"][writer]
    w.admin.pins["signers"][writer] = c.b64e(Device.generate("x", "alice").sign_pub)   # as if pinned earlier
    with pytest.raises(c.CryptoError, match="pinned"):
        w.admin.fetch("report", auto_rotate=False)
