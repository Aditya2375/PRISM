"""A hostile server cannot add a reader: the client wraps keys only for devices of users on the file's ACL."""
import pytest

from kig import crypto as c
from kig.client import Client, Device


def _with_extra_eligible(w, extra: Device):
    """Wrap the admin's transport so the 'eligible' reply also lists one more real, enrolled device."""
    real = w.admin.send

    def hostile(env):
        r = real(env)
        if isinstance(r, dict) and "devices" in r and isinstance(r["devices"], dict) and isinstance(r["devices"].get("alice-laptop"), str):
            r = dict(r, devices=dict(r["devices"], **{extra.device_id: c.b64e(extra.kem_pub)}))
        return r

    w.admin.send = hostile


def test_server_cannot_add_an_enrolled_device_of_a_user_not_on_the_acl(w):
    w.admin.call("create_user", user="carol", role="member")
    carol = Device.generate("carol-laptop", "carol")
    w.admin.call("enroll_device", **carol.public_args())           # a real, properly enrolled device
    _with_extra_eligible(w, carol)
    with pytest.raises(c.CryptoError, match="not on the file's access list"):
        w.admin.put_file("memo", b"for alice and bob", acl=["alice", "bob"])
    assert "memo" not in w.svc.state["files"]


def test_normal_acl_users_still_work(w):
    w.admin.put_file("memo", b"for alice and bob", acl=["alice", "bob"])
    assert w.bob.fetch("memo", auto_rotate=False) == b"for alice and bob"
