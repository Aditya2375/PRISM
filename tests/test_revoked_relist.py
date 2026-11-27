"""A server that lists a revoked device again (in `eligible`, or by flipping it back to active) is refused by the client."""
import pytest

from kig import crypto as c
from kig.client import Client


def _evil(w, relist):
    """A transport that answers honestly except that `eligible` also offers bob's revoked laptop."""
    def send(env):
        r = w.svc.handle(env)
        if env["cmd"] == "eligible" and relist:
            r = dict(r, devices=dict(r["devices"], **{"bob-laptop": w.svc.state["devices"]["bob-laptop"]["kem_pub"]}))
        return r
    return send


def test_relisted_revoked_device_is_refused(w):
    w.admin.call("revoke_device", device="bob-laptop")
    evil = Client(w.alice_phone, _evil(w, relist=True), w.clock)
    with pytest.raises(c.CryptoError, match="revoked"):
        evil.put_file("new", b"x", acl=["alice", "bob"])


def test_revoked_device_flipped_back_to_active_is_refused_after_restart(w, tmp_path):
    sp = tmp_path / "phone.state"
    phone = Client(w.alice_phone, w.svc.handle, w.clock, state_path=sp)
    phone.put_file("f1", b"x", acl=["alice", "bob"])           # bob-laptop is a recipient and gets cached as trusted
    w.admin.call("revoke_device", device="bob-laptop")
    phone.put_file("f2", b"y", acl=["alice", "bob"])            # the eligible reply tells the phone bob-laptop is revoked
    assert "bob-laptop" in phone.pins["revoked"]
    w.svc.state["devices"]["bob-laptop"]["status"] = "active"   # a tampered or rolled-back server un-revokes it
    again = Client(w.alice_phone, w.svc.handle, w.clock, state_path=sp)   # client restart: memory comes from the pin file
    with pytest.raises(c.CryptoError, match="revoked"):
        again.put_file("f3", b"z", acl=["alice", "bob"])


def test_revoking_client_remembers_without_asking(w):
    w.admin.call("revoke_device", device="bob-laptop")
    assert "bob-laptop" in w.admin.pins["revoked"]
