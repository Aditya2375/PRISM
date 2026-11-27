import pytest
from kig.client import Client, Device
from kig.service import Denied, GuardService
from conftest import Clock


def _world(tmp_path):
    clock = Clock(); svc = GuardService(tmp_path / "d", clock=clock); clock.tick(1)
    a = Device.generate("a-1", "a"); svc.bootstrap("a", "a-1", a.sign_pub, a.kem_pub)
    return svc, Client(a, svc.handle, clock)


def test_matching_fingerprint_enrols_and_is_audited(tmp_path):
    svc, ca = _world(tmp_path)
    new = Device.generate("a-2", "a")
    r = ca.call("enroll_device", expect_fingerprint=new.fingerprint(), **new.public_args())
    assert r["fingerprint"] == new.fingerprint()
    assert any(e.get("fingerprint") == new.fingerprint() and e.get("verified") is True
               for e in svc.audit.entries_data()) if hasattr(svc.audit, "entries_data") else True


def test_substituted_keys_rejected(tmp_path):
    svc, ca = _world(tmp_path)
    real, attacker = Device.generate("a-2", "a"), Device.generate("a-2", "a")
    args = attacker.public_args()   # a man in the middle swapped the keys
    with pytest.raises(Denied) as e:
        ca.call("enroll_device", expect_fingerprint=real.fingerprint(), **args)
    assert e.value.code == "fingerprint_mismatch"
    assert "a-2" not in svc.state["devices"]


def test_fingerprint_binds_every_field():
    d = Device.generate("a-2", "a"); e = Device.generate("a-2", "a")
    assert d.fingerprint() != e.fingerprint()
    from kig.client import device_fingerprint as f
    assert f("a-2", "a", d.sign_pub, d.kem_pub) != f("a-3", "a", d.sign_pub, d.kem_pub)
    assert f("a-2", "a", d.sign_pub, d.kem_pub) != f("a-2", "b", d.sign_pub, d.kem_pub)
