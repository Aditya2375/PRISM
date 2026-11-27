import pytest

from kig.client import Client, Device
import kig.service as S
from kig.service import Denied, GuardService


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, s):
        self.t += s


class World:
    """alice (admin) with laptop+phone, bob (member) with one laptop, shared file."""

    def __init__(self, tmp_path):
        self.clock = Clock()
        self.svc = GuardService(tmp_path / "data", clock=self.clock)
        self.clock.tick(1)
        self.alice_laptop = Device.generate("alice-laptop", "alice")
        self.svc.bootstrap("alice", "alice-laptop", self.alice_laptop.sign_pub, self.alice_laptop.kem_pub)
        self.admin = Client(self.alice_laptop, self.svc.handle, self.clock)
        self.admin.call("create_user", user="bob", role="member")
        self.alice_phone = Device.generate("alice-phone", "alice")
        self.bob_laptop = Device.generate("bob-laptop", "bob")
        for d in (self.alice_phone, self.bob_laptop):
            self.admin.call("enroll_device", **d.public_args())
        self.phone = Client(self.alice_phone, self.svc.handle, self.clock)
        self.bob = Client(self.bob_laptop, self.svc.handle, self.clock)
        self.admin.put_file("report", b"top secret payroll", acl=["alice", "bob"])


    @property
    def ops(self):
        """A second admin, made when a test needs it: an admin's device is removed by another admin (or offline by the
        operator), never by a sibling device of the same admin."""
        if not hasattr(self, "_ops"):
            self.admin.call("create_user", user="ops", role="admin")
            d = Device.generate("ops-laptop", "ops")
            self.admin.call("enroll_device", **d.public_args())
            self.clock.tick(S.COOLING_OFF_S + 1)         # a freshly enrolled device cannot remove admins yet
            self._ops = Client(d, self.svc.handle, self.clock)
        return self._ops


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except Denied as e:
        return e.code
    return None


@pytest.fixture(autouse=True)
def _no_ambient_passphrase(monkeypatch):
    """A passphrase left in the developer's environment must not change what the tests do."""
    for name in ("PRISM_PASSPHRASE", "KIG_DATA", "KIG_TRUSTED_PROXY", "KIG_PROXY_HOPS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="session")
def v1_data(tmp_path_factory):
    """PRISM-1 on-disk data written at test time: every key and the passphrase are generated fresh per run.

    Nothing secret is committed. The price: this proves restart and restore round-trip with the current code, and the
    format snapshot in test_frozen_format.py catches a silent layout change, but it no longer opens bytes written by
    an older build."""
    import secrets
    from kig import backup, crypto as c
    out = tmp_path_factory.mktemp("v1")
    passphrase = secrets.token_urlsafe(24)
    clock = Clock()
    svc = GuardService(out / "data", clock=clock)
    clock.tick(1)
    a, bob = Device.generate("alice-laptop", "alice"), Device.generate("bob-laptop", "bob")
    svc.bootstrap("alice", "alice-laptop", a.sign_pub, a.kem_pub)
    ca = Client(a, svc.handle, clock)
    ca.call("create_user", user="bob", role="member")
    ca.call("enroll_device", **bob.public_args())
    ca.put_file("report", b"frozen fixture plaintext", acl=["alice", "bob"])
    clock.tick(40)
    ca.call("revoke_device", device="bob-laptop")
    a.save(out / "alice-laptop.key.json", passphrase)
    pub, sec = c.kem_keygen()
    (out / "backup.pub").write_bytes(pub)
    (out / "backup.key").write_bytes(sec)
    backup.create(svc, pub, out / "frozen.bak")
    return out, passphrase
