import pytest

from kig.client import Client, Device
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
