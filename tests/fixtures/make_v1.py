"""Regenerate tests/fixtures/v1 (only when the on-disk format changes on purpose).

Everything here is a throwaway test key. The point of the fixture is that a release can still open
data written by an earlier release, so it is committed and never regenerated casually.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conftest import Clock  # noqa: E402
from kig import backup, crypto as c  # noqa: E402
from kig.client import Client, Device  # noqa: E402
from kig.service import GuardService  # noqa: E402

PASS = "fixture-passphrase-not-secret"
out = Path(__file__).parent / "v1"
shutil.rmtree(out, ignore_errors=True)
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
a.save(out / "alice-laptop.key.json", PASS)
pub, sec = c.kem_keygen()
(out / "backup.pub").write_bytes(pub)
(out / "backup.key").write_bytes(sec)
backup.create(svc, pub, out / "frozen.bak")
print("written", out)
