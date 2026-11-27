import shutil
from pathlib import Path

from kig import backup, vault  # noqa: F401
from kig.client import Client, Device
from kig.service import GuardService
from conftest import Clock

FIX = Path(__file__).parent / "fixtures" / "v1"
PASS = "fixture-passphrase-not-secret"


def _clock():
    c = Clock()
    c.tick(100)   # after everything in the fixture was written
    return c


def test_current_code_opens_frozen_data_dir_and_decrypts(tmp_path):
    shutil.copytree(FIX / "data", tmp_path / "data")
    clock = _clock()
    svc = GuardService(tmp_path / "data", clock=clock)
    assert svc.audit.verify() == (True, "ok")
    dev = Device.load(FIX / "alice-laptop.key.json", PASS)
    assert Client(dev, svc.handle, clock).fetch("report") == b"frozen fixture plaintext"
    assert svc.state["devices"]["bob-laptop"]["status"] != "active"


def test_current_code_restores_frozen_backup(tmp_path):
    out = backup.restore(FIX / "frozen.bak", tmp_path / "r", (FIX / "backup.pub").read_bytes(),
                         (FIX / "backup.key").read_bytes(), FIX / "data" / "server_sign.pub",
                         FIX / "data" / "server_sign.key", min_counter=1, accept_lost_revocations=True)
    assert out["counter"] == 1
    svc = GuardService(tmp_path / "r", clock=_clock())
    assert svc.audit.verify() == (True, "ok")
    assert Client(Device.load(FIX / "alice-laptop.key.json", PASS), svc.handle, _clock()).fetch("report") \
        == b"frozen fixture plaintext"
