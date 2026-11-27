import json
import shutil
from pathlib import Path

from kig import backup, vault  # noqa: F401
from kig.client import Client, Device
from kig.service import GuardService
from conftest import Clock

ROOT = Path(__file__).resolve().parents[1]

# Fields the PRISM-1 layout had. Removing or renaming one breaks data written by an earlier release; new fields are fine.
STATE_KEYS = ['_sig', '_wal', 'applied', 'audit_head', 'devices', 'files', 'suite', 'users']
DEVICE_KEYS = ['enrolled_at', 'kem_pub', 'sign_pub', 'status', 'user']
AUDIT_KEYS = ['actor', 'data', 'hash', 'prev', 'seq', 'sig', 'ts', 'type']
KEYFILE_KEYS = ['ct', 'hdr', 'nonce']


def _clock():
    c = Clock()
    c.tick(100)   # after everything in the fixture was written
    return c


def test_current_code_opens_data_dir_and_decrypts(tmp_path, v1_data):
    fix, pw = v1_data
    shutil.copytree(fix / "data", tmp_path / "data")
    clock = _clock()
    svc = GuardService(tmp_path / "data", clock=clock)
    assert svc.audit.verify() == (True, "ok")
    dev = Device.load(fix / "alice-laptop.key.json", pw)
    assert Client(dev, svc.handle, clock).fetch("report") == b"frozen fixture plaintext"
    assert svc.state["devices"]["bob-laptop"]["status"] != "active"


def test_current_code_restores_backup(tmp_path, v1_data):
    fix, pw = v1_data
    out = backup.restore(fix / "frozen.bak", tmp_path / "r", (fix / "backup.pub").read_bytes(),
                         (fix / "backup.key").read_bytes(), fix / "data" / "server_sign.pub",
                         fix / "data" / "server_sign.key", min_counter=1, accept_lost_revocations=True)
    assert out["counter"] == 1
    svc = GuardService(tmp_path / "r", clock=_clock())
    assert svc.audit.verify() == (True, "ok")
    assert Client(Device.load(fix / "alice-laptop.key.json", pw), svc.handle, _clock()).fetch("report") \
        == b"frozen fixture plaintext"


def test_on_disk_layout_is_still_prism_1(v1_data):
    fix, _ = v1_data
    s = json.loads((fix / "data" / "state.json").read_text())
    assert set(STATE_KEYS) <= set(s)
    assert set(DEVICE_KEYS) <= set(s["devices"]["alice-laptop"])
    assert set(AUDIT_KEYS) <= set(json.loads((fix / "data" / "audit.jsonl").read_text().splitlines()[0]))
    assert set(KEYFILE_KEYS) <= set(json.loads((fix / "alice-laptop.key.json").read_text()))


def test_no_private_key_material_is_committed():
    """A fresh clone holds no private key or passphrase: only the public NIST vectors under tests/vectors."""
    bad = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or {"node_modules", ".git", "venv", ".venv"} & set(p.parts) or "vectors" in p.parts:
            continue
        if p.name.endswith((".key", ".key.json", ".bak")) or p.name in ("server_sign.key", "revoked.log", "state.wal"):
            bad.append(str(p.relative_to(ROOT)))
        elif p.suffix in (".py", ".md", ".sh", ".json", ".toml", ".yml", ".yaml") and "fixture-passphrase" in p.read_text(errors="ignore") \
                and p.name != "test_frozen_format.py":
            bad.append(str(p.relative_to(ROOT)))
    assert bad == []
