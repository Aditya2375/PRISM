import json
import os
import random

import pytest

from kig import vault
from kig.client import Device
from kig.service import GuardService


def test_seal_open_roundtrip_and_label_binding():
    blob = vault.seal(b"secret-bytes", "correct horse", "prism/device-key")
    assert b"secret-bytes" not in blob
    assert vault.open_(blob, "correct horse", "prism/device-key") == b"secret-bytes"
    with pytest.raises(vault.VaultError):
        vault.open_(blob, "wrong", "prism/device-key")
    with pytest.raises(vault.VaultError):
        vault.open_(blob, "correct horse", "prism/server-key")
    with pytest.raises(vault.VaultError):
        vault.open_(blob, None, "prism/device-key")


def test_every_single_byte_flip_is_rejected():
    blob = vault.seal(b"x" * 64, "pw", "l")
    rnd = random.Random(3)
    for _ in range(120):
        m = bytearray(blob)
        m[rnd.randrange(len(m))] ^= 1 << rnd.randrange(8)
        with pytest.raises(vault.VaultError):
            vault.open_(bytes(m), "pw", "l")


def test_hostile_kdf_parameters_refused_before_deriving():
    d = json.loads(vault.seal(b"x", "pw", "l"))
    d["hdr"]["n"] = 2**30
    with pytest.raises(vault.VaultError, match="unacceptable"):
        vault.open_(json.dumps(d).encode(), "pw", "l")


def test_device_key_file_encrypted_at_rest(tmp_path, monkeypatch):
    dev = Device.generate("d1", "u")
    p = tmp_path / "d1.key"
    dev.save(p, passphrase="pw")
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    raw = p.read_bytes()
    from kig import crypto as c
    assert c.b64e(dev.sign_sec).encode() not in raw
    assert Device.load(p, passphrase="pw").sign_sec == dev.sign_sec
    with pytest.raises(vault.VaultError):
        Device.load(p)
    monkeypatch.setenv(vault.ENV_PASSPHRASE, "pw")
    assert Device.load(p).kem_sec == dev.kem_sec


def test_server_key_encrypted_when_passphrase_set(tmp_path, monkeypatch):
    monkeypatch.setenv(vault.ENV_PASSPHRASE, "pw")
    s = GuardService(tmp_path / "d")
    raw = (tmp_path / "d" / "server_sign.key").read_bytes()
    assert vault.is_sealed(raw) and s._sec not in raw
    assert GuardService(tmp_path / "d").pub == s.pub
    monkeypatch.setenv(vault.ENV_PASSPHRASE, "nope")
    with pytest.raises(vault.VaultError):
        GuardService(tmp_path / "d")
