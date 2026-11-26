import pytest

from kig.keystore import FileKeyStore, MemoryKeyStore
from kig.service import GuardService, StateCorrupt


def test_service_uses_keystore_not_a_key_file(tmp_path):
    ks = MemoryKeyStore()
    a = GuardService(tmp_path, keystore=ks)
    assert not (tmp_path / "server_sign.key").exists()
    assert ks.get("server-sign") == a._sec
    b = GuardService(tmp_path, keystore=ks)
    assert b.pub == a.pub and b._sec == a._sec


def test_keystore_and_pub_disagreement_refused(tmp_path):
    GuardService(tmp_path, keystore=MemoryKeyStore())
    with pytest.raises(StateCorrupt):
        GuardService(tmp_path, keystore=MemoryKeyStore())   # pub exists, store empty: never regenerate


def test_file_keystore_roundtrip_sealed_and_plain(tmp_path):
    for pw in (None, "correct horse"):
        d = tmp_path / str(pw)
        ks = FileKeyStore(d, passphrase=pw) if pw else FileKeyStore(d, passphrase="")
        assert ks.get("k1") is None
        ks.put("k1", b"s" * 40)
        assert FileKeyStore(d, passphrase=pw or "").get("k1") == b"s" * 40
        assert oct((d / "k1.key").stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "correct horse" / "k1.key").read_bytes() != b"s" * 40


def test_bad_names_refused():
    with pytest.raises(ValueError):
        MemoryKeyStore().get("../x")
