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


def test_file_mode_pub_swap_is_refused_and_missing_pub_is_rederived(tmp_path):
    from kig import crypto as c
    a = GuardService(tmp_path)
    (tmp_path / "server_sign.pub").unlink()
    with pytest.raises(StateCorrupt):
        GuardService(tmp_path)                      # one file missing in file mode: still refuse
    (tmp_path / "server_sign.pub").write_bytes(c.sig_keygen()[0])
    with pytest.raises(StateCorrupt, match="does not belong"):
        GuardService(tmp_path)
    assert a.pub != (tmp_path / "server_sign.pub").read_bytes()


def test_write_atomic_exclusive_and_symlink(tmp_path):
    from kig import vault
    p = tmp_path / "f"
    vault.write_atomic(p, b"1", exclusive=True)
    with pytest.raises(FileExistsError):
        vault.write_atomic(p, b"2", exclusive=True)
    assert p.read_bytes() == b"1"
    (tmp_path / "victim").write_bytes(b"keep")
    (tmp_path / "f.tmp").symlink_to(tmp_path / "victim")
    vault.write_atomic(p, b"3")
    assert (tmp_path / "victim").read_bytes() == b"keep" and p.read_bytes() == b"3"


def test_exclusive_write_without_hardlinks_refuses_existing_and_leaves_no_partial(tmp_path, monkeypatch):
    import os
    from kig import vault

    def nolink(*a, **k):
        raise OSError(1, "no hard links")
    monkeypatch.setattr(os, "link", nolink)
    p = tmp_path / "s.json"
    vault.write_atomic(p, b"first", exclusive=True)
    with pytest.raises(FileExistsError):
        vault.write_atomic(p, b"second", exclusive=True)
    assert p.read_bytes() == b"first"
    assert [x.name for x in tmp_path.iterdir()] == ["s.json"]       # no temp files left behind


def test_metrics_recount_when_the_audit_log_is_replaced(w):
    a = w.svc.metrics()
    assert sum(a["audit_events"].values()) == a["audit_entries"]
    ents = w.svc.audit.entries
    forged = [dict(e, type="x.forged", hash=f"{i:064d}") for i, e in enumerate(ents)]   # same length, different log
    w.svc.audit.entries = forged
    b = w.svc.metrics()
    assert b["audit_events"] == {"x.forged": len(forged)}
