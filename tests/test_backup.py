import json
import random

import pytest

from kig import backup as b
from kig.client import Client
from kig.service import GuardService

from conftest import code


@pytest.fixture
def bk(w, tmp_path):
    b.keygen(tmp_path / "ops")
    pub, sec = (tmp_path / "ops" / "backup.pub").read_bytes(), (tmp_path / "ops" / "backup.key").read_bytes()
    out = tmp_path / "bk.json"
    b.create(w.svc, pub, out)
    return out, pub, sec


def do_restore(w, tmp_path, bk, dest="restored", **kw):
    out, pub, sec = bk
    d = tmp_path / "data"
    return b.restore(out, tmp_path / dest, pub, sec, d / "server_sign.pub", d / "server_sign.key", **kw)


def test_backup_roundtrip_serves_data(w, tmp_path, bk):
    do_restore(w, tmp_path, bk)
    svc2 = GuardService(tmp_path / "restored", clock=w.clock)
    assert svc2.audit.verify() == (True, "ok")
    w.clock.tick(1)
    assert Client(w.bob_laptop, svc2.handle, w.clock).fetch("report") == b"top secret payroll"


def test_backup_is_encrypted_not_plaintext(w, tmp_path, bk):
    raw = bk[0].read_bytes()
    assert b"alice-phone" not in raw and b"payroll" not in raw and b"kem_pub" not in raw


def test_every_flipped_byte_region_is_detected_and_nothing_is_written(w, tmp_path, bk):
    out, pub, sec = bk
    good = out.read_bytes()
    rnd = random.Random(7)
    positions = sorted({rnd.randrange(len(good)) for _ in range(150)} | {0, 1, len(good) - 1, len(good) // 2})
    for i, pos in enumerate(positions):
        bad = bytearray(good)
        bad[pos] ^= 0x01
        out.write_bytes(bytes(bad))
        with pytest.raises(b.BackupError):
            do_restore(w, tmp_path, (out, pub, sec), dest=f"r{i}")
        assert not (tmp_path / f"r{i}").exists()
    out.write_bytes(good)


def test_truncated_garbage_and_wrong_key(w, tmp_path, bk):
    out, pub, sec = bk
    good = out.read_bytes()
    for bad in (good[: len(good) // 2], b"", b"not json", b"[]", b"{}"):
        out.write_bytes(bad)
        with pytest.raises(b.BackupError):
            do_restore(w, tmp_path, (out, pub, sec), dest=f"t{len(bad)}")
    out.write_bytes(good)
    b.keygen(tmp_path / "other")
    wrong = (tmp_path / "other" / "backup.key").read_bytes()
    with pytest.raises(b.BackupError):
        do_restore(w, tmp_path, (out, pub, wrong), dest="wk")


def test_signed_by_other_service_rejected(w, tmp_path, bk):
    out, pub, sec = bk
    other = GuardService(tmp_path / "other_svc", clock=w.clock)
    with pytest.raises(b.BackupError):
        b.verify_and_open(out, pub, sec, other.pub)


def test_revocation_newer_than_backup_is_not_lost(w, tmp_path, bk):
    w.admin.call("revoke_device", device="alice-phone")        # after the backup was taken
    do_restore(w, tmp_path, bk, live_revoked_log=tmp_path / "data" / "revoked.log")
    svc2 = GuardService(tmp_path / "restored", clock=w.clock)
    assert svc2.state["devices"]["alice-phone"]["status"] != "active"
    assert "alice-phone" not in svc2.state["files"]["report"]["wraps"]


def test_refuses_to_overwrite_existing_data(w, tmp_path, bk):
    with pytest.raises(b.BackupError):
        do_restore(w, tmp_path, bk, dest="data")


def test_fuzz_200_single_byte_flips_all_rejected_with_a_reason(w, tmp_path, bk):
    out, pub, sec = bk
    raw = out.read_bytes()
    spub = (tmp_path / "data" / "server_sign.pub").read_bytes()
    rnd = random.Random(7)
    reasons = set()
    for i in range(200):
        pos = rnd.randrange(len(raw))
        mut = bytearray(raw)
        mut[pos] ^= 1 << rnd.randrange(8)
        f = tmp_path / f"fz{i}.json"
        f.write_bytes(bytes(mut))
        with pytest.raises(b.BackupError) as ei:
            b.verify_and_open(f, pub, sec, spub)
        assert str(ei.value)
        reasons.add(str(ei.value).split(":")[0])
    assert len(reasons) >= 2


def test_older_valid_backup_refused_unless_flagged_and_revocations_unioned(w, tmp_path, bk):
    out, pub, sec = bk
    w.admin.call("revoke_device", device="bob-laptop")
    out2 = tmp_path / "bk2.json"
    b.create(w.svc, pub, out2)
    d = tmp_path / "data"
    with pytest.raises(b.BackupError, match="older backup"):
        b.restore(out, tmp_path / "r1", pub, sec, d / "server_sign.pub", d / "server_sign.key", live_dir=d)
    rep = b.restore(out, tmp_path / "r2", pub, sec, d / "server_sign.pub", d / "server_sign.key",
                    live_revoked_log=d / "revoked.log", live_dir=d, allow_older=True)
    assert "bob-laptop" in rep["revoked"]            # revocations are never lost by restoring older state
    svc2 = GuardService(tmp_path / "r2", clock=w.clock)
    w.clock.tick(1)
    assert code(Client(w.bob_laptop, svc2.handle, w.clock).fetch, "report") == "revoked"


def test_backup_key_can_be_passphrase_protected(tmp_path):
    b.keygen(tmp_path / "ops2", passphrase="pw")
    sec = b.load_secret(tmp_path / "ops2" / "backup.key", "pw")
    from kig import vault
    assert len(sec) > 0 and vault.is_sealed((tmp_path / "ops2" / "backup.key").read_bytes())
    with pytest.raises(vault.VaultError):
        b.load_secret(tmp_path / "ops2" / "backup.key", "bad")
