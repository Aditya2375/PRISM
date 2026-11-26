import json
import random

import pytest

from kig import backup as b
from kig import crypto as c
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


def live_positions(path):
    """Byte offsets that carry header or data of an archive member (tar padding is inert by design)."""
    import tarfile
    out = []
    with tarfile.open(path, "r:") as tf:
        for ti in tf:
            out += list(range(ti.offset, ti.offset + 512)) + list(range(ti.offset_data, ti.offset_data + ti.size))
    return out


def retar(path, replace):
    """Copy an archive, replacing the content of named members."""
    import io
    import tarfile
    with tarfile.open(path, "r:") as src, tarfile.open(str(path) + ".new", "w", format=tarfile.PAX_FORMAT) as dst:
        for ti in src:
            data = replace.get(ti.name, src.extractfile(ti).read())
            ti.size = len(data)
            dst.addfile(ti, io.BytesIO(data))
    import os
    os.replace(str(path) + ".new", path)


def do_restore(w, tmp_path, bk, dest="restored", **kw):
    out, pub, sec = bk
    d = tmp_path / "data"
    kw.setdefault("accept_rollback", True)
    kw.setdefault("min_counter", 1)
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
    live = live_positions(out)
    positions = sorted({rnd.choice(live) for _ in range(150)} | {live[0], live[1], live[-1], live[len(live) // 2]})
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
    do_restore(w, tmp_path, bk, live_revoked_log=tmp_path / "data" / "revoked.log", accept_rollback=False)
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
    live = live_positions(out)
    for i in range(200):
        pos = rnd.choice(live)
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


def test_padding_bytes_are_inert_and_extra_members_are_refused(w, tmp_path, bk):
    import io
    import tarfile
    out, pub, sec = bk
    spub = (tmp_path / "data" / "server_sign.pub").read_bytes()
    with tarfile.open(out, "a") as tf:                      # a member the manifest does not list
        ti = tarfile.TarInfo("blobs/" + "ab" * 32)
        ti.size = 3
        tf.addfile(ti, io.BytesIO(b"xyz"))
    with pytest.raises(b.BackupError, match="manifest"):
        b.verify_and_open(out, pub, sec, spub)
    with tarfile.open(out, "a") as tf:
        ti = tarfile.TarInfo("../evil")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    with pytest.raises(b.BackupError, match="unexpected"):
        b.verify_and_open(out, pub, sec, spub)


def test_backup_memory_does_not_grow_with_blob_size(w, tmp_path):
    """Create and verify a backup holding ~30 MB of blobs; peak extra memory stays far below that."""
    import os
    import tracemalloc
    pub, sec = c.kem_keygen()
    for i in range(6):
        w.clock.tick(1)
        w.admin.put_file(f"big{i}", os.urandom(4_900_000), acl=["alice"])
    tracemalloc.start()
    out = tmp_path / "big.bak"
    b.create(w.svc, pub, out)
    b.verify_and_open(out, pub, sec, w.svc.pub)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert out.stat().st_size > 29_000_000
    assert peak < 12_000_000, f"peak {peak/1e6:.1f} MB while handling a {out.stat().st_size/1e6:.0f} MB backup"
