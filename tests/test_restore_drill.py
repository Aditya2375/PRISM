"""Disaster drill: lose the whole data directory, restore from a backup, check everything that matters."""
import shutil

import pytest

from kig import backup, crypto as c, doctor
from kig.client import Client
from kig.service import GuardService


def _plain(x):
    if isinstance(x, dict):
        return {k: _plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_plain(v) for v in x]
    return x


@pytest.mark.parametrize("mode", ["accept_rollback", "live_revoked_log"])
def test_total_loss_then_restore_then_keep_working(w, tmp_path, mode):
    w.ops.call("revoke_device", device="alice-phone")
    live = w.svc.dir
    pub, sec = c.kem_keygen()
    bk = tmp_path / "drill.bak"
    backup.create(w.svc, pub, bk)
    head = w.svc.audit.head
    keys = tmp_path / "keys"; keys.mkdir()
    shutil.copy(live / "server_sign.pub", keys / "pub"); shutil.copy(live / "server_sign.key", keys / "key")
    survivor = tmp_path / "revoked.log"
    shutil.copy(live / "revoked.log", survivor)                    # the one file that survived on another disk
    before = {k: _plain(w.svc.state[k]) for k in ("users", "devices", "files")}
    revoked = set(w.svc.revoked)
    shutil.rmtree(live)                                            # the disaster
    out = tmp_path / "recovered"
    kw = dict(accept_rollback=True) if mode == "accept_rollback" else dict(live_revoked_log=survivor,
                                                                          accept_counter_rollback=True)
    backup.restore(bk, out, pub, sec, keys / "pub", keys / "key", min_counter=1, **kw)
    assert all(r[0] != "FAIL" for r in doctor.check(out))
    svc2 = GuardService(out, clock=w.clock)
    assert {k: _plain(svc2.state[k]) for k in before} == before     # users, devices, files all back
    assert svc2.revoked >= revoked                                 # a revoked device stays revoked
    assert head in {e["hash"] for e in svc2.audit.entries}         # history before the backup is intact
    assert any(e["type"] == "restore.completed" for e in svc2.audit.entries)
    w.clock.tick(1)
    ad = Client(w.admin.dev, svc2.handle, w.clock)
    assert ad.fetch("report", auto_rotate=False)
    ad.put_file("after-restore", b"new data", acl=["alice"])       # the restored service takes writes
    bk2 = tmp_path / "second.bak"
    backup.create(svc2, pub, bk2)                                  # and can be backed up again
    out2 = tmp_path / "recovered2"
    backup.restore(bk2, out2, pub, sec, out / "server_sign.pub", out / "server_sign.key", live_dir=out,
                   accept_lost_revocations=True)
    svc3 = GuardService(out2, clock=w.clock)
    w.clock.tick(1)
    assert Client(w.admin.dev, svc3.handle, w.clock).fetch("after-restore", auto_rotate=False) == b"new data"
