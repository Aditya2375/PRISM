"""Disaster drill: lose the whole data directory, restore from a backup, check everything that matters."""
import shutil

from kig import backup, crypto as c, doctor
from kig.service import GuardService


def test_total_loss_then_restore(w, tmp_path):
    w.admin.call("revoke_device", device="alice-phone")
    live = w.svc.dir
    head = w.svc.audit.head
    pub, sec = c.kem_keygen()
    bk = tmp_path / "drill.bak"
    backup.create(w.svc, pub, bk)
    keys = (tmp_path / "keys"); keys.mkdir()
    shutil.copy(live / "server_sign.pub", keys / "pub"); shutil.copy(live / "server_sign.key", keys / "key")
    revoked = set(w.svc.revoked)
    shutil.rmtree(live)                                            # the disaster
    out = tmp_path / "recovered"
    backup.restore(bk, out, pub, sec, keys / "pub", keys / "key", accept_rollback=True, min_counter=1)
    assert all(r[0] != "FAIL" for r in doctor.check(out))
    svc2 = GuardService(out, clock=w.clock)
    assert svc2.revoked >= revoked                                 # a revoked device stays revoked
    assert head in {e["hash"] for e in svc2.audit.entries}         # history before the backup is intact
    assert any(e["type"] == "restore.completed" for e in svc2.audit.entries)
    w.clock.tick(1)
    from kig.client import Client
    assert Client(w.admin.dev, svc2.handle, w.clock).fetch("report", auto_rotate=False)
