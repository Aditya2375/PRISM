import os
from kig import doctor
from kig.service import GuardService


def test_healthy_directory_passes(w, capsys):
    d = w.svc.dir
    assert doctor.run(d) == 0
    assert "FAIL" not in capsys.readouterr().out


def test_corrupt_blob_reported(w):
    h = next(iter(w.svc.blob_hashes()))
    p = w.svc._blob_path(h); raw = bytearray(p.read_bytes()); raw[-1] ^= 1; p.write_bytes(bytes(raw))
    rows = doctor.check(w.svc.dir)
    assert ("FAIL", "blobs") in [(r[0], r[1]) for r in rows]


def test_wal_loss_reported(w):
    w.admin.call("create_user", user="u1"); w.clock.tick(1)
    w.admin.call("create_user", user="u2")
    p = w.svc.dir / "state.wal"; L = p.read_bytes().splitlines(keepends=True); p.write_bytes(b"".join(L[:-2]))
    rows = doctor.check(w.svc.dir)
    assert rows[0][:2] == ("FAIL", "open")


def test_audit_check_present(w):
    rows = doctor.check(w.svc.dir)
    assert ("OK", "audit") in [(r[0], r[1]) for r in rows]
