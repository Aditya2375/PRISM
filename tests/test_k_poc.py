import json, os, tarfile, io, pytest
from kig.service import GuardService
from kig import backup as B, crypto as c

def _cut(d, k):
    p = d / "state.wal"; L = p.read_bytes().splitlines(keepends=True); p.write_bytes(b"".join(L[:-k]))

def test_K1_losing_last_rotate_with_acl_removal_is_silent(w):
    w.admin.rotate("report", acl=["alice"])               # bob removed; acknowledged
    d = w.svc.dir
    n = len((d/"state.wal").read_bytes().splitlines())
    for k in (2,):
        _cut(d, k)
        try:
            s = GuardService(d, clock=w.clock)
        except Exception:
            return
        assert s.state["files"]["report"]["acl"] == ["alice"], f"cut {k} wal line(s): ACL removal silently rolled back, no error"
        return

def test_K2_losing_last_two_user_creations_is_silent(w):
    w.admin.call("create_user", user="u1"); w.clock.tick(1)
    w.admin.call("create_user", user="u2")
    _cut(w.svc.dir, 2)
    try:
        s = GuardService(w.svc.dir, clock=w.clock)
    except Exception:
        return
    assert "u1" in s.state["users"] and "u2" in s.state["users"], "two acknowledged create_user commands vanished silently"


import tarfile
from test_backup import bk, retar, do_restore  # noqa

def test_K3_blob_swap_between_members_rejected(w, tmp_path, bk):
    out, pub, sec = bk
    w.admin.put_file("f2", b"other", acl=["alice"]); 
    import kig.backup as B2
    with tarfile.open(out) as t: names=[m.name for m in t if m.name.startswith("blobs/")]
    if len(names) < 2: pytest.skip("need 2 blobs")
    with tarfile.open(out) as t: a,b_=[t.extractfile(n).read() for n in names[:2]]
    retar(out, {names[0]: b_, names[1]: a})
    with pytest.raises(B.BackupError): do_restore(w, tmp_path, bk)
    assert not (tmp_path/"restored").exists() and not (tmp_path/"restored.partial").exists()

def test_K4_symlink_dest_partial_does_not_follow(w, tmp_path, bk):
    victim = tmp_path/"victim"; victim.mkdir(); (victim/"keep").write_text("x")
    os.symlink(victim, tmp_path/"restored.partial")
    try: do_restore(w, tmp_path, bk)
    except Exception: pass
    assert (victim/"keep").exists(), "restore deleted files through a symlinked .partial"
