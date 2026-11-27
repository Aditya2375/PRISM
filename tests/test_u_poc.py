import json, os, threading, pytest
from kig import threshold as T, crypto as c
from kig.client import Device

def _forge(share):
    d = json.loads(share); raw = os.urandom(32); d["share"] = c.b64e(raw); d["fp"] = T._fp(d["i"], raw)
    return json.dumps(d).encode()

@pytest.mark.parametrize("n,k,nbad", [(12, 6, 4), (15, 7, 5), (20, 10, 6)])
def test_U1_colluding_minority_with_valid_fingerprints_cannot_block_recovery(n, k, nbad):
    S = os.urandom(96); sh = T.split(S, k, n)
    for i in range(nbad): sh[i] = _forge(sh[i])          # n-nbad >= k honest shares remain
    assert T.combine(sh) == S, f"{n-nbad} honest shares of {n} (k={k}) offered, {nbad} bad ones first: recovery fails after MAX_TRIES"

def test_U2_metrics_while_state_changes_never_raises(w):
    errs, stop = [], threading.Event()
    def scrape():
        while not stop.is_set():
            try: w.svc.metrics()
            except Exception as e: errs.append(repr(e)); return
    t = threading.Thread(target=scrape); t.start()
    try:
        for i in range(150):
            w.clock.tick(1)
            d = Device.generate(f"x{i}", "bob"); w.admin.call("enroll_device", **d.public_args())
    finally:
        stop.set(); t.join()
    assert not errs, f"metrics() read live state without the lock: {errs[0]}"

def test_U3_exclusive_write_works_without_hardlinks(tmp_path, monkeypatch):
    from kig import vault
    def nolink(*a, **k): raise OSError(1, "Operation not permitted")
    monkeypatch.setattr(os, "link", nolink)
    try:
        vault.write_atomic(tmp_path / "x", b"1", 0o600, exclusive=True)
    except FileExistsError:
        pytest.fail("wrong error")
    except OSError:
        pytest.fail("exclusive write needs hard links (fails on FAT/some network filesystems); fall back to O_EXCL on the target")
