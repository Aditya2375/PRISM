import itertools
import os

import pytest

from kig import threshold as t


def test_any_k_of_n_recovers():
    sec = os.urandom(3000)
    sh = t.split(sec, 3, 5)
    for combo in itertools.combinations(sh, 3):
        assert t.combine(list(combo)) == sec


def test_fewer_than_k_refused():
    sh = t.split(b"x" * 64, 3, 5)
    with pytest.raises(t.ThresholdError):
        t.combine(sh[:2])


def test_mixed_sets_duplicates_and_corruption_refused():
    a, b = t.split(b"a" * 32, 2, 3), t.split(b"b" * 32, 2, 3)
    with pytest.raises(t.ThresholdError):
        t.combine([a[0], b[1]])
    with pytest.raises(t.ThresholdError):
        t.combine([a[0], a[0]])
    import json
    d = json.loads(a[1])
    from kig import crypto as c
    s = bytearray(c.b64d(d["share"]))
    s[0] ^= 1
    d["share"] = c.b64e(bytes(s))
    with pytest.raises(t.ThresholdError):
        t.combine([a[0], json.dumps(d).encode()])
    with pytest.raises(t.ThresholdError):
        t.combine([b"junk", b"junk"])


def test_bad_parameters():
    for k, n in [(1, 3), (4, 3), (2, 300)]:
        with pytest.raises(t.ThresholdError):
            t.split(b"s", k, n)


def test_hostile_share_fields_never_hang_or_raise_other_errors():
    import json
    import signal
    sh = t.split(b"z" * 48, 3, 5)
    junk = [0, -1, 256, 2**70, 1.5, "1", None, True, [], {}]
    signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError("hung")))
    signal.alarm(20)
    try:
        for field in ("i", "k", "n", "share", "nonce", "v", "fp"):
            for j in junk:
                ds = [json.loads(x) for x in sh[:3]]
                ds[0][field] = j
                try:
                    t.combine([json.dumps(d).encode() for d in ds])
                except t.ThresholdError:
                    pass
    finally:
        signal.alarm(0)


def test_one_damaged_share_is_named_and_extra_shares_recover():
    import json
    from kig import crypto as c
    sec = os.urandom(100)
    sh = t.split(sec, 3, 5)
    d = json.loads(sh[0]); b = bytearray(c.b64d(d["share"])); b[0] ^= 1; d["share"] = c.b64e(bytes(b))
    sh[0] = json.dumps(d).encode()
    assert t.combine(sh) == sec
    with pytest.raises(t.ThresholdError, match=r"damaged share index\(es\): \[1\]"):
        t.combine(sh[:3])


def test_forged_fingerprint_with_bad_share_still_recovers_from_other_subsets():
    import json
    from kig import crypto as c
    sec = os.urandom(40)
    sh = t.split(sec, 2, 4)
    d = json.loads(sh[0]); b = bytearray(c.b64d(d["share"])); b[5] ^= 1; d["share"] = c.b64e(bytes(b))
    d["fp"] = t._fp(d["i"], bytes(b))
    sh[0] = json.dumps(d).encode()
    assert t.combine(sh) == sec


def test_wrapping_key_is_full_256_bit():
    import json
    sh = t.split(b"x", 2, 2)
    assert len(json.loads(sh[0])["share"]) >= 43      # 32 bytes of share material
    from kig import crypto as c
    assert len(c.b64d(json.loads(sh[0])["share"])) == 32


def test_cli_split_and_combine(tmp_path):
    from kig import cli
    key = tmp_path / "backup.key"; key.write_bytes(os.urandom(2000))
    assert cli.main(["backup-key", "split", "--key", str(key), "-k", "2", "-n", "3", "--out-dir", str(tmp_path / "s")]) == 0
    out = tmp_path / "back.key"
    assert cli.main(["backup-key", "combine", "--shares", str(tmp_path / "s/share-3.json"),
                     str(tmp_path / "s/share-1.json"), "--out", str(out)]) == 0
    assert out.read_bytes() == key.read_bytes()
    assert cli.main(["backup-key", "combine", "--shares", str(tmp_path / "s/share-3.json"), "--out", str(out)]) == 2
