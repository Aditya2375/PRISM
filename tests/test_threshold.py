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
