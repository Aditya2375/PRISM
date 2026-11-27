import json, os, random, pytest
from kig import threshold as T, crypto as c

S = os.urandom(48)

def _skip_S1_combine_only_raises_ThresholdError_on_junk_shares():
    rnd = random.Random(5)
    sh = T.split(S, 3, 5)
    junk_vals = [0, -1, 1, 255, 256, 2**70, 1.5, "1", None, True, [], {}]
    for _ in range(600):
        ds = [json.loads(x) for x in rnd.sample(sh, 3)]
        d = rnd.choice(ds); k = rnd.choice(["i", "share", "k", "n", "v", "set", "nonce", "sealed"])
        r = rnd.random()
        if r < 0.3: d[k] = rnd.choice(junk_vals)
        elif r < 0.5: d.pop(k, None)
        elif r < 0.7 and isinstance(d.get(k), str): d[k] = d[k][: rnd.randrange(len(d[k]) + 1)]
        else: d[k] = rnd.choice(junk_vals)
        try:
            T.combine([json.dumps(x).encode() for x in ds])
        except T.ThresholdError:
            pass
        except Exception as e:
            raise AssertionError(f"non-ThresholdError {type(e).__name__}: {e} for field {k}={d.get(k)!r}")

def test_S2_k_minus_one_and_garbage_input_types():
    sh = T.split(S, 3, 5)
    for bad in ([], [b""], [b"null"], [b"[]"], [b"{}"], [sh[0], sh[0], sh[1]], sh[:2], [b"\xff\xfe"]):
        with pytest.raises(T.ThresholdError):
            T.combine(bad)

def test_S3_key_has_full_256_bit_strength():
    import inspect
    src = inspect.getsource(T)
    assert "os.urandom(32)" in src or "wrap * 2" not in src, "AES-256 key is a 16-byte secret repeated twice: 128 bits of entropy (Grover: ~64)"

def test_S4_more_than_k_shares_with_one_corrupt_still_recovers_or_names_it():
    sh = T.split(S, 3, 5); d = json.loads(sh[0]); d["share"] = d["share"][:-4] + "AAAA"; sh[0] = json.dumps(d).encode()
    try:
        out = T.combine(sh)            # 5 shares offered, one corrupt: only the first 3 are used
        assert out == S
    except T.ThresholdError:
        pytest.fail("4 good shares offered with the corrupt one first: combine fails instead of trying subsets or naming the bad share")

def test_S5_negative_share_index_must_not_hang():
    import signal
    sh = T.split(S, 3, 5); ds = [json.loads(x) for x in sh[:3]]; ds[0]["i"] = -1
    def h(*a): raise TimeoutError("combine did not return in 3 s on a share with index -1")
    signal.signal(signal.SIGALRM, h); signal.alarm(3)
    try:
        with pytest.raises(T.ThresholdError):
            T.combine([json.dumps(d).encode() for d in ds])
    finally:
        signal.alarm(0)
