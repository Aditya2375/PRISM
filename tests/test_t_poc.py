import json, os, threading, pytest
from kig import threshold as T, crypto as c
from kig.keystore import FileKeyStore
from kig.service import GuardService, StateCorrupt

S = os.urandom(48)

def _forge(share, ):
    d = json.loads(share); raw = os.urandom(32); d["share"] = c.b64e(raw); d["fp"] = T._fp(d["i"], raw)
    return json.dumps(d).encode()

def test_T1_one_stray_share_from_another_split_does_not_block_recovery():
    a, b = T.split(S, 3, 5), T.split(os.urandom(48), 3, 5)
    assert T.combine(a[:3] + [b[0]]) == S, "3 good shares plus one stray share from an old split: whole combine refused"

def test_T2_one_malicious_holder_cannot_block_recovery_large_k():
    sh = T.split(S, 6, 12)
    sh[0] = _forge(sh[0])                         # holder 1 returns random bytes with a recomputed fingerprint
    assert T.combine(sh) == S, "11 offered shares, 11 needed by 6: bad share first, tries capped at 200, recovery fails"

def test_T3_split_must_not_overwrite_existing_share_files(tmp_path):
    from kig import cli
    key = tmp_path / "backup.key"; key.write_bytes(os.urandom(96))
    out = tmp_path / "sh"
    assert cli.main(["backup-key", "split", "--key", str(key), "-k", "2", "-n", "3", "--out-dir", str(out)]) == 0
    first = (out / "share-1.json").read_bytes()
    rc = cli.main(["backup-key", "split", "--key", str(key), "-k", "2", "-n", "3", "--out-dir", str(out)])
    assert rc != 0 or (out / "share-1.json").read_bytes() == first, "second split silently overwrote the first set of shares"

def test_T4_combine_must_not_overwrite_an_existing_file(tmp_path):
    from kig import cli
    key = tmp_path / "backup.key"; key.write_bytes(os.urandom(96)); orig = key.read_bytes()
    out = tmp_path / "sh"
    cli.main(["backup-key", "split", "--key", str(key), "-k", "2", "-n", "3", "--out-dir", str(out)])
    (tmp_path / "other.key").write_bytes(b"precious")
    rc = cli.main(["backup-key", "combine", "--shares", str(out / "share-1.json"), str(out / "share-2.json"), "--out", str(tmp_path / "other.key")])
    assert rc != 0 and (tmp_path / "other.key").read_bytes() == b"precious", "combine overwrote an existing file"

def test_K1_pub_not_matching_keystore_secret_is_refused(tmp_path):
    ks = FileKeyStore(tmp_path / "ks", passphrase="")
    GuardService(tmp_path / "d", keystore=ks)
    other_pub, _ = c.sig_keygen()
    (tmp_path / "d" / "server_sign.pub").write_bytes(other_pub)
    try:
        GuardService(tmp_path / "d", keystore=ks)
    except Exception:
        return
    pytest.fail("service started with a public key that does not belong to its private key")

def test_K2_two_first_starts_race_and_end_with_matching_key_and_pub(tmp_path):
    bad = 0
    for trial in range(4):
        d, kd = tmp_path / f"d{trial}", tmp_path / f"k{trial}"
        bar = threading.Barrier(2)
        class KS(FileKeyStore):
            def get(self, name):
                r = super().get(name)
                try: bar.wait(2)
                except threading.BrokenBarrierError: pass
                return r
        res = []
        def go():
            try: res.append(GuardService(d, keystore=KS(kd, passphrase="")))
            except Exception as e: res.append(e)
        ts = [threading.Thread(target=go) for _ in range(2)]; [t.start() for t in ts]; [t.join() for t in ts]
        sec = FileKeyStore(kd, passphrase="").get("server-sign"); pub = (d / "server_sign.pub").read_bytes()
        ok = c.verify(pub, "x", b"m", c.sign(sec, "x", b"m"))
        if not ok or any(isinstance(r, Exception) is False and r.pub != pub for r in res): bad += 1
    assert bad == 0, f"{bad}/4 racing first starts left server_sign.pub not matching the stored key, or a process signing with another key"
