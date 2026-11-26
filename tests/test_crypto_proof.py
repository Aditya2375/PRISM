"""Known-answer tests and format guards for the cryptographic layer.

Vectors are NIST ACVP-Server data (usnistgov/ACVP-Server, commit pinned in
tests/vectors/acvp.json). They show that the ``cryptography`` build we pin implements FIPS 203
and FIPS 204 for the parameter sets PRISM uses. We did not write any primitive.
"""
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from kig import backup as b
from kig import crypto as c
from kig import vault

V = json.loads((Path(__file__).parent / "vectors" / "acvp.json").read_text())


@pytest.mark.parametrize("t", V["mldsa65_keygen"], ids=lambda t: t["seed"][:8])
def test_ml_dsa_65_keygen_matches_acvp(t):
    k = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(t["seed"]))
    assert k.public_key().public_bytes_raw().hex().upper() == t["pk"].upper()


@pytest.mark.parametrize("t", V["mlkem768_keygen"], ids=lambda t: t["d"][:8])
def test_ml_kem_768_keygen_matches_acvp(t):
    k = mlkem.MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(t["d"] + t["z"]))
    assert k.public_key().public_bytes_raw().hex().upper() == t["ek"].upper()


@pytest.mark.parametrize("t", V["mldsa65_sigver"], ids=lambda t: t["reason"][:30])
def test_ml_dsa_65_sigver_matches_acvp(t):
    pk = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(t["pk"]))
    try:
        pk.verify(bytes.fromhex(t["signature"]), bytes.fromhex(t["message"]))
        ok = True
    except Exception:  # noqa: BLE001
        ok = False
    assert ok == t["valid"]


def test_our_sign_verify_and_domain_separation():
    pub, sec = c.sig_keygen()
    sig = c.sign(sec, "state", b"m")
    assert c.verify(pub, "state", b"m", sig)
    assert not c.verify(pub, "backup", b"m", sig), "a signature for one purpose must not verify for another"
    assert not c.verify(pub, "state", b"m2", sig)


def test_suite_id_names_every_primitive():
    for part in ("MLKEM768-X25519", "HKDF-SHA256", "ChaCha20Poly1305", "AES-256-GCM", "ML-DSA-65", "scrypt"):
        assert part in c.SUITE


def test_unknown_suite_is_refused_everywhere(w, tmp_path):
    blob = vault.seal(b"secret", "pw", "prism/test")
    d = json.loads(blob)
    d["hdr"]["suite"] = "PRISM-2:other"
    with pytest.raises(vault.VaultError):
        vault.open_(json.dumps(d).encode(), "pw", "prism/test")
    with pytest.raises(c.CryptoError):
        c.require_suite({}, "thing")
    st = json.loads((tmp_path / "data" / "state.json").read_text())
    assert st["suite"] == c.SUITE


def test_backup_with_other_suite_is_refused(w, tmp_path):
    pub, sec = c.kem_keygen()
    out = tmp_path / "x.bak"
    b.create(w.svc, pub, out)
    doc = json.loads(out.read_bytes())
    doc["suite"] = "PRISM-0:old"
    out.write_bytes(json.dumps(doc).encode())
    with pytest.raises(b.BackupError, match="suite"):
        b.verify_and_open(out, pub, sec, w.svc.pub)


def test_foreign_suite_is_refused_for_state_and_device_key_file(w, tmp_path):
    from kig.client import Device
    from kig.service import GuardService, StateCorrupt
    d = tmp_path / "data"
    svc_pub = (d / "server_sign.pub").read_bytes()
    st = json.loads((d / "state.json").read_text())
    st.pop("_sig")
    st["suite"] = "PRISM-0:old"
    st["_sig"] = c.b64e(c.sign(w.svc._sec, "state", c.canonical({k: v for k, v in st.items() if k != "_sig"})))
    (d / "state.json").write_text(json.dumps(st))
    with pytest.raises(StateCorrupt, match="suite"):
        GuardService(d, clock=w.clock)
    p = tmp_path / "dev.json"
    w.alice_laptop.save(p)
    raw = json.loads(p.read_text())
    raw["suite"] = "PRISM-0:old"
    p.write_text(json.dumps(raw))
    with pytest.raises(vault.VaultError, match="suite"):
        Device.load(p)
    assert svc_pub
