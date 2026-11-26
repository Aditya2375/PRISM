import pytest

from kig import crypto as c


def test_kem_roundtrip_and_context_binding():
    pub, sec = c.kem_keygen()
    ct, k1 = c.kem_encaps(pub, b"ctx")
    assert c.kem_decaps(sec, pub, ct, b"ctx") == k1
    assert c.kem_decaps(sec, pub, ct, b"other") != k1


def test_kem_wrong_secret_gives_different_key():
    pub, _ = c.kem_keygen()
    _, other_sec = c.kem_keygen()
    ct, k1 = c.kem_encaps(pub, b"ctx")
    try:
        k2 = c.kem_decaps(other_sec, pub, ct, b"ctx")
    except c.CryptoError:
        return
    assert k2 != k1


def test_kem_rejects_bad_lengths():
    with pytest.raises(c.CryptoError):
        c.kem_encaps(b"short", b"x")
    pub, sec = c.kem_keygen()
    with pytest.raises(c.CryptoError):
        c.kem_decaps(sec, pub, b"short", b"x")


def test_signature_domain_separation():
    pub, sec = c.sig_keygen()
    sig = c.sign(sec, "cmd", b"hello")
    assert c.verify(pub, "cmd", b"hello", sig)
    assert not c.verify(pub, "audit", b"hello", sig)
    assert not c.verify(pub, "cmd", b"hellp", sig)
    assert not c.verify(pub, "cmd", b"hello", sig[:-1])
    assert not c.verify(b"junk", "cmd", b"hello", sig)


def test_aead_tamper_and_aad():
    k = c.random_key()
    blob = c.aead_encrypt(k, b"secret", b"aad")
    assert c.aead_decrypt(k, blob, b"aad") == b"secret"
    with pytest.raises(c.CryptoError):
        c.aead_decrypt(k, blob, b"other")
    bad = bytearray(blob)
    bad[-1] ^= 1
    with pytest.raises(c.CryptoError):
        c.aead_decrypt(k, bytes(bad), b"aad")
    assert c.aead_encrypt(k, b"x", b"") != c.aead_encrypt(k, b"x", b"")
