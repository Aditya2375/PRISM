"""Cryptographic building blocks.

No custom primitives. Everything is composed from vetted implementations:

* ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) from ``pqcrypto`` (PQClean).
* X25519, HKDF-SHA256 and AES-256-GCM from ``cryptography``.

Key establishment is hybrid: the wrap key is derived from both the ML-KEM and
the X25519 shared secrets, so it stays safe unless both are broken.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

import pqcrypto.kem.ml_kem_768 as _kem
import pqcrypto.sign.ml_dsa_65 as _dsa
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto import InvalidSignatureError

KEM_PQ_PUB = _kem.PUBLIC_KEY_SIZE
KEM_PQ_CT = _kem.CIPHERTEXT_SIZE
KEM_PQ_SEC = _kem.SECRET_KEY_SIZE
X_LEN = 32
KEY_LEN = 32
NONCE_LEN = 12


class CryptoError(Exception):
    """Raised for any failed decryption, verification or malformed input."""


# ---------------------------------------------------------------- encoding


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("invalid base64") from exc


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding used for everything that is signed or hashed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------ hybrid KEM


def kem_keygen() -> tuple[bytes, bytes]:
    """Return (public, secret). public = mlkem_pk || x25519_pk, secret likewise."""
    pq_pub, pq_sec = _kem.keygen()
    xsec = X25519PrivateKey.generate()
    xpub = xsec.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    xsec_raw = xsec.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return pq_pub + xpub, pq_sec + xsec_raw


def _derive(ss_pq: bytes, ss_x: bytes, ct: bytes, pub: bytes, context: bytes) -> bytes:
    info = b"kig/v1/hybrid-kem\x00" + context + b"\x00" + sha256_hex(pub).encode() + ct
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(
        ss_pq + ss_x
    )


def kem_encaps(pub: bytes, context: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, key). ``context`` binds the key to its purpose."""
    if len(pub) != KEM_PQ_PUB + X_LEN:
        raise CryptoError("bad KEM public key length")
    pq_pub, x_pub = pub[:KEM_PQ_PUB], pub[KEM_PQ_PUB:]
    pq_ct, ss_pq = _kem.encaps(pq_pub)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(x_pub))
    ct = pq_ct + eph_pub
    return ct, _derive(ss_pq, ss_x, ct, pub, context)


def kem_decaps(sec: bytes, pub: bytes, ct: bytes, context: bytes) -> bytes:
    if len(sec) != KEM_PQ_SEC + X_LEN or len(ct) != KEM_PQ_CT + X_LEN:
        raise CryptoError("bad KEM key or ciphertext length")
    pq_sec, x_sec = sec[:KEM_PQ_SEC], sec[KEM_PQ_SEC:]
    pq_ct, eph_pub = ct[:KEM_PQ_CT], ct[KEM_PQ_CT:]
    try:
        ss_pq = _kem.decaps(pq_sec, pq_ct)
        ss_x = X25519PrivateKey.from_private_bytes(x_sec).exchange(
            X25519PublicKey.from_public_bytes(eph_pub)
        )
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("KEM decapsulation failed") from exc
    return _derive(ss_pq, ss_x, ct, pub, context)


# ------------------------------------------------------------- signatures


def sig_keygen() -> tuple[bytes, bytes]:
    return _dsa.keygen()


def _domain(purpose: str, msg: bytes) -> bytes:
    return b"kig/v1/" + purpose.encode("ascii") + b"\x00" + msg


def sign(sec: bytes, purpose: str, msg: bytes) -> bytes:
    return _dsa.sign(sec, _domain(purpose, msg))


def verify(pub: bytes, purpose: str, msg: bytes, sig: bytes) -> bool:
    try:
        _dsa.verify(pub, _domain(purpose, msg), sig)
        return True
    except (InvalidSignatureError, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001  malformed key or signature length
        return False


# ------------------------------------------------------------------- AEAD


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise CryptoError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as exc:
        raise CryptoError("authentication failed") from exc


def random_key() -> bytes:
    return os.urandom(KEY_LEN)
