"""Cryptographic building blocks.

No custom primitives. Everything is composed from vetted implementations:

* ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), the X25519+ML-KEM-768 hybrid HPKE
  suite, HKDF-SHA256 and AES-256-GCM, all from ``cryptography``.

Key establishment is hybrid through the library's standard HPKE suite, so it
stays safe unless both X25519 and ML-KEM are broken.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    MLKEM768X25519PrivateKey,
    MLKEM768X25519PublicKey,
    Suite,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_PQ_PUB = 1184
KEM_PQ_SEED = 64
X_LEN = 32
SIG_PUB = 1952
SIG_SEED = 32
_SUITE = Suite(KEM.MLKEM768_X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)
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
# X25519 + ML-KEM-768 through the library's standard hybrid HPKE suite. We never
# combine the two shared secrets ourselves. Binding data goes in HPKE ``info``.


def _raw(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kem_keygen() -> tuple[bytes, bytes]:
    """Return (public, secret). public = mlkem_pk || x25519_pk; secret = mlkem_seed || x25519_sk."""
    m = mlkem.MLKEM768PrivateKey.generate()
    x = x25519.X25519PrivateKey.generate()
    pub = m.public_key().public_bytes_raw() + _raw(x.public_key())
    sec = m.private_bytes_raw() + x.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    return pub, sec


def _pub_obj(pub: bytes) -> MLKEM768X25519PublicKey:
    if len(pub) != KEM_PQ_PUB + X_LEN:
        raise CryptoError("bad KEM public key length")
    try:
        return MLKEM768X25519PublicKey(
            mlkem.MLKEM768PublicKey.from_public_bytes(pub[:KEM_PQ_PUB]),
            x25519.X25519PublicKey.from_public_bytes(pub[KEM_PQ_PUB:]),
        )
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("bad KEM public key") from exc


def _sec_obj(sec: bytes) -> MLKEM768X25519PrivateKey:
    if len(sec) != KEM_PQ_SEED + X_LEN:
        raise CryptoError("bad KEM secret key length")
    try:
        return MLKEM768X25519PrivateKey(
            mlkem.MLKEM768PrivateKey.from_seed_bytes(sec[:KEM_PQ_SEED]),
            x25519.X25519PrivateKey.from_private_bytes(sec[KEM_PQ_SEED:]),
        )
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("bad KEM secret key") from exc


def _info(pub: bytes, context: bytes) -> bytes:
    return b"kig/v2/kem\x00" + context + b"\x00" + hashlib.sha256(pub).digest()


def kem_encaps(pub: bytes, context: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, key). A fresh random key is sent through HPKE to ``pub``."""
    key = os.urandom(KEY_LEN)
    return _SUITE.encrypt(key, _pub_obj(pub), info=_info(pub, context)), key


def kem_decaps(sec: bytes, pub: bytes, ct: bytes, context: bytes) -> bytes:
    try:
        key = _SUITE.decrypt(ct, _sec_obj(sec), info=_info(pub, context))
    except CryptoError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("KEM decapsulation failed") from exc
    if len(key) != KEY_LEN:
        raise CryptoError("bad key length")
    return key


# ------------------------------------------------------------- signatures


def sig_keygen() -> tuple[bytes, bytes]:
    """Return (public, secret). The secret is the 32-byte ML-DSA-65 seed."""
    k = mldsa.MLDSA65PrivateKey.generate()
    return k.public_key().public_bytes_raw(), k.private_bytes_raw()


def _domain(purpose: str, msg: bytes) -> bytes:
    return b"kig/v1/" + purpose.encode("ascii") + b"\x00" + msg


def sign(sec: bytes, purpose: str, msg: bytes) -> bytes:
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(sec).sign(_domain(purpose, msg))


def verify(pub: bytes, purpose: str, msg: bytes, sig: bytes) -> bool:
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(sig, _domain(purpose, msg))
        return True
    except (InvalidSignature, ValueError, TypeError):
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
