"""Crypto helpers: hybrid X25519+ML-KEM-768 KEM and Ed25519+ML-DSA-65 signatures."""
import os
from typing import Tuple, Union

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65


# ML-KEM-768 instance (already instantiated)
_ml_kem_768 = ML_KEM_768

# ML-DSA-65 instance (already instantiated)
_ml_dsa_65 = ML_DSA_65


# Type aliases
KEMPublicKey = bytes  # X25519 pk (32) || ML-KEM-768 pk (1184)
KEMPrivateKey = bytes  # X25519 sk (32) || ML-KEM-768 sk (2400)
KEMCiphertext = bytes  # X25519 ct (32) || ML-KEM-768 ct (1088)
KEMSharedSecret = bytes  # 32 bytes (X25519) + 32 bytes (ML-KEM) = 64 bytes

SIGPublicKey = bytes  # Ed25519 pk (32) || ML-DSA-65 pk (1952)
SIGPrivateKey = bytes  # Ed25519 sk (32) || ML-DSA-65 sk (4032)
Signature = bytes  # Ed25519 sig (64) || ML-DSA-65 sig (3309)


def _split_kem_pk(pk: KEMPublicKey) -> Tuple[bytes, bytes]:
    """Split hybrid KEM public key into X25519 and ML-KEM parts."""
    if len(pk) != 32 + 1184:
        raise ValueError(f"Invalid KEM public key length: {len(pk)}")
    return pk[:32], pk[32:]


def _split_kem_sk(sk: KEMPrivateKey) -> Tuple[bytes, bytes]:
    """Split hybrid KEM private key into X25519 and ML-KEM parts."""
    if len(sk) != 32 + 2400:
        raise ValueError(f"Invalid KEM private key length: {len(sk)}")
    return sk[:32], sk[32:]


def _split_kem_ct(ct: KEMCiphertext) -> Tuple[bytes, bytes]:
    """Split hybrid KEM ciphertext into X25519 and ML-KEM parts."""
    if len(ct) != 32 + 1088:
        raise ValueError(f"Invalid KEM ciphertext length: {len(ct)}")
    return ct[:32], ct[32:]


def _split_sig_pk(pk: SIGPublicKey) -> Tuple[bytes, bytes]:
    """Split hybrid signature public key into Ed25519 and ML-DSA parts."""
    if len(pk) != 32 + 1952:
        raise ValueError(f"Invalid SIG public key length: {len(pk)}")
    return pk[:32], pk[32:]


def _split_sig_sk(sk: SIGPrivateKey) -> Tuple[bytes, bytes]:
    """Split hybrid signature private key into Ed25519 and ML-DSA parts."""
    if len(sk) != 32 + 4032:
        raise ValueError(f"Invalid SIG private key length: {len(sk)}")
    return sk[:32], sk[32:]


def _split_sig(sig: Signature) -> Tuple[bytes, bytes]:
    """Split hybrid signature into Ed25519 and ML-DSA parts."""
    if len(sig) != 64 + 3309:
        raise ValueError(f"Invalid signature length: {len(sig)}")
    return sig[:64], sig[64:]


def kem_keygen() -> Tuple[KEMPublicKey, KEMPrivateKey]:
    """Generate a hybrid KEM key pair (X25519 + ML-KEM-768)."""
    # X25519
    x25519_sk = X25519PrivateKey.generate()
    x25519_pk = x25519_sk.public_key()
    x25519_sk_bytes = x25519_sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    x25519_pk_bytes = x25519_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # ML-KEM-768
    ml_kem_pk, ml_kem_sk = _ml_kem_768.keygen()

    return (
        x25519_pk_bytes + ml_kem_pk,
        x25519_sk_bytes + ml_kem_sk,
    )


def kem_encaps(pk: KEMPublicKey) -> Tuple[KEMCiphertext, KEMSharedSecret]:
    """Encapsulate a shared secret to a hybrid KEM public key."""
    x25519_pk_bytes, ml_kem_pk = _split_kem_pk(pk)

    # X25519 encapsulation (ephemeral key agreement)
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x25519_ss = eph_sk.exchange(X25519PublicKey.from_public_bytes(x25519_pk_bytes))

    # ML-KEM-768 encapsulation - NOTE: this library returns (ss, ct) not (ct, ss)!
    ml_kem_ss, ml_kem_ct = _ml_kem_768.encaps(ml_kem_pk)

    return (
        eph_pk_bytes + ml_kem_ct,
        x25519_ss + ml_kem_ss,
    )


def kem_decaps(sk: KEMPrivateKey, ct: KEMCiphertext) -> KEMSharedSecret:
    """Decapsulate a shared secret from a hybrid KEM ciphertext."""
    x25519_sk_bytes, ml_kem_sk = _split_kem_sk(sk)
    x25519_ct_bytes, ml_kem_ct = _split_kem_ct(ct)

    # X25519 decapsulation
    x25519_sk = X25519PrivateKey.from_private_bytes(x25519_sk_bytes)
    x25519_ss = x25519_sk.exchange(X25519PublicKey.from_public_bytes(x25519_ct_bytes))

    # ML-KEM-768 decapsulation
    ml_kem_ss = _ml_kem_768.decaps(ml_kem_sk, ml_kem_ct)

    return x25519_ss + ml_kem_ss


def sig_keygen() -> Tuple[SIGPublicKey, SIGPrivateKey]:
    """Generate a hybrid signature key pair (Ed25519 + ML-DSA-65)."""
    # Ed25519
    ed25519_sk = Ed25519PrivateKey.generate()
    ed25519_pk = ed25519_sk.public_key()
    ed25519_sk_bytes = ed25519_sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ed25519_pk_bytes = ed25519_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # ML-DSA-65
    ml_dsa_pk, ml_dsa_sk = _ml_dsa_65.keygen()

    return (
        ed25519_pk_bytes + ml_dsa_pk,
        ed25519_sk_bytes + ml_dsa_sk,
    )


def sign(sk: SIGPrivateKey, msg: bytes) -> Signature:
    """Sign a message with hybrid Ed25519 + ML-DSA-65."""
    ed25519_sk_bytes, ml_dsa_sk = _split_sig_sk(sk)

    # Ed25519 signature
    ed25519_sk = Ed25519PrivateKey.from_private_bytes(ed25519_sk_bytes)
    ed25519_sig = ed25519_sk.sign(msg)

    # ML-DSA-65 signature
    ml_dsa_sig = _ml_dsa_65.sign(ml_dsa_sk, msg)

    return ed25519_sig + ml_dsa_sig


def verify(pk: SIGPublicKey, msg: bytes, sig: Signature) -> bool:
    """Verify a hybrid Ed25519 + ML-DSA-65 signature. Both must verify."""
    ed25519_pk_bytes, ml_dsa_pk = _split_sig_pk(pk)
    ed25519_sig, ml_dsa_sig = _split_sig(sig)

    # Ed25519 verification
    try:
        ed25519_pk = Ed25519PublicKey.from_public_bytes(ed25519_pk_bytes)
        ed25519_pk.verify(ed25519_sig, msg)
    except Exception:
        return False

    # ML-DSA-65 verification
    try:
        _ml_dsa_65.verify(ml_dsa_pk, msg, ml_dsa_sig)
    except Exception:
        return False

    return True