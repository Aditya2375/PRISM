"""k-of-n split of a secret (for example the backup private key).

No secret-sharing maths is written here. A random 16-byte wrapping key encrypts the
secret with AES-GCM (cryptography library); only that wrapping key is split, using
PyCryptodome's Shamir implementation (Crypto.Protocol.SecretSharing). Every share
carries the same sealed secret plus one share of the wrapping key, so fewer than k
shares reveal nothing about the wrapping key. Shares carry an id of the set, so
shares from different splits are refused. Honest limit: the sealed secret is
repeated in each share, and there is no verifiable secret sharing: a corrupt share
is detected only because AES-GCM then fails to open.
"""
from __future__ import annotations

import json
import os

from Crypto.Protocol.SecretSharing import Shamir
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto as c


class ThresholdError(Exception):
    pass


def split(secret: bytes, k: int, n: int) -> list[bytes]:
    if not (2 <= k <= n <= 255):
        raise ThresholdError("need 2 <= k <= n <= 255")
    wrap = os.urandom(16)
    set_id = os.urandom(8)
    nonce = os.urandom(12)
    hdr = {"v": 1, "set": c.b64e(set_id), "k": k, "n": n}
    sealed = AESGCM(wrap * 2).encrypt(nonce, secret, c.canonical(hdr))
    shares = Shamir.split(k, n, wrap)
    return [json.dumps({**hdr, "i": i, "share": c.b64e(s), "nonce": c.b64e(nonce),
                        "sealed": c.b64e(sealed)}).encode() for i, s in shares]


def combine(shares: list[bytes]) -> bytes:
    try:
        ds = [json.loads(s) for s in shares]
        first = ds[0]
        hdr = {"v": first["v"], "set": first["set"], "k": first["k"], "n": first["n"]}
        if first["v"] != 1:
            raise ThresholdError("unknown share version")
        if any({"v": d["v"], "set": d["set"], "k": d["k"], "n": d["n"]} != hdr or
               d["sealed"] != first["sealed"] or d["nonce"] != first["nonce"] for d in ds):
            raise ThresholdError("shares are from different sets")
        idx = [d["i"] for d in ds]
        if len(set(idx)) != len(idx):
            raise ThresholdError("duplicate share")
        if len(ds) < hdr["k"]:
            raise ThresholdError(f"need {hdr['k']} shares, got {len(ds)}")
        wrap = Shamir.combine([(d["i"], c.b64d(d["share"])) for d in ds[:hdr["k"]]])
        return AESGCM(wrap * 2).decrypt(c.b64d(first["nonce"]), c.b64d(first["sealed"]), c.canonical(hdr))
    except ThresholdError:
        raise
    except (InvalidTag, c.CryptoError, ValueError, KeyError, TypeError, IndexError) as e:
        raise ThresholdError("shares do not combine (corrupt, wrong or too few)") from e
