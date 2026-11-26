"""k-of-n split of a secret (for example the backup private key).

No secret-sharing maths is written here. A random 32-byte wrapping key encrypts the secret
with AES-256-GCM (cryptography library). The wrapping key is split as two 16-byte halves with
PyCryptodome's Shamir (Crypto.Protocol.SecretSharing), using the same share indices for both
halves, so one share carries one piece of each half. Fewer than k shares reveal nothing about
the wrapping key. Every share carries the same sealed secret and a fingerprint of its own
bytes, so a damaged share is named instead of just failing the whole combine. Shares from
different splits are refused. Honest limit: no verifiable secret sharing, so a share that was
forged with a matching fingerprint is only caught because AES-GCM then fails to open.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os

from Crypto.Protocol.SecretSharing import Shamir
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto as c

MAX_TRIES = 200


class ThresholdError(Exception):
    pass


def _int(v, lo: int, hi: int) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise ThresholdError("share has an invalid number field")
    return v


def _fp(i: int, share: bytes) -> str:
    return hashlib.sha256(b"kig/share/v1" + bytes([i]) + share).hexdigest()[:16]


def fingerprint(share: bytes) -> str:
    """Short fingerprint to record next to each share at split time."""
    try:
        return json.loads(share)["fp"]
    except (ValueError, KeyError, TypeError) as e:
        raise ThresholdError("not a share") from e


def split(secret: bytes, k: int, n: int) -> list[bytes]:
    if not (2 <= k <= n <= 255):
        raise ThresholdError("need 2 <= k <= n <= 255")
    wrap, set_id, nonce = os.urandom(32), os.urandom(8), os.urandom(12)
    hdr = {"v": 1, "set": c.b64e(set_id), "k": k, "n": n}
    sealed = AESGCM(wrap).encrypt(nonce, secret, c.canonical(hdr))
    a, b = Shamir.split(k, n, wrap[:16]), Shamir.split(k, n, wrap[16:])
    out = []
    for (i, sa), (j, sb) in zip(a, b):
        assert i == j
        sh = sa + sb
        out.append(json.dumps({**hdr, "i": i, "share": c.b64e(sh), "fp": _fp(i, sh), "nonce": c.b64e(nonce),
                               "sealed": c.b64e(sealed)}).encode())
    return out


def _parse(raw: bytes) -> dict:
    try:
        d = json.loads(raw)
        if not isinstance(d, dict) or d.get("v") != 1:
            raise ThresholdError("not a share, or an unknown version")
        n = _int(d["n"], 2, 255)
        _int(d["k"], 2, n)
        _int(d["i"], 1, n)
        share, nonce = c.b64d(d["share"]), c.b64d(d["nonce"])
        if len(share) != 32 or len(nonce) != 12 or not isinstance(d["set"], str) or not isinstance(d["sealed"], str):
            raise ThresholdError("share has wrong field sizes")
        d["_share"], d["_good"] = share, d.get("fp") == _fp(d["i"], share)
        return d
    except ThresholdError:
        raise
    except (c.CryptoError, ValueError, KeyError, TypeError) as e:
        raise ThresholdError("not a valid share") from e


def combine(shares: list[bytes]) -> bytes:
    ds, unreadable = [], []
    for pos, raw in enumerate(shares, 1):
        try:
            ds.append(_parse(raw))
        except ThresholdError:
            unreadable.append(f"input #{pos}")
    if not ds:
        raise ThresholdError("no readable shares" + (f" ({', '.join(unreadable)} unreadable)" if unreadable else ""))
    f = ds[0]
    ident = lambda d: (d["set"], d["k"], d["n"], d["sealed"], d["nonce"])  # noqa: E731
    if any(ident(d) != ident(f) for d in ds):
        raise ThresholdError("shares are from different sets")
    seen, uniq = set(), []
    for d in ds:
        if d["i"] not in seen:
            seen.add(d["i"]); uniq.append(d)
    k = f["k"]
    bad = [d["i"] for d in uniq if not d["_good"]] + unreadable
    good = [d for d in uniq if d["_good"]]
    if len(good) < k:
        raise ThresholdError(f"need {k} intact shares, got {len(good)} distinct and intact"
                             + (f"; damaged share index(es): {bad}" if bad else ""))
    hdr = {"v": 1, "set": f["set"], "k": k, "n": f["n"]}
    for tries, combo in enumerate(itertools.combinations(good, k)):
        if tries >= MAX_TRIES:
            break
        try:
            wrap = (Shamir.combine([(d["i"], d["_share"][:16]) for d in combo]) +
                    Shamir.combine([(d["i"], d["_share"][16:]) for d in combo]))
            return AESGCM(wrap).decrypt(c.b64d(f["nonce"]), c.b64d(f["sealed"]), c.canonical(hdr))
        except (InvalidTag, ValueError, c.CryptoError):
            continue
    raise ThresholdError("shares do not combine: a share was altered or is not from this set"
                         + (f" (damaged by fingerprint: {bad})" if bad else ""))
