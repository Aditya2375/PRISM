"""Passphrase vault for private keys at rest.

A secret is sealed with AES-256-GCM under a key derived with scrypt (N=2^15, r=8, p=1)
from the passphrase and a random 16-byte salt. The header (format, KDF parameters, salt,
label) is authenticated as AAD, so changing any parameter or swapping the label fails the
tag. Files are written atomically with fsync, mode 0600.

Limits: Python cannot reliably wipe memory, and a passphrase supplied through the
environment is visible to the process owner. Use a hardware keystore for production.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import crypto as c

ENV_PASSPHRASE = "PRISM_PASSPHRASE"
_N, _R, _P = 2**15, 8, 1
_MAX_N = 2**20  # refuse a file that asks us to burn unbounded memory


class VaultError(Exception):
    pass


def passphrase_from_env() -> str | None:
    return os.environ.get(ENV_PASSPHRASE) or None


def _kdf(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def seal(secret: bytes, passphrase: str, label: str) -> bytes:
    if not passphrase:
        raise VaultError("empty passphrase")
    salt, nonce = os.urandom(16), os.urandom(12)
    hdr = {"v": 1, "suite": c.SUITE, "kdf": "scrypt", "n": _N, "r": _R, "p": _P, "salt": c.b64e(salt), "label": label}
    ct = AESGCM(_kdf(passphrase, salt, _N, _R, _P)).encrypt(nonce, secret, c.canonical(hdr))
    return json.dumps({"hdr": hdr, "nonce": c.b64e(nonce), "ct": c.b64e(ct)}, sort_keys=True).encode()


def is_sealed(blob: bytes) -> bool:
    try:
        d = json.loads(blob)
        return isinstance(d, dict) and "hdr" in d and "ct" in d
    except ValueError:
        return False


def open_(blob: bytes, passphrase: str | None, label: str) -> bytes:
    if not passphrase:
        raise VaultError("this key is encrypted; a passphrase is required")
    try:
        d = json.loads(blob)
        hdr = d["hdr"]
        c.require_suite(hdr, "key file")
        if hdr["v"] != 1 or hdr["kdf"] != "scrypt" or hdr["label"] != label:
            raise VaultError("unsupported or mismatched key file")
        n, r, p = hdr["n"], hdr["r"], hdr["p"]
        if not (all(isinstance(x, int) and not isinstance(x, bool) for x in (n, r, p))
                and 2**14 <= n <= _MAX_N and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
            raise VaultError("key file has unacceptable KDF parameters")
        key = _kdf(passphrase, c.b64d(hdr["salt"]), n, r, p)
        return AESGCM(key).decrypt(c.b64d(d["nonce"]), c.b64d(d["ct"]), c.canonical(hdr))
    except VaultError:
        raise
    except c.CryptoError as e:
        raise VaultError(str(e)) from None
    except InvalidTag:
        raise VaultError("wrong passphrase or the key file was modified") from None
    except Exception:  # noqa: BLE001
        raise VaultError("key file is damaged") from None


def write_atomic(path: str | Path, data: bytes, mode: int = 0o600, exclusive: bool = False) -> None:
    """Write via a randomly named temp file (never follows a symlink), fsync, then rename.

    With exclusive=True an existing target is never replaced: FileExistsError is raised instead.
    """
    p = Path(path)
    tmp = p.with_name(f".{p.name}.{os.urandom(6).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if exclusive:
            try:
                os.link(tmp, p)         # atomic, fails if the target exists
                os.unlink(tmp)
            except FileExistsError:
                raise
            except OSError:             # no hard links here (FAT, some network mounts): create the target exclusively
                tfd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
                with os.fdopen(tfd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.unlink(tmp)
        else:
            os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    dfd = os.open(p.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
