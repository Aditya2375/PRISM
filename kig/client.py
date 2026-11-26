"""Device-side client. Holds the device's private keys and does all file crypto.

The service only ever receives ciphertext, wrapped keys and signed requests.
"""
from __future__ import annotations

import hmac as _hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes, hmac

from . import crypto as c
from . import vault

Transport = Callable[[dict[str, Any]], dict[str, Any]]


def _file_aad(file_id: str, epoch: int) -> bytes:
    return f"kig/v1/file|{file_id}|{epoch}".encode()


def _commit(dek: bytes, file_id: str, epoch: int) -> str:
    """Key commitment: AES-GCM alone does not bind a ciphertext to one key, this tag does."""
    h = hmac.HMAC(dek, hashes.SHA256())
    h.update(f"prism/key-commit/v1|{file_id}|{epoch}".encode())
    return h.finalize().hex()


def _wrap_ctx(file_id: str, device_id: str, epoch: int) -> bytes:
    return f"kig/v1/wrap|{file_id}|{device_id}|{epoch}".encode()


def device_fingerprint(device: str, user: str, sign_pub: bytes, kem_pub: bytes) -> str:
    """SHA-256 over the device id, user and both public keys, as 8 groups of 8 hex digits.

    The enrolling person reads it off their own device and the admin compares it before enrolling, over a
    channel the server does not control (voice, in person). It is a plain hash of public data, not a new scheme.
    """
    import hashlib
    h = hashlib.sha256()
    for part in (b"PRISM-1 device fingerprint", device.encode(), user.encode(), sign_pub, kem_pub):
        h.update(len(part).to_bytes(4, "big")); h.update(part)
    x = h.hexdigest()
    return "-".join(x[k:k + 8] for k in range(0, 64, 8))


@dataclass
class Device:
    device_id: str
    user: str
    sign_pub: bytes
    sign_sec: bytes
    kem_pub: bytes
    kem_sec: bytes

    @classmethod
    def generate(cls, device_id: str, user: str) -> "Device":
        sp, ss = c.sig_keygen()
        kp, ks = c.kem_keygen()
        return cls(device_id, user, sp, ss, kp, ks)

    def fingerprint(self) -> str:
        return device_fingerprint(self.device_id, self.user, self.sign_pub, self.kem_pub)

    def public_args(self) -> dict[str, str]:
        return {"device": self.device_id, "user": self.user,
                "sign_pub": c.b64e(self.sign_pub), "kem_pub": c.b64e(self.kem_pub)}

    def save(self, path: str | Path, passphrase: str | None = None) -> None:
        """Write the key file atomically. With a passphrase (or PRISM_PASSPHRASE) it is encrypted."""
        data = {k: (c.b64e(v) if isinstance(v, bytes) else v) for k, v in self.__dict__.items()}
        data["suite"] = c.SUITE
        raw = json.dumps(data).encode()
        passphrase = passphrase or vault.passphrase_from_env()
        blob = vault.seal(raw, passphrase, "prism/device-key") if passphrase else raw
        vault.write_atomic(path, blob)

    @classmethod
    def load(cls, path: str | Path, passphrase: str | None = None) -> "Device":
        blob = Path(path).read_bytes()
        if vault.is_sealed(blob):
            blob = vault.open_(blob, passphrase or vault.passphrase_from_env(), "prism/device-key")
        try:
            raw = json.loads(blob)
            c.require_suite(raw, "device key file")
            return cls(raw["device_id"], raw["user"], *(c.b64d(raw[k]) for k in
                       ("sign_pub", "sign_sec", "kem_pub", "kem_sec")))
        except c.CryptoError as e:
            raise vault.VaultError(str(e)) from None
        except Exception:  # noqa: BLE001
            raise vault.VaultError("key file is damaged") from None


class Client:
    def __init__(self, device: Device, transport: Transport, clock: Callable[[], float] = time.time,
                 audience: str = "primary", state_path: str | Path | None = None):
        self.dev, self.send, self.clock, self.aud = device, transport, clock, audience
        self.state_path = Path(state_path) if state_path else None
        self.seen_epoch: dict[str, int] = {}   # newest key version this client has seen per file
        self.rotation_errors: list[str] = []   # auto-rotation failures other than a lost race
        if self.state_path and self.state_path.exists():
            try:
                self.seen_epoch = {k: int(v) for k, v in json.loads(self.state_path.read_text()).items()}
            except (ValueError, OSError, TypeError):
                raise c.CryptoError("client state file is damaged; refusing to start without its rollback record") from None

    def _note_epoch(self, file_id: str, epoch: int) -> None:
        if epoch > self.seen_epoch.get(file_id, 0):
            self.seen_epoch[file_id] = epoch
            if self.state_path:
                vault.write_atomic(self.state_path, json.dumps(self.seen_epoch, sort_keys=True).encode())

    # -- envelope ------------------------------------------------------------
    def envelope(self, cmd: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        body = {"cmd": cmd, "device": self.dev.device_id, "ts": round(self.clock(), 3),
                "nonce": secrets.token_hex(16), "args": args or {}, "aud": self.aud}
        body["sig"] = c.b64e(c.sign(self.dev.sign_sec, "cmd", c.canonical(body)))
        return body

    def call(self, cmd: str, **args: Any) -> dict[str, Any]:
        return self.send(self.envelope(cmd, args))

    # -- key wrapping ----------------------------------------------------------
    def _wrap_for(self, dek: bytes, file_id: str, epoch: int, recipients: dict[str, str]) -> dict[str, Any]:
        out = {}
        for dev_id, kem_pub_b64 in recipients.items():
            pub = c.b64d(kem_pub_b64)
            ct, kek = c.kem_encaps(pub, _wrap_ctx(file_id, dev_id, epoch))
            out[dev_id] = {"ct": c.b64e(ct),
                           "blob": c.b64e(c.aead_encrypt(kek, dek, _file_aad(file_id, epoch)))}
        return out

    def _unwrap(self, wrap: dict[str, Any], file_id: str, epoch: int) -> bytes:
        kek = c.kem_decaps(self.dev.kem_sec, self.dev.kem_pub, c.b64d(wrap["ct"]),
                           _wrap_ctx(file_id, self.dev.device_id, epoch))
        return c.aead_decrypt(kek, c.b64d(wrap["blob"]), _file_aad(file_id, epoch))

    def _recipients(self, acl: list[str]) -> dict[str, str]:
        return self.call("eligible", users=acl)["devices"]

    # -- file operations -------------------------------------------------------
    def put_file(self, file_id: str, plaintext: bytes, acl: list[str] | None = None) -> dict[str, Any]:
        acl = sorted(set(acl or []) | {self.dev.user})
        dek = c.random_key()
        ct = c.aead_encrypt(dek, plaintext, _file_aad(file_id, 1))
        wraps = self._wrap_for(dek, file_id, 1, self._recipients(acl))
        self._note_epoch(file_id, 1)
        return self.call("put_file", file_id=file_id, acl=acl, ciphertext=c.b64e(ct), wraps=wraps,
                         commit=_commit(dek, file_id, 1))

    def _open(self, file_id: str, r: dict[str, Any]) -> bytes:
        epoch = r["epoch"]
        dek = self._unwrap(r["wrap"], file_id, epoch)
        if not isinstance(r.get("commit"), str) or not _hmac.compare_digest(r["commit"], _commit(dek, file_id, epoch)):
            raise c.CryptoError("key commitment mismatch: ciphertext is not bound to this key")
        return c.aead_decrypt(dek, c.b64d(r["ciphertext"]), _file_aad(file_id, epoch))

    def fetch(self, file_id: str, auto_rotate: bool = True, epoch: int | None = None) -> bytes:
        """Fetch and decrypt. Asking for the current version never accepts an older one than already seen.

        Only an explicit ``epoch=`` (an in-flight transfer of a version you chose) may return an older
        version, and that never lowers the recorded newest version.
        """
        r = self.call("fetch", file_id=file_id) if epoch is None else self.call("fetch", file_id=file_id, epoch=epoch)
        got = r["epoch"]
        if epoch is None and got < self.seen_epoch.get(file_id, 0):
            raise c.CryptoError(f"rollback detected: server offered version {got}, already saw {self.seen_epoch[file_id]}")
        if epoch is not None and got != epoch:
            raise c.CryptoError("server answered with a different version than requested")
        plain = self._open(file_id, r)
        if epoch is None:
            self._note_epoch(file_id, got)
        if r["needs_rotation"] and auto_rotate and epoch is None and r.get("can_rotate"):
            try:
                self._rotate_from(file_id, got, plain, r["acl"])
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", "") != "conflict":     # a lost race is fine; anything else is surfaced
                    self.rotation_errors.append(f"{file_id}: {getattr(exc, 'code', type(exc).__name__)}: {exc}")
        return plain

    def rotate(self, file_id: str, acl: list[str] | None = None) -> dict[str, Any]:
        r = self.call("fetch", file_id=file_id)
        if r["epoch"] < self.seen_epoch.get(file_id, 0):
            raise c.CryptoError(f"rollback detected: server offered version {r['epoch']}, already saw {self.seen_epoch[file_id]}")
        plain = self._open(file_id, r)
        return self._rotate_from(file_id, r["epoch"], plain, acl or r["acl"], change_acl=acl is not None)

    def _rotate_from(self, file_id: str, epoch: int, plain: bytes, acl: list[str],
                     change_acl: bool = False) -> dict[str, Any]:
        new_epoch = epoch + 1
        dek = c.random_key()
        ct = c.aead_encrypt(dek, plain, _file_aad(file_id, new_epoch))
        wraps = self._wrap_for(dek, file_id, new_epoch, self._recipients(acl))
        args: dict[str, Any] = {"file_id": file_id, "expected_epoch": epoch, "commit": _commit(dek, file_id, new_epoch),
                                "ciphertext": c.b64e(ct), "wraps": wraps}
        if change_acl:
            args["acl"] = acl
        res = self.call("rotate", **args)
        self._note_epoch(file_id, new_epoch)
        return res
