"""Device-side client. Holds the device's private keys and does all file crypto.

The service only ever receives ciphertext, wrapped keys and signed requests.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import crypto as c
from . import vault

Transport = Callable[[dict[str, Any]], dict[str, Any]]


def _file_aad(file_id: str, epoch: int) -> bytes:
    return f"kig/v1/file|{file_id}|{epoch}".encode()


def _wrap_ctx(file_id: str, device_id: str, epoch: int) -> bytes:
    return f"kig/v1/wrap|{file_id}|{device_id}|{epoch}".encode()


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

    def public_args(self) -> dict[str, str]:
        return {"device": self.device_id, "user": self.user,
                "sign_pub": c.b64e(self.sign_pub), "kem_pub": c.b64e(self.kem_pub)}

    def save(self, path: str | Path, passphrase: str | None = None) -> None:
        """Write the key file atomically. With a passphrase (or PRISM_PASSPHRASE) it is encrypted."""
        data = {k: (c.b64e(v) if isinstance(v, bytes) else v) for k, v in self.__dict__.items()}
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
            return cls(raw["device_id"], raw["user"], *(c.b64d(raw[k]) for k in
                       ("sign_pub", "sign_sec", "kem_pub", "kem_sec")))
        except Exception:  # noqa: BLE001
            raise vault.VaultError("key file is damaged") from None


class Client:
    def __init__(self, device: Device, transport: Transport, clock: Callable[[], float] = time.time,
                 audience: str = "primary"):
        self.dev, self.send, self.clock, self.aud = device, transport, clock, audience
        self.seen_epoch: dict[str, int] = {}   # newest key version this client has seen per file

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
        return self.call("put_file", file_id=file_id, acl=acl, ciphertext=c.b64e(ct), wraps=wraps)

    def fetch(self, file_id: str, auto_rotate: bool = True, epoch: int | None = None) -> bytes:
        r = self.call("fetch", file_id=file_id) if epoch is None else self.call("fetch", file_id=file_id, epoch=epoch)
        epoch = r["epoch"]
        if self.seen_epoch.get(file_id, 0) > epoch and not (r.get("grace_remaining_s") is not None):
            raise c.CryptoError(f"rollback detected: server offered version {epoch}, already saw {self.seen_epoch[file_id]}")
        dek = self._unwrap(r["wrap"], file_id, epoch)
        plain = c.aead_decrypt(dek, c.b64d(r["ciphertext"]), _file_aad(file_id, epoch))
        self.seen_epoch[file_id] = max(self.seen_epoch.get(file_id, 0), epoch)
        if r["needs_rotation"] and auto_rotate:
            try:
                self._rotate_from(file_id, epoch, plain, r["acl"])
            except Exception:  # noqa: BLE001  a lost race is fine; another device rotated
                pass
        return plain

    def rotate(self, file_id: str, acl: list[str] | None = None) -> dict[str, Any]:
        r = self.call("fetch", file_id=file_id)
        dek = self._unwrap(r["wrap"], file_id, r["epoch"])
        plain = c.aead_decrypt(dek, c.b64d(r["ciphertext"]), _file_aad(file_id, r["epoch"]))
        return self._rotate_from(file_id, r["epoch"], plain, acl or r["acl"], change_acl=acl is not None)

    def _rotate_from(self, file_id: str, epoch: int, plain: bytes, acl: list[str],
                     change_acl: bool = False) -> dict[str, Any]:
        new_epoch = epoch + 1
        dek = c.random_key()
        ct = c.aead_encrypt(dek, plain, _file_aad(file_id, new_epoch))
        wraps = self._wrap_for(dek, file_id, new_epoch, self._recipients(acl))
        args: dict[str, Any] = {"file_id": file_id, "expected_epoch": epoch,
                                "ciphertext": c.b64e(ct), "wraps": wraps}
        if change_acl:
            args["acl"] = acl
        return self.call("rotate", **args)
