"""Device-side client. Holds the device's private keys and does all file crypto.

The service only ever receives ciphertext, wrapped keys and signed requests.
"""
from __future__ import annotations

import hmac as _hmac
import json
import os
import re
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


def manifest_msg(file_id: str, epoch: int, acl: list[str], owner: str, commit: str, writer: str,
                 writer_user: str = "") -> bytes:
    """What a writing device signs for each file version: id, version, ACL, owner, key commitment and itself."""
    return c.canonical({"file": file_id, "epoch": epoch, "acl": sorted(acl), "owner": owner,
                        "commit": commit, "writer": writer, "writer_user": writer_user})


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
                 audience: str = "primary", state_path: str | Path | None = None,
                 roots: list[str] | None = None, tofu_root: bool = True, verify_directory: bool = True):
        """``roots``: fingerprints of the device(s) every enrolment must trace back to (the first admin's device, and
        any device an operator added by offline recovery). Without it, the roots behind this device's own enrolment
        are pinned on first use (trust on first use) and checked on every later call. ``verify_directory=False``
        turns the check off; only tests do that."""
        self.verify_directory = verify_directory
        self._roots: list[str] | None = list(roots) if roots else None
        self.tofu_root = tofu_root
        self._admin_users: set[str] = set()                   # users shown to be admins (cache)
        self._neg_dir: Any = None                              # directory the negative memo belongs to
        self._neg: set[tuple[str, frozenset]] = set()
        self._trusted: dict[str, tuple[str, str, str]] = {}   # device -> (user, sign_pub, kem_pub) proven to the root
        self.dev, self.send, self.clock, self.aud = device, transport, clock, audience
        self.state_path = Path(state_path) if state_path else None
        self.seen_epoch: dict[str, int] = {}   # newest key version this client has seen per file
        self.rotation_errors: list[str] = []   # auto-rotation failures other than a lost race
        self.pins: dict[str, Any] = {"signers": {}, "owners": {}, "writers": {}, "writer_users": {}, "admins": {}, "roots": []}   # first-seen signer keys and file owners
        if self.state_path and Path(str(self.state_path) + ".pins").exists():
            try:
                self.pins = json.loads(Path(str(self.state_path) + ".pins").read_text())
                self.pins.setdefault("writers", {}); self.pins.setdefault("writer_users", {}); self.pins.setdefault("admins", {}); self.pins.setdefault("roots", []); self.pins["signers"], self.pins["owners"]
            except (ValueError, OSError, TypeError, KeyError):
                raise c.CryptoError("client pin file is damaged; refusing to start without it") from None
        if self._roots and set(self.pins.get("roots", [])) - set(self._roots):
            import sys
            print("warning: this device has pinned roots that the given --root-fingerprint / KIG_ROOT_FINGERPRINTS do not list; "
                  "only the given ones are used (kig unpin-root removes the stale pin)", file=sys.stderr)
        if self.state_path and self.state_path.exists():
            try:
                self.seen_epoch = {k: int(v) for k, v in json.loads(self.state_path.read_text()).items()}
            except (ValueError, OSError, TypeError):
                raise c.CryptoError("client state file is damaged; refusing to start without its rollback record") from None

    def _save_pins(self) -> None:
        if self.state_path:
            vault.write_atomic(Path(str(self.state_path) + ".pins"), json.dumps(self.pins, sort_keys=True).encode())

    def _verify_manifest(self, file_id: str, r: dict[str, Any]) -> None:
        """Check the writer's signature over this version's id, epoch, ACL, owner and key commitment.

        The signer's key and the file's owner are pinned the first time they are seen (trust on first use, with
        the enrolment fingerprint as the out-of-band check for the key). After that the service cannot change
        the ACL, the owner or the key commitment of a version without a device's signature.
        """
        m = r.get("manifest")
        if not isinstance(m, dict) or not all(isinstance(m.get(k), str) for k in ("writer", "writer_sign_pub", "sig")):
            raise c.CryptoError("no signed manifest for this version")
        owner = r.get("owner")
        if not isinstance(owner, str) or not isinstance(r.get("acl"), list):
            raise c.CryptoError("response lacks owner or acl")
        pinned = self.pins["signers"].get(m["writer"])
        if pinned is not None and pinned != m["writer_sign_pub"]:
            raise c.CryptoError(f"signing key of device {m['writer']} differs from the one pinned earlier")
        pinned_owner = self.pins["owners"].get(file_id)
        if pinned_owner is not None and pinned_owner != owner:
            raise c.CryptoError("file owner differs from the one pinned earlier")
        wuser = m.get("writer_user")
        if not isinstance(wuser, str):
            raise c.CryptoError("manifest lacks the writer's user")
        msg = manifest_msg(file_id, r["epoch"], r["acl"], owner, r.get("commit", ""), m["writer"], wuser)
        if not c.verify(c.b64d(m["writer_sign_pub"]), "manifest", msg, c.b64d(m["sig"])):
            raise c.CryptoError("manifest signature invalid: acl, owner or version were changed")
        writers = self.pins["writers"].get(file_id, {})
        if not writers and self.verify_directory:
            # first sight of this file: the writer must trace back to the pinned root, or the server could invent a file
            self._ensure_roots()
            if self._root_list():
                dirm = self._directory([m["writer"]])
                u, sp, _ = self._prove(m["writer"], dirm)
                if u != wuser or sp != m["writer_sign_pub"]:
                    raise c.CryptoError("the file's writer does not match its signed enrolment")
        if writers:
            self._check_writer_authority(file_id, m, writers, wuser, owner)
        if writers and m["writer"] not in writers:
            self._check_enrollment(m, writers, wuser)       # a writer never seen for this file needs a proof
        elif m["writer"] in writers and writers[m["writer"]] != m["writer_sign_pub"]:
            raise c.CryptoError(f"signing key of {m['writer']} for this file differs from the one pinned earlier")
        if pinned is None or pinned_owner is None or m["writer"] not in writers:
            self.pins["signers"][m["writer"]] = m["writer_sign_pub"]
            self.pins["owners"][file_id] = owner
            self.pins["writers"].setdefault(file_id, {})[m["writer"]] = m["writer_sign_pub"]
            self.pins["writer_users"].setdefault(file_id, {})[m["writer"]] = wuser
            if not writers:
                self.pins["admins"].setdefault(file_id, [])        # the first writer is the owner (TOFU)
            self._save_pins()

    def _check_writer_authority(self, file_id: str, m: dict[str, Any], writers: dict[str, str], wuser: str,
                                owner: str) -> None:
        """Only the file's owner, or an admin proven by a chain of signed requests, may write a version.

        An admin is proven by the `create_user` / `set_role` request (role admin) that the owner, or an admin
        already proven for this file, signed with a device pinned as a writer of this file.
        """
        if wuser == owner or wuser in self.pins["admins"].get(file_id, []):
            return
        env = m.get("role_proof")
        users = self.pins["writer_users"].get(file_id, {})
        try:
            body = {k: env[k] for k in ("cmd", "device", "ts", "nonce", "args") + (("aud",) if "aud" in env else ())}
            signer_user = users.get(body["device"])
            ok = (body["cmd"] in ("create_user", "set_role") and body["args"]["user"] == wuser
                  and body["args"].get("role") == "admin" and body["device"] in writers
                  and (signer_user == owner or signer_user in self.pins["admins"].get(file_id, []))
                  and c.verify(c.b64d(writers[body["device"]]), "cmd", c.canonical(body), c.b64d(env["sig"])))
        except (KeyError, TypeError, ValueError, c.CryptoError):
            ok = False
        if not ok:
            raise c.CryptoError(f"writer user {wuser} is neither the file's owner nor an admin proven by a pinned "
                                "owner or admin")
        self.pins["admins"].setdefault(file_id, []).append(wuser)

    @staticmethod
    def _check_enrollment(m: dict[str, Any], writers: dict[str, str], wuser: str) -> None:
        """A new writer for a file is accepted only with the enrolment request signed by a device already pinned
        as a writer of this file (only the owner or an admin can write, and only an admin can enrol)."""
        env = m.get("enrollment")
        try:
            body = {k: env[k] for k in ("cmd", "device", "ts", "nonce", "args") + (("aud",) if "aud" in env else ())}
            ok = (body["cmd"] == "enroll_device" and body["device"] in writers
                  and body["args"]["device"] == m["writer"] and body["args"]["sign_pub"] == m["writer_sign_pub"]
                  and body["args"]["user"] == wuser
                  and c.verify(c.b64d(writers[body["device"]]), "cmd", c.canonical(body), c.b64d(env["sig"])))
        except (KeyError, TypeError, ValueError, c.CryptoError):
            ok = False
        if not ok:
            raise c.CryptoError(f"writer {m['writer']} was never pinned for this file and carries no valid enrolment "
                                "signed by a pinned writer")

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

    # -- root of trust ---------------------------------------------------------
    def _root_list(self) -> list[str]:
        if self._roots:
            # roots given by flag or environment are the operator's word and are used ALONE; a root that was pinned
            # earlier (for example from a hostile first contact) cannot ride along
            return list(self._roots)
        return list(self.pins.get("roots", []))

    def add_root(self, fingerprint: str) -> None:
        """Pin one more root device (for example the device an operator enrolled by offline recovery). The fingerprint
        must come from the operator out of band, never from the server."""
        fp = fingerprint.strip().lower()
        if not 20 <= len(fp) <= 128 or not all(ch in "0123456789abcdef-" for ch in fp):
            raise c.CryptoError("that does not look like a device fingerprint")
        roots = self.pins.setdefault("roots", [])
        if fp not in roots:
            roots.append(fp)
            self._save_pins()
        self._trusted.clear(); self._admin_users.clear(); self._neg_dir = None

    def remove_root(self, fingerprint: str) -> None:
        """Forget one pinned root (for example one pinned from a hostile first contact). Local trust record only."""
        fp = fingerprint.strip().lower()
        roots = self.pins.setdefault("roots", [])
        if fp not in roots:
            raise c.CryptoError("that fingerprint is not pinned here")
        roots.remove(fp)
        self._save_pins()
        self._trusted.clear(); self._admin_users.clear(); self._neg_dir = None

    @staticmethod
    def _env_body(env: dict[str, Any]) -> dict[str, Any]:
        return {k: env[k] for k in ("cmd", "device", "ts", "nonce", "args") + (("aud",) if "aud" in env else ())}

    def _is_admin(self, user: str, dirm: dict[str, Any], depth: int, busy: frozenset) -> bool:
        """A user is an admin if a pinned root device belongs to them, or if a `create_user` / `set_role` request for
        them (role admin) is signed by a device of a user who is an admin (the directory carries that request)."""
        if user in self._admin_users:
            return True
        if depth > 16 or user in busy:
            return False
        # a user shown NOT to be an admin in this very directory is not searched for again (an attacker could otherwise
        # make every check re-walk the same long chains); the memo is dropped with the directory or the roots
        if self._neg_dir is not dirm:
            self._neg_dir, self._neg = dirm, set()
        if (user, busy) in self._neg:
            return False
        r = self._is_admin_walk(user, dirm, depth, busy)
        if not r:
            self._neg.add((user, busy))
        return r

    def _is_admin_walk(self, user: str, dirm: dict[str, Any], depth: int, busy: frozenset) -> bool:
        for did, e in dirm.items():
            if not isinstance(e, dict) or e.get("user") != user:
                continue
            try:
                fp = device_fingerprint(did, user, c.b64d(e["sign_pub"]), c.b64d(e["kem_pub"]))
            except (KeyError, TypeError, c.CryptoError):
                continue
            if e.get("proof") is None and fp in self._root_list():
                self._admin_users.add(user)
                return True
        for did, e in dirm.items():
            if not isinstance(e, dict) or e.get("user") != user:
                continue
            env = e.get("role_proof")
            try:
                body = self._env_body(env)
                signer = body["device"]
                if not (body["cmd"] in ("create_user", "set_role") and body["args"]["user"] == user
                        and body["args"].get("role") == "admin" and signer != did):
                    continue
                suser, ssp, _ = self._prove(signer, dirm, depth + 1, busy | {user})
                if self._limited(dirm, signer):
                    continue
                if self._is_admin(suser, dirm, depth + 1, busy | {user}) and \
                        c.verify(c.b64d(ssp), "cmd", c.canonical(body), c.b64d(env["sig"])):
                    self._admin_users.add(user)
                    return True
            except (KeyError, TypeError, ValueError, c.CryptoError):
                continue
        return False

    @staticmethod
    def _limited(dirm: dict[str, Any], dev_id: str) -> bool:
        """True when the device's own signed enrolment says it is a limited device (no admin power). The signature on that
        record has been checked by _prove before this is asked."""
        e = dirm.get(dev_id)
        p = e.get("proof") if isinstance(e, dict) else None
        args = None
        try:
            args = p["args"] if isinstance(p, dict) else None
        except KeyError:
            pass
        return isinstance(args, dict) and args.get("limited") is True

    def _prove(self, dev_id: str, dirm: dict[str, Any], depth: int = 0, busy: frozenset = frozenset()) -> tuple[str, str, str]:
        """Return (user, sign_pub, kem_pub) of a device if its enrolment chain ends at a pinned root and every signer
        in it was an admin, else raise."""
        if dev_id in self._trusted:
            return self._trusted[dev_id]
        if depth > 16:
            raise c.CryptoError("enrolment chain too long")
        info = dirm.get(dev_id)
        try:
            user, sp, kp, proof = info["user"], info["sign_pub"], info["kem_pub"], info.get("proof")
            fp = device_fingerprint(dev_id, user, c.b64d(sp), c.b64d(kp))
        except (KeyError, TypeError, c.CryptoError):
            raise c.CryptoError(f"the directory has no valid entry for device {dev_id}") from None
        if proof is None:
            if fp not in self._root_list():
                raise c.CryptoError(f"device {dev_id} is not enrolled by anyone and is not a pinned root (fingerprint {fp})")
        else:
            try:
                body = self._env_body(proof)
                signer = body["device"]
                ok = (body["cmd"] == "enroll_device" and body["args"]["device"] == dev_id and body["args"]["user"] == user
                      and body["args"]["sign_pub"] == sp and body["args"]["kem_pub"] == kp and signer != dev_id)
            except (KeyError, TypeError):
                ok = False
            if not ok:
                raise c.CryptoError(f"the enrolment record for device {dev_id} does not match its keys")
            suser, ssp, _ = self._prove(signer, dirm, depth + 1, busy)
            if self._limited(dirm, signer):
                raise c.CryptoError(f"the enrolment of device {dev_id} was signed by a limited device, which has no admin power")
            if not self._is_admin(suser, dirm, depth + 1, busy):
                raise c.CryptoError(f"the enrolment of device {dev_id} was signed by a device of {suser}, who is not "
                                    "shown to be an admin")
            if not c.verify(c.b64d(ssp), "cmd", c.canonical(body), c.b64d(proof["sig"])):
                raise c.CryptoError(f"the enrolment of device {dev_id} is not signed by a device the root vouches for")
        self._trusted[dev_id] = (user, sp, kp)
        return user, sp, kp

    def _directory(self, ids: list[str]) -> dict[str, Any]:
        r = self.call("directory", devices=sorted(set(ids)))
        d = r.get("devices") if isinstance(r, dict) else None
        if not isinstance(d, dict):
            raise c.CryptoError("the directory reply is unreadable")
        return d

    def _ensure_roots(self) -> None:
        if self._root_list() or not self.tofu_root:
            return
        # first use: find the root(s) behind our own enrolment and pin them (trust on first use)
        dirm = self._directory([self.dev.device_id])
        me = dirm.get(self.dev.device_id)
        if not me or me.get("sign_pub") != c.b64e(self.dev.sign_pub) or me.get("kem_pub") != c.b64e(self.dev.kem_pub):
            raise c.CryptoError("the directory does not list this device with its own keys")
        roots, seen, cur = [], set(), self.dev.device_id
        while cur in dirm and cur not in seen:
            seen.add(cur)
            e = dirm[cur]
            if e.get("proof") is None:
                roots.append(device_fingerprint(cur, e["user"], c.b64d(e["sign_pub"]), c.b64d(e["kem_pub"])))
                break
            cur = e["proof"].get("device")
        if not roots:
            raise c.CryptoError("could not find the root behind this device's enrolment")
        self.pins["roots"] = roots                     # tentative: our own chain must verify against it
        self._trusted.clear(); self._admin_users.clear(); self._neg_dir = None
        try:
            self._prove(self.dev.device_id, dirm)
        except c.CryptoError:
            self.pins["roots"] = []
            raise
        self._save_pins()

    def _check_devices(self, devs: dict[str, str], acl: list[str] | None = None) -> None:
        """Every recipient key must belong to a device the root vouches for, and, when the ACL is given, to a user on it."""
        if not self.verify_directory:
            return
        self._ensure_roots()
        if not self._root_list():
            return
        need = [d for d in devs if d != self.dev.device_id and d not in self._trusted]
        if need:
            dirm = self._directory(need)
        for d, kem in devs.items():
            if d == self.dev.device_id:
                if kem != c.b64e(self.dev.kem_pub):
                    raise c.CryptoError("the server listed a different key for this device")
                continue
            duser, _, kp = self._prove(d, dirm) if d not in self._trusted else self._trusted[d]
            if acl is not None and duser not in acl:
                raise c.CryptoError(f"the server listed device {d} of user {duser}, who is not on the file's access list")
            if kp != kem:
                raise c.CryptoError(f"the key listed for device {d} differs from the one in its signed enrolment")

    def _recipients(self, acl: list[str]) -> dict[str, str]:
        devs = self.call("eligible", users=acl)["devices"]
        self._check_devices(devs, acl)
        return devs

    # -- file operations -------------------------------------------------------
    def put_file(self, file_id: str, plaintext: bytes, acl: list[str] | None = None, _epoch: int = 1) -> dict[str, Any]:
        acl = sorted(set(acl or []) | {self.dev.user})
        dek = c.random_key()
        ct = c.aead_encrypt(dek, plaintext, _file_aad(file_id, _epoch))
        wraps = self._wrap_for(dek, file_id, _epoch, self._recipients(acl))
        commit = _commit(dek, file_id, _epoch)
        sig = c.sign(self.dev.sign_sec, "manifest",
                     manifest_msg(file_id, _epoch, acl, self.dev.user, commit, self.dev.device_id, self.dev.user))
        extra = {"epoch": _epoch} if _epoch != 1 else {}
        self._note_epoch(file_id, _epoch)
        try:
            r = self.call("put_file", file_id=file_id, acl=acl, ciphertext=c.b64e(ct), wraps=wraps,
                          commit=commit, manifest_sig=c.b64e(sig), **extra)
        except Exception as e:
            if not hasattr(e, "code"):
                raise
            # a deleted id comes back at the next epoch, so readers that saw the old file do not call it a rollback
            m = re.search(r"next_epoch=(\d+)", e.reason or "") if e.code == "tombstoned" and _epoch == 1 else None
            if m and 1 < int(m.group(1)) <= 1_000_000:
                return self.put_file(file_id, plaintext, acl, _epoch=int(m.group(1)))
            raise
        return r

    def _open(self, file_id: str, r: dict[str, Any]) -> bytes:
        epoch = r["epoch"]
        self._verify_manifest(file_id, r)
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
                self._rotate_from(file_id, got, plain, r["acl"], owner=r["owner"])
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", "") != "conflict":     # a lost race is fine; anything else is surfaced
                    self.rotation_errors.append(f"{file_id}: {getattr(exc, 'code', type(exc).__name__)}: {exc}")
        return plain

    def rotate(self, file_id: str, acl: list[str] | None = None) -> dict[str, Any]:
        r = self.call("fetch", file_id=file_id)
        if r["epoch"] < self.seen_epoch.get(file_id, 0):
            raise c.CryptoError(f"rollback detected: server offered version {r['epoch']}, already saw {self.seen_epoch[file_id]}")
        plain = self._open(file_id, r)
        return self._rotate_from(file_id, r["epoch"], plain, acl or r["acl"], change_acl=acl is not None,
                                 owner=r["owner"])

    def _rotate_from(self, file_id: str, epoch: int, plain: bytes, acl: list[str],
                     change_acl: bool = False, owner: str = "") -> dict[str, Any]:
        new_epoch = epoch + 1
        dek = c.random_key()
        ct = c.aead_encrypt(dek, plain, _file_aad(file_id, new_epoch))
        wraps = self._wrap_for(dek, file_id, new_epoch, self._recipients(acl))
        commit = _commit(dek, file_id, new_epoch)
        sig = c.sign(self.dev.sign_sec, "manifest",
                     manifest_msg(file_id, new_epoch, acl, owner, commit, self.dev.device_id, self.dev.user))
        args: dict[str, Any] = {"file_id": file_id, "expected_epoch": epoch, "commit": commit,
                                "ciphertext": c.b64e(ct), "wraps": wraps, "manifest_sig": c.b64e(sig)}
        if change_acl:
            args["acl"] = acl
        res = self.call("rotate", **args)
        self._note_epoch(file_id, new_epoch)
        return res
