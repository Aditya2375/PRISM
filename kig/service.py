"""The guard service: identity directory, access decisions, revocation, audit.

Zero-trust rules enforced on every request:

1. Every request is an envelope signed by a device key (ML-DSA-65). No bearer
   tokens, no sessions.
2. The signature, timestamp freshness and nonce uniqueness are checked first.
3. The device must be active, its user must be active, and the user must be
   allowed on the file. Every decision is written to the signed audit log.
4. The service never sees file keys. It stores ciphertext plus one wrapped key
   per eligible device. Revoking a device deletes its wraps immediately and
   flags affected files for rotation.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import crypto as c
from .audit import AuditError, AuditLog
from .detect import Alert, Detector

SKEW_S = 30
MAX_FILE_BYTES = 5 * 1024 * 1024
ROLES = ("admin", "member")
ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


class Denied(Exception):
    def __init__(self, code: str, reason: str, status: int = 403):
        super().__init__(reason)
        self.code, self.reason, self.status = code, reason, status


def _valid_id(x: Any) -> str:
    if not isinstance(x, str) or not (1 <= len(x) <= 64) or set(x) - ID_CHARS:
        raise Denied("bad_request", "invalid identifier", 400)
    return x


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class GuardService:
    def __init__(self, data_dir: str | Path, clock: Callable[[], float] = time.time):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._lock = threading.RLock()
        self._load_server_key()
        self.audit = AuditLog(self.dir / "audit.jsonl", self._sec, self.pub)
        self.state: dict[str, Any] = self._load_state()
        self._check_not_truncated()
        self.detector = Detector()
        self.locks: dict[str, float] = {}
        self.nonces: dict[str, float] = {}
        self._src = "local"
        self._lock_logged: set[str] = set()
        # Nonces are memory-only, so refuse anything signed before this process started.
        self.boot = self.clock()
        self._replay_detector()
        self._reconcile()

    # ------------------------------------------------------------ key + state

    def _load_server_key(self) -> None:
        sec_p, pub_p = self.dir / "server_sign.key", self.dir / "server_sign.pub"
        if sec_p.exists() and pub_p.exists():
            self._sec, self.pub = sec_p.read_bytes(), pub_p.read_bytes()
        else:
            self.pub, self._sec = c.sig_keygen()
            _atomic_write(sec_p, self._sec)
            _atomic_write(pub_p, self.pub, 0o644)

    def _load_state(self) -> dict[str, Any]:
        p = self.dir / "state.json"
        if p.exists():
            return json.loads(p.read_text())
        return {"users": {}, "devices": {}, "files": {}, "applied": 0}

    def _check_not_truncated(self) -> None:
        n = int(self.state.get("applied", 0))
        if n > len(self.audit.entries):
            raise AuditError(f"audit log truncated: state has seen {n} entries, log has {len(self.audit.entries)}")
        if n and self.audit.entries[n - 1]["hash"] != self.state.get("audit_head"):
            raise AuditError("audit log does not match the head recorded in state")

    def _persist(self) -> None:
        self.state["applied"] = len(self.audit.entries)
        self.state["audit_head"] = self.audit.head
        _atomic_write(self.dir / "state.json", json.dumps(self.state, sort_keys=True).encode())

    def _replay_detector(self) -> None:
        """Rebuild detector memory from the audit log after a restart."""
        for e in self.audit.entries:
            if e["type"] != "alert.raised":
                self.detector.observe(e)

    def _reconcile(self) -> None:
        """Fail closed after a crash between audit append and state write.

        Security-critical removals are re-applied from audit entries the state
        file has not yet seen. Anything else is simply not applied (the client
        never got a success response, so it will retry).
        """
        start = int(self.state.get("applied", 0))
        changed = False
        for e in self.audit.entries[start:]:
            d = e["data"]
            if e["type"] in ("device.revoked", "device.lost"):
                changed |= self._apply_remove_device(d["device"], e["type"].split(".")[1])
            elif e["type"] == "user.disabled":
                self.state["users"].get(d["user"], {})["active"] = False
                for dev in self._devices_of(d["user"]):
                    changed |= self._apply_remove_device(dev, "revoked")
                changed = True
            elif e["type"] == "alert.raised" and d.get("lock_key"):
                self.locks[d["lock_key"]] = d["lock_until"]
        if changed or start != len(self.audit.entries):
            self._persist()

    # ---------------------------------------------------------------- helpers

    def _log(self, etype: str, actor: str, data: dict[str, Any]) -> dict[str, Any]:
        entry = self.audit.append(self.clock(), etype, actor, data)
        if etype != "alert.raised":
            for a in self.detector.observe(entry):
                self._raise(a)
        return entry

    def _raise(self, a: Alert) -> None:
        data = a.as_data()
        if a.lock_key:
            self._lock_logged.discard(a.lock_key)
            if len(self.locks) > 4096:
                self.locks = {k: v for k, v in self.locks.items() if v > self.clock()}
            self.locks[a.lock_key] = a.lock_until
            data["lock_key"], data["lock_until"] = a.lock_key, a.lock_until
        self.audit.append(self.clock(), "alert.raised", "detector", data)

    def _devices_of(self, user: str) -> list[str]:
        return [d for d, v in self.state["devices"].items() if v["user"] == user]

    def eligible_devices(self, acl: list[str]) -> list[str]:
        out = []
        for d, v in self.state["devices"].items():
            u = self.state["users"].get(v["user"], {})
            if v["status"] == "active" and u.get("active") and v["user"] in acl:
                out.append(d)
        return sorted(out)

    def _apply_remove_device(self, device: str, kind: str) -> bool:
        dev = self.state["devices"].get(device)
        if not dev:
            return False
        changed = False
        status = "lost" if kind == "lost" else "revoked"
        if dev["status"] == "active":
            dev["status"] = status
            dev["removed_at"] = self.clock()
            changed = True
        for f in self.state["files"].values():
            if device in f["wraps"]:
                del f["wraps"][device]
                f["needs_rotation"] = True
                changed = True
        return changed

    # ---------------------------------------------------------- bootstrapping

    def bootstrap(self, user: str, device: str, sign_pub: bytes, kem_pub: bytes) -> None:
        """Create the first admin. Allowed exactly once, out of band (operator console)."""
        with self._lock:
            if self.state["users"]:
                raise Denied("already_bootstrapped", "service already has users", 409)
            user, device = _valid_id(user), _valid_id(device)
            self.state["users"][user] = {"role": "admin", "active": True}
            self.state["devices"][device] = {
                "user": user,
                "status": "active",
                "sign_pub": c.b64e(sign_pub),
                "kem_pub": c.b64e(kem_pub),
                "enrolled_at": self.clock(),
            }
            self._log("service.bootstrapped", "operator", {"user": user, "device": device})
            self._log("device.enrolled", "operator", {"user": user, "device": device})
            self._persist()

    # ------------------------------------------------------------ entry point

    def handle(self, env: dict[str, Any], source: str = "local") -> dict[str, Any]:
        """Process one signed envelope. Returns a JSON-able dict or raises Denied.

        ``source`` is the network origin (the API passes the client address).
        Lockouts are keyed by device AND source, so an attacker cannot lock a
        victim out by sending garbage that claims the victim's device id.
        """
        with self._lock:
            self._src = str(source)[:64]
            return self._handle(env)

    def _deny(self, etype: str, actor: str, data: dict[str, Any], code: str, reason: str) -> None:
        if etype.startswith("auth."):
            data = dict(data, source=self._src)
        self._log(etype, actor, data)
        raise Denied(code, reason)

    def _handle(self, env: dict[str, Any]) -> dict[str, Any]:
        try:
            cmd, dev_id = env["cmd"], env["device"]
            ts, nonce, args = env["ts"], env["nonce"], env["args"]
            sig = c.b64d(env["sig"])
            if not (isinstance(cmd, str) and isinstance(dev_id, str) and isinstance(nonce, str)):
                raise KeyError
            if (not isinstance(args, dict) or isinstance(ts, bool) or not isinstance(ts, (int, float))
                    or not math.isfinite(ts)):
                raise KeyError
            if len(nonce) > 64 or len(dev_id) > 64:
                raise KeyError
        except (KeyError, TypeError, c.CryptoError):
            raise Denied("bad_request", "malformed envelope", 400) from None

        now = self.clock()
        lkey = f"{dev_id[:64]}@{self._src}"
        if self.locks.get(lkey, 0) > now:
            if lkey not in self._lock_logged:  # one audit line per lock, so a flood cannot fill the disk
                self._lock_logged.add(lkey)
                self._log("auth.locked_out", "unknown", {"device": dev_id[:64], "cmd": cmd[:32], "source": self._src})
            raise Denied("locked", "identifier temporarily locked after repeated failures", 429)

        dev = self.state["devices"].get(dev_id)
        if dev is None:
            self._deny("auth.unknown_device", "unknown", {"device": dev_id[:64], "cmd": cmd[:32]},
                       "unauthorized", "unknown device")
        body = {k: env[k] for k in ("cmd", "device", "ts", "nonce", "args")}
        if not c.verify(c.b64d(dev["sign_pub"]), "cmd", c.canonical(body), sig):
            self._deny("auth.bad_signature", dev_id, {"device": dev_id, "cmd": cmd[:32]},
                       "unauthorized", "bad signature")
        if abs(now - ts) > SKEW_S or ts < self.boot:
            self._deny("auth.stale", dev_id, {"device": dev_id, "cmd": cmd, "skew": round(now - ts, 1)},
                       "stale", "timestamp outside the allowed window")
        self._prune_nonces(now)
        nkey = f"{dev_id}:{nonce}"
        if nkey in self.nonces:
            self._deny("auth.replay", dev_id, {"device": dev_id, "cmd": cmd}, "replay", "nonce already used")
        self.nonces[nkey] = now

        if dev["status"] != "active":
            self._deny("auth.revoked_device_use", dev_id,
                       {"device": dev_id, "cmd": cmd, "status": dev["status"], "user": dev["user"]},
                       "revoked", f"device is {dev['status']}")
        user = self.state["users"].get(dev["user"])
        if not user or not user["active"]:
            self._deny("auth.disabled_user", dev_id, {"device": dev_id, "user": dev["user"], "cmd": cmd},
                       "forbidden", "user is disabled")

        fn = getattr(self, f"cmd_{cmd}", None)
        if fn is None or cmd.startswith("_"):
            raise Denied("bad_request", "unknown command", 400)
        try:
            result = fn(dev_id, dev["user"], user["role"], args)
            self._persist()
        except Denied:
            raise  # commands validate before mutating, so a denial leaves state untouched
        except Exception:  # noqa: BLE001  never leave half-applied in-memory state
            self.state = self._load_state()
            raise Denied("internal", "internal error; no change was committed", 500) from None
        return result

    def _prune_nonces(self, now: float) -> None:
        if len(self.nonces) > 1024:
            cutoff = now - 2 * SKEW_S
            self.nonces = {k: v for k, v in self.nonces.items() if v >= cutoff}

    # --------------------------------------------------------------- commands

    def _require_admin(self, actor: str, role: str, what: str) -> None:
        if role != "admin":
            self._deny("authz.denied", actor, {"device": actor, "action": what, "why": "not admin"},
                       "forbidden", "admin role required")

    def cmd_whoami(self, dev, user, role, args):
        return {"user": user, "role": role, "device": dev}

    def cmd_eligible(self, dev, user, role, args):
        users = args.get("users")
        if not isinstance(users, list) or not users or len(users) > 64:
            raise Denied("bad_request", "users must be a non-empty list", 400)
        users = [_valid_id(u) for u in users]
        return {
            "devices": {
                d: self.state["devices"][d]["kem_pub"] for d in self.eligible_devices(users)
            }
        }

    def cmd_create_user(self, dev, user, role, args):
        self._require_admin(dev, role, "create_user")
        new, new_role = _valid_id(args.get("user")), args.get("role", "member")
        if new_role not in ROLES:
            raise Denied("bad_request", "bad role", 400)
        if new in self.state["users"]:
            raise Denied("conflict", "user exists", 409)
        self.state["users"][new] = {"role": new_role, "active": True}
        self._log("user.created", dev, {"user": new, "role": new_role, "by": user})
        if new_role == "admin":
            self._log("role.changed", dev, {"user": new, "old": None, "new": "admin", "by": user})
        return {"ok": True}

    def cmd_set_role(self, dev, user, role, args):
        self._require_admin(dev, role, "set_role")
        target, new_role = _valid_id(args.get("user")), args.get("role")
        if new_role not in ROLES or target not in self.state["users"]:
            raise Denied("bad_request", "bad user or role", 400)
        old = self.state["users"][target]["role"]
        if old == new_role:
            return {"ok": True, "unchanged": True}
        if old == "admin" and sum(
            1 for u in self.state["users"].values() if u["role"] == "admin" and u["active"]
        ) <= 1:
            raise Denied("conflict", "cannot demote the last admin", 409)
        self.state["users"][target]["role"] = new_role
        self._log("role.changed", dev, {"user": target, "old": old, "new": new_role, "by": user})
        return {"ok": True}

    def cmd_enroll_device(self, dev, user, role, args):
        self._require_admin(dev, role, "enroll_device")
        target, new_dev = _valid_id(args.get("user")), _valid_id(args.get("device"))
        try:
            sp, kp = c.b64d(args["sign_pub"]), c.b64d(args["kem_pub"])
        except (KeyError, c.CryptoError):
            raise Denied("bad_request", "missing keys", 400) from None
        if len(kp) != c.KEM_PQ_PUB + c.X_LEN or len(sp) != 1952:
            raise Denied("bad_request", "wrong key size", 400)
        if target not in self.state["users"] or not self.state["users"][target]["active"]:
            raise Denied("bad_request", "unknown or disabled user", 400)
        if new_dev in self.state["devices"]:
            raise Denied("conflict", "device id already used (ids are never reused)", 409)
        self.state["devices"][new_dev] = {
            "user": target, "status": "active", "sign_pub": c.b64e(sp), "kem_pub": c.b64e(kp),
            "enrolled_at": self.clock(),
        }
        self._log("device.enrolled", dev, {"user": target, "device": new_dev, "by": user})
        return {"ok": True}

    def _remove(self, dev, user, role, args, kind):
        target = _valid_id(args.get("device"))
        d = self.state["devices"].get(target)
        if d is None:
            raise Denied("bad_request", "unknown device", 400)
        if role != "admin" and d["user"] != user:
            self._deny("authz.denied", dev, {"device": dev, "action": kind, "target": target},
                       "forbidden", "only the owner or an admin may do this")
        if d["status"] != "active":
            return {"ok": True, "already": d["status"]}
        self._apply_remove_device(target, kind)
        pending = sorted(k for k, f in self.state["files"].items() if f["needs_rotation"])
        self._log(f"device.{'lost' if kind == 'lost' else 'revoked'}", dev,
                  {"device": target, "user": d["user"], "by": user,
                   "reason": str(args.get("reason", ""))[:200], "files_needing_rotation": pending})
        return {"ok": True, "files_needing_rotation": pending}

    def cmd_revoke_device(self, dev, user, role, args):
        return self._remove(dev, user, role, args, "revoked")

    def cmd_report_lost(self, dev, user, role, args):
        return self._remove(dev, user, role, args, "lost")

    def cmd_disable_user(self, dev, user, role, args):
        self._require_admin(dev, role, "disable_user")
        target = _valid_id(args.get("user"))
        u = self.state["users"].get(target)
        if not u:
            raise Denied("bad_request", "unknown user", 400)
        if target == user:
            raise Denied("conflict", "cannot disable yourself", 409)
        u["active"] = False
        for d in self._devices_of(target):
            self._apply_remove_device(d, "revoked")
        self._log("user.disabled", dev, {"user": target, "by": user})
        return {"ok": True}

    # files ------------------------------------------------------------------

    def _check_blob(self, ct_b64: Any) -> str:
        if not isinstance(ct_b64, str) or len(ct_b64) > MAX_FILE_BYTES * 4 // 3 + 64:
            raise Denied("bad_request", "ciphertext missing or too large", 400)
        c.b64d(ct_b64)
        return ct_b64

    def _check_wraps(self, wraps: Any, acl: list[str]) -> dict[str, Any]:
        want = set(self.eligible_devices(acl))
        if not isinstance(wraps, dict) or set(wraps) != want:
            raise Denied("conflict", f"wraps must cover exactly the eligible devices: {sorted(want)}", 409)
        for w in wraps.values():
            if not (isinstance(w, dict) and isinstance(w.get("ct"), str) and isinstance(w.get("blob"), str)):
                raise Denied("bad_request", "malformed wrap", 400)
            c.b64d(w["ct"]), c.b64d(w["blob"])
        return wraps

    def _acl(self, args: dict[str, Any], actor_user: str) -> list[str]:
        acl = args.get("acl")
        if not isinstance(acl, list) or not acl or len(acl) > 64:
            raise Denied("bad_request", "acl must be a non-empty list", 400)
        acl = sorted({_valid_id(u) for u in acl})
        for u in acl:
            if u not in self.state["users"] or not self.state["users"][u]["active"]:
                raise Denied("bad_request", f"unknown or disabled user {u}", 400)
        return acl

    def cmd_put_file(self, dev, user, role, args):
        fid = _valid_id(args.get("file_id"))
        if fid in self.state["files"]:
            raise Denied("conflict", "file exists; use rotate", 409)
        acl = self._acl(args, user)
        if user not in acl:
            raise Denied("bad_request", "creator must be in acl", 400)
        ct = self._check_blob(args.get("ciphertext"))
        wraps = self._check_wraps(args.get("wraps"), acl)
        self.state["files"][fid] = {
            "owner": user, "acl": acl, "epoch": 1, "ciphertext": ct,
            "wraps": wraps, "needs_rotation": False,
        }
        self._log("file.created", dev, {"file": fid, "owner": user, "acl": acl, "epoch": 1})
        return {"ok": True, "epoch": 1}

    def _file_for(self, dev, user, role, fid: str, action: str) -> dict[str, Any]:
        f = self.state["files"].get(fid)
        if f is None:
            raise Denied("not_found", "no such file", 404)
        if user not in f["acl"]:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid,
                                              "action": action, "why": "user not in acl"},
                       "forbidden", "not permitted on this file")
        return f

    def cmd_fetch(self, dev, user, role, args):
        fid = _valid_id(args.get("file_id"))
        f = self._file_for(dev, user, role, fid, "fetch")
        wrap = f["wraps"].get(dev)
        if wrap is None:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid,
                                              "action": "fetch", "why": "no key wrapped for this device"},
                       "forbidden", "no key available for this device")
        self._log("access.granted", dev, {"device": dev, "user": user, "file": fid, "epoch": f["epoch"]})
        return {"file_id": fid, "epoch": f["epoch"], "ciphertext": f["ciphertext"], "wrap": wrap,
                "acl": f["acl"], "needs_rotation": f["needs_rotation"]}

    def cmd_rotate(self, dev, user, role, args):
        fid = _valid_id(args.get("file_id"))
        f = self._file_for(dev, user, role, fid, "rotate")
        if dev not in f["wraps"]:
            self._deny("access.denied", dev, {"device": dev, "file": fid, "action": "rotate",
                                              "why": "no key wrapped for this device"},
                       "forbidden", "no key available for this device")
        ep = args.get("expected_epoch")
        if isinstance(ep, bool) or ep != f["epoch"]:
            raise Denied("conflict", f"epoch changed, now {f['epoch']}; re-fetch and retry", 409)
        acl = f["acl"]
        if "acl" in args:
            if role != "admin" and f["owner"] != user:
                self._deny("authz.denied", dev, {"device": dev, "file": fid, "action": "change_acl"},
                           "forbidden", "only the owner or an admin may change the acl")
            acl = self._acl(args, user)
            if f["owner"] not in acl and role != "admin":
                raise Denied("bad_request", "owner must stay in acl", 400)
        ct = self._check_blob(args.get("ciphertext"))
        wraps = self._check_wraps(args.get("wraps"), acl)
        old_acl = f["acl"]
        f.update(acl=acl, ciphertext=ct, wraps=wraps, epoch=f["epoch"] + 1, needs_rotation=False)
        self._log("file.rotated", dev, {"file": fid, "epoch": f["epoch"], "by": user,
                                        "acl_changed": acl != old_acl})
        return {"ok": True, "epoch": f["epoch"]}

    def cmd_list_files(self, dev, user, role, args):
        return {"files": [
            {"file_id": k, "epoch": f["epoch"], "needs_rotation": f["needs_rotation"]}
            for k, f in sorted(self.state["files"].items()) if user in f["acl"]
        ]}

    # ------------------------------------------------------------ read models

    def alerts(self) -> list[dict[str, Any]]:
        return [dict(e["data"], seq=e["seq"], ts=e["ts"]) for e in self.audit.entries
                if e["type"] == "alert.raised"]

    def overview(self) -> dict[str, Any]:
        s = self.state
        return {
            "users": {u: dict(v) for u, v in s["users"].items()},
            "devices": {d: {k: v for k, v in dv.items() if k not in ("sign_pub", "kem_pub")}
                        for d, dv in s["devices"].items()},
            "files": {k: {"epoch": f["epoch"], "acl": f["acl"], "needs_rotation": f["needs_rotation"],
                          "wrapped_devices": sorted(f["wraps"])} for k, f in s["files"].items()},
            "audit_head": self.audit.head,
            "audit_len": len(self.audit.entries),
        }
