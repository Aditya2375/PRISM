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
from . import vault
from .audit import AuditError, AuditLog
from .detect import Alert, Detector
from .store import StateStore, StoreCorrupt

SKEW_S = 30
GRACE_S = 30  # rotation cutoff: the previous key version stays readable this long for in-flight transfers
MAX_FILE_BYTES = 5 * 1024 * 1024
READ_ONLY_CMDS = {"fetch", "whoami", "eligible", "list_files"}
MAX_FILES = 10_000                 # per service, bounds state size and write cost
DEVICE_RATE_PER_MIN = 240          # authenticated requests per device per minute
SOURCE_FAIL_PER_MIN = 1200         # failed (unauthenticated) requests per source address per minute
UNAUTH_LOG_PER_SOURCE_MIN = 3      # signed audit lines for unauthenticated failures, per source per minute
UNAUTH_LOG_TOTAL_MIN = 30          # ... and in total per minute; the rest are counted and summarised
POST_AUTH_EXTRA_LOG_MIN = 300      # after a valid signature: the first line per device+class is always logged, extras share this
STATE_CHANGING_TYPES = {"user.created", "role.changed", "device.enrolled", "file.created", "file.rotate_prepared",
                       "file.rotated", "device.revoked", "device.lost", "user.disabled", "service.bootstrapped"}
MUTATING_TYPES = {"user.created", "role.changed", "device.enrolled", "file.created", "service.bootstrapped"}
ROLES = ("admin", "member")
ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


class SimulatedCrash(BaseException):
    """Raised by fault-injection hooks in tests and the red-team harness to model a process kill."""


class StateCorrupt(Exception):
    """state.json is unreadable or failed its integrity signature; restore from a verified backup."""


class Denied(Exception):
    def __init__(self, code: str, reason: str, status: int = 403):
        super().__init__(reason)
        self.code, self.reason, self.status = code, reason, status


def _valid_id(x: Any) -> str:
    if not isinstance(x, str) or not (1 <= len(x) <= 64) or set(x) - ID_CHARS:
        raise Denied("bad_request", "invalid identifier", 400)
    return x


def _atomic_write(path: Path, data: bytes, mode: int = 0o600, hook: Callable[[], None] | None = None) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    if hook:
        hook()
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _fp_equal(a: Any, b: str) -> bool:
    """Compare fingerprints typed by a person: ignore case, dashes and spaces."""
    norm = lambda x: "".join(ch for ch in str(x).lower() if ch not in "- \t")  # noqa: E731
    return hmac_compare(norm(a), norm(b))


def hmac_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


class GuardService:
    def __init__(self, data_dir: str | Path, clock: Callable[[], float] = time.time,
                 name: str = "primary", read_only: bool = False, lease_s: float | None = None):
        self.name = name
        self.lease_s = lease_s                     # replicas: refuse everything if not confirmed fresh this recently
        self.last_sync: float | None = None        # when this replica last confirmed it is current with the primary
        self._cert_cache: dict[int, list[dict[str, Any]]] = {}
        self.read_only = read_only
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.clock = clock
        self._lock = threading.RLock()
        self.crash_at: str | None = None  # fault injection: name of a crash point
        self._load_server_key()
        self.revoked: set[str] = self._load_revoked()
        self.audit = AuditLog(self.dir / "audit.jsonl", self._sec, self.pub)
        self._fresh = False
        self.store = StateStore(self.dir, self._sec, self.pub, self._crash)
        self.state: dict[str, Any] = self._load_state()
        self._check_not_truncated()
        self._check_journal_not_behind_audit()
        self.detector = Detector()
        self.locks: dict[str, float] = {}  # kept for alert bookkeeping; authentication is never blocked by it
        rep_state = self.state.get("_replica", {})
        # replica bookkeeping is persisted inside the signed state so a restart cannot be used to roll it back
        self.epoch_floor: dict[str, tuple[int, float]] = {k: (v[0], v[1]) for k, v in rep_state.get("epoch_floor", {}).items()}
        self.snapshot_version: int = int(rep_state.get("snapshot_version", -1))
        self.snapshot_generation: int = int(rep_state.get("snapshot_generation", 0))
        self.nonces: dict[str, tuple[float, str, str]] = {}   # nonce key -> (first seen, source, body hash)
        self._src = "local"
        self._ua_minute = -1
        self._ua_src: dict[str, int] = {}
        self._ua_total = 0
        self._ua_post = 0
        self._ua_suppressed = 0
        self._rate: dict[str, tuple[int, int]] = {}
        # Nonces are memory-only, so refuse anything signed before this process started.
        self.boot = self.clock()
        self._replay_detector()
        self._reconcile()
        self._recover_rotations()
        self._enforce_revoked()
        if not self._fresh:
            self._gc_blobs()               # only after a verified state load; never from an empty start
        if self.audit.recovered_torn_bytes:
            self._log("service.recovered", "service", {"dropped_torn_bytes": self.audit.recovered_torn_bytes})
            self._persist()

    # ------------------------------------------------------------ key + state

    def _recover_rotations(self) -> None:
        """Close any prepare record that has no commit. State is the single source of truth."""
        open_: dict[tuple[str, int], dict[str, Any]] = {}
        for e in self.audit.entries:
            d = e["data"]
            if e["type"] == "file.rotate_prepared":
                open_[(d["file"], d["to_epoch"])] = d
            elif e["type"] in ("file.rotated", "file.rotate_recovered", "file.rotate_aborted"):
                open_.pop((d["file"], d["epoch"] if "epoch" in d else d.get("to_epoch")), None)
        for (fid, to), d in sorted(open_.items()):
            cur = self.state["files"].get(fid, {}).get("epoch")
            kind = "file.rotate_recovered" if cur == to else "file.rotate_aborted"
            self._log(kind, "service", {"file": fid, "to_epoch": to, "active_epoch": cur})
            self._persist()

    def _load_server_key(self) -> None:
        sec_p, pub_p = self.dir / "server_sign.key", self.dir / "server_sign.pub"
        pw = vault.passphrase_from_env()
        if sec_p.exists() and pub_p.exists():
            raw = sec_p.read_bytes()
            self._sec = vault.open_(raw, pw, "prism/server-key") if vault.is_sealed(raw) else raw
            self.pub = pub_p.read_bytes()
        elif sec_p.exists() or pub_p.exists():
            raise StateCorrupt("exactly one of server_sign.key / server_sign.pub exists; refusing to generate a new "
                               "signing key over it. Restore the missing file or restore from a verified backup")
        else:
            self.pub, self._sec = c.sig_keygen()
            _atomic_write(sec_p, vault.seal(self._sec, pw, "prism/server-key") if pw else self._sec)
            _atomic_write(pub_p, self.pub, 0o644)

    def _crash(self, point: str) -> None:
        if self.crash_at == point:
            raise SimulatedCrash(point)

    def _load_revoked(self) -> set[str]:
        """The revoked set lives in its own append-only file, written and fsynced first.

        Even if state.json is lost or rolled back, a revocation that was acknowledged
        cannot be forgotten, and the set is checked before anything else.
        """
        p = self.dir / "revoked.log"
        out: set[str] = set()
        if p.exists():
            raw = p.read_bytes()
            good = raw.rfind(b"\n") + 1
            if good != len(raw):
                # torn tail from a crash mid-append (never acknowledged): cut it off so the
                # next record cannot be glued onto it
                with open(p, "r+b") as fh:
                    fh.truncate(good)
                    fh.flush()
                    os.fsync(fh.fileno())
            for line in raw[:good].decode("utf-8", "replace").split("\n"):
                if line.strip():
                    out.add(line.strip().split("\t")[0])
        return out

    def _record_revoked(self, devices: list[str]) -> None:
        new = [d for d in devices if d not in self.revoked]
        if not new:
            return
        p = self.dir / "revoked.log"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            for d in new:
                fh.write(f"{d}\t{self.clock():.3f}\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.revoked.update(new)
        self._crash("after_revoked_journal")

    def _enforce_revoked(self) -> None:
        changed = False
        for d in self.revoked:
            dev = self.state["devices"].get(d)
            if dev and (dev["status"] == "active" or any(d in f["wraps"] for f in self.state["files"].values())):
                changed |= self._apply_remove_device(d, "revoked")
        if changed:
            self._persist()

    def _load_state(self) -> dict[str, Any]:
        p = self.dir / "state.json"
        if p.exists():
            try:
                return self.store.load()
            except (StoreCorrupt, c.CryptoError) as e:
                raise StateCorrupt(str(e)) from None
        blobs = self.dir / "blobs"
        leftovers = [x for x in (self.dir / "revoked.log", self.dir / "audit.jsonl") if x.exists() and x.stat().st_size]
        if leftovers or self.revoked or self.audit.entries or (blobs.exists() and any(blobs.rglob("*"))):
            raise StateCorrupt("state.json is missing but this directory holds service data; "
                               "restore from a verified backup instead of starting empty")
        self._fresh = True
        return self.store.wrap({"suite": c.SUITE, "users": {}, "devices": {}, "files": {}, "applied": 0})

    def _check_not_truncated(self) -> None:
        n = int(self.state.get("applied", 0))
        if n > len(self.audit.entries):
            raise AuditError(f"audit log truncated: state has seen {n} entries, log has {len(self.audit.entries)}")
        if n and self.audit.entries[n - 1]["hash"] != self.state.get("audit_head"):
            raise AuditError("audit log does not match the head recorded in state")

    def _check_journal_not_behind_audit(self) -> None:
        """The audit log is the witness for the state journal.

        State is saved before a command is acknowledged, so after a crash the audit log can be ahead of
        state by at most the one command that was in flight: nothing or one state-changing entry
        (a rotation persists its prepare step before it logs the commit, so it never leaves two). More than that means state.wal or state.json lost acknowledged
        commits (deleted, truncated or replaced by an older copy) and starting would silently roll back
        ACLs and devices, so refuse. Revocations are not at risk either way: revoked.log is separate.
        """
        if self._fresh:
            return
        tail = [e for e in self.audit.entries[int(self.state.get("applied", 0)):] if e["type"] in STATE_CHANGING_TYPES]
        ok = len(tail) <= 1
        if not ok:
            raise StateCorrupt(f"state is behind the audit log by {len(tail)} state-changing entries; the journal or "
                               "snapshot lost acknowledged commits. Restore from a verified backup")

    def _persist(self) -> None:
        if self.read_only:
            self.state["_replica"] = {"snapshot_version": self.snapshot_version,
                                      "snapshot_generation": self.snapshot_generation,
                                      "epoch_floor": {k: list(v) for k, v in self.epoch_floor.items()}}
        self.state["applied"] = len(self.audit.entries)
        self.state["audit_head"] = self.audit.head
        self.store.commit(self.state)

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
        lost = [(e["seq"], e["type"]) for e in self.audit.entries[start:] if e["type"] in MUTATING_TYPES]
        if lost:
            # these were logged but the state write never happened and the client never got a success reply
            self.audit.append(self.clock(), "recovery.unapplied", "service",
                              {"seqs": [x[0] for x in lost], "types": sorted({x[1] for x in lost})})
        if changed or start != len(self.audit.entries):
            self._persist()

    # ---------------------------------------------------------------- helpers

    def _log(self, etype: str, actor: str, data: dict[str, Any]) -> dict[str, Any]:
        entry = self.audit.append(self.clock(), etype, actor, data)
        self._crash("after_audit")
        if etype != "alert.raised":
            for a in self.detector.observe(entry):
                self._raise(a)
        return entry

    def _raise(self, a: Alert) -> None:
        data = a.as_data()
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
            prev = f.get("prev")
            if prev and device in prev["wraps"]:
                del prev["wraps"][device]  # a revoked device gets no grace period at all
                changed = True
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
            self._persist()   # state first: a crash after this leaves a usable directory, never a half-empty one
            self._log("service.bootstrapped", "operator", {"user": user, "device": device})
            self._log("device.enrolled", "operator", {"user": user, "device": device})
            self._persist()

    # ------------------------------------------------------------ entry point

    def handle(self, env: dict[str, Any], source: str = "local") -> dict[str, Any]:
        """Process one signed envelope. Returns a JSON-able dict or raises Denied.

        ``source`` is the network origin (the API passes the client address).
        Nothing an unauthenticated sender can do blocks a legitimate device: failures are
        counted and rate limited, never turned into a lockout.
        """
        with self._lock:
            self._src = str(source)[:64]
            return self._handle(env)

    def _deny(self, etype: str, actor: str, data: dict[str, Any], code: str, reason: str) -> None:
        if etype.startswith("auth."):
            data = dict(data, source=self._src)
        self._log(etype, actor, data)
        raise Denied(code, reason)

    # -- bounded logging and rate limits for traffic that has not earned an audit line ------------
    def _roll(self, now: float) -> None:
        minute = int(now // 60)
        if minute == self._ua_minute:
            return
        if self._ua_suppressed and self._ua_minute >= 0:
            self._log("auth.failures_suppressed", "service",
                      {"minute": self._ua_minute, "count": self._ua_suppressed,
                       "note": "failed, limited or retried requests beyond the per-minute logging budget"})
            self._persist()
        self._ua_minute, self._ua_src, self._ua_total, self._ua_suppressed = minute, {}, 0, 0
        self._ua_post = 0
        self._rate = {k: v for k, v in self._rate.items() if v[0] == minute}

    def _rate_hit(self, key: str, limit: int, now: float) -> bool:
        minute = int(now // 60)
        m, n = self._rate.get(key, (minute, 0))
        if m != minute:
            m, n = minute, 0
        n += 1
        if len(self._rate) > 20_000 and key not in self._rate:
            return False                       # table full: stop tracking rather than grow without bound
        self._rate[key] = (m, n)
        return n > limit

    def _throttled(self, cls: str, key: str, etype: str, actor: str, data: dict[str, Any],
                   code: str, reason: str, pre_auth: bool = False) -> None:
        """Log a bounded number of signed lines and count the rest.

        Requests that failed before any signature checked out (``pre_auth``) share a small total
        budget and count against the source's failure budget. Events after a valid signature
        (revoked device, replay, stale, wrong audience) are never throttled by anonymous noise:
        each gets its own few lines per device per minute.
        """
        k = f"{cls}|{key}"
        n = self._ua_src.get(k, 0)
        over_src = pre_auth and self._rate_hit(f"srcfail:{self._src}", SOURCE_FAIL_PER_MIN, self.clock())
        if pre_auth:
            allowed = n < UNAUTH_LOG_PER_SOURCE_MIN and self._ua_total < UNAUTH_LOG_TOTAL_MIN
        else:
            # the first line per device and class is never crowded out; extras share a global cap
            allowed = n == 0 or (n < UNAUTH_LOG_PER_SOURCE_MIN and self._ua_post < POST_AUTH_EXTRA_LOG_MIN)
        if allowed:
            self._ua_src[k] = n + 1
            if pre_auth:
                self._ua_total += 1
            elif n > 0:
                self._ua_post += 1
            self._log(etype, actor, dict(data, source=self._src))
            self._persist()     # keep state.applied current so tail truncation is caught
        else:
            self._ua_suppressed += 1
        if over_src:
            raise Denied("rate_limited", "too many failed requests from this source", 429)
        raise Denied(code, reason)

    def _handle(self, env: dict[str, Any]) -> dict[str, Any]:
        now = self.clock()
        self._roll(now)
        if self.read_only and self.lease_s is not None and (self.last_sync is None or now - self.last_sync > self.lease_s):
            # the lease lives in the node: a replica that cannot show it is current refuses everyone (fail closed),
            # including right after a restart, until its first successful sync
            raise Denied("node_stale", "replica cannot confirm revocation state; failing closed", 503)
        try:
            cmd, dev_id = env["cmd"], env["device"]
            ts, nonce, args = env["ts"], env["nonce"], env["args"]
            aud = env.get("aud", "primary")
            if not isinstance(aud, str) or len(aud) > 64:
                raise KeyError
            sig = c.b64d(env["sig"])
            if not (isinstance(cmd, str) and isinstance(dev_id, str) and isinstance(nonce, str)):
                raise KeyError
            if (not isinstance(args, dict) or isinstance(ts, bool) or not isinstance(ts, (int, float))
                    or not math.isfinite(ts) or abs(ts) > 1e12):
                raise KeyError
            if len(nonce) > 64 or len(dev_id) > 64:
                raise KeyError
            body = {k: env[k] for k in ("cmd", "device", "ts", "nonce", "args")}
            if "aud" in env:
                body["aud"] = env["aud"]
            canon = c.canonical(body)
        except Exception:  # noqa: BLE001  any malformed envelope is a clean 400, never a 500
            self._ua_suppressed += 1
            if self._rate_hit(f"srcfail:{self._src}", SOURCE_FAIL_PER_MIN, now):
                raise Denied("rate_limited", "too many failed requests from this source", 429) from None
            raise Denied("bad_request", "malformed envelope", 400) from None

        dev = self.state["devices"].get(dev_id)
        if dev is None:
            self._throttled("anon", self._src, "auth.unknown_device", "unknown",
                            {"device": dev_id[:64], "cmd": cmd[:32]}, "unauthorized", "unknown device", pre_auth=True)
        if not c.verify(c.b64d(dev["sign_pub"]), "cmd", canon, sig):
            self._throttled("anon", self._src, "auth.bad_signature", dev_id,
                            {"device": dev_id, "cmd": cmd[:32]}, "unauthorized", "bad signature", pre_auth=True)
        # from here on the signature is valid for a known device
        if self._rate_hit(f"dev:{dev_id}", DEVICE_RATE_PER_MIN, now):
            self._ua_suppressed += 1
            raise Denied("rate_limited", "too many requests from this device", 429)
        if aud != self.name:
            self._throttled("anon", self._src, "auth.wrong_audience", dev_id,
                            {"device": dev_id, "cmd": cmd, "aud": aud[:64]},
                            "wrong_audience", "request was signed for a different node")
        if abs(now - ts) > SKEW_S or ts < self.boot:
            self._throttled("anon", self._src, "auth.stale", dev_id,
                            {"device": dev_id, "cmd": cmd, "skew": round(now - ts, 1)},
                            "stale", "timestamp outside the allowed window")
        self._prune_nonces(now)
        nkey = f"{dev_id}:{nonce}"
        bh = c.sha256_hex(canon)
        seen = self.nonces.get(nkey)
        if seen is not None:
            if seen[1] == self._src and seen[2] == bh:
                # the identical request again from the same place: a network retry, not an attack.
                # Refuse it (single use), do not alert, do not penalise the sender.
                self._ua_suppressed += 1
                raise Denied("replay", "request already processed; send a new one", 409)
            self._throttled("anon", f"{dev_id}@{self._src}", "auth.replay", dev_id,
                            {"device": dev_id, "cmd": cmd}, "replay", "nonce already used")
        self.nonces[nkey] = (now, self._src, bh)

        if dev["status"] != "active" or dev_id in self.revoked:
            if dev["status"] == "active":
                self._apply_remove_device(dev_id, "revoked")
                self._persist()
            self._throttled("revoked", dev_id, "auth.revoked_device_use", dev_id,
                            {"device": dev_id, "cmd": cmd,
                             "status": "revoked" if dev["status"] == "active" else dev["status"],
                             "user": dev["user"]},
                            "revoked", f"device is {dev['status']}")
        user = self.state["users"].get(dev["user"])
        if not user or not user["active"]:
            self._deny("auth.disabled_user", dev_id, {"device": dev_id, "user": dev["user"], "cmd": cmd},
                       "forbidden", "user is disabled")

        fn = getattr(self, f"cmd_{cmd}", None)
        if fn is None or cmd.startswith("_"):
            raise Denied("bad_request", "unknown command", 400)
        if self.read_only and cmd not in READ_ONLY_CMDS:
            raise Denied("read_only", f"node {self.name} is a read-only replica; send writes to the primary", 421)
        try:
            self._cur_env = {**body, "sig": env["sig"]} if cmd in ("enroll_device", "create_user", "set_role") else None
            result = fn(dev_id, dev["user"], user["role"], args)
            if cmd not in READ_ONLY_CMDS:   # reads change no state; the audit log alone records them
                self._persist()
        except Denied:
            raise  # commands validate before mutating, so a denial leaves state untouched
        except Exception:  # noqa: BLE001  never leave half-applied in-memory state
            self.state = self._load_state()
            self._recover_rotations()
            raise Denied("internal", "internal error; no change was committed", 500) from None
        return result

    def _prune_nonces(self, now: float) -> None:
        if len(self.nonces) > 1024:
            cutoff = now - 2 * SKEW_S
            self.nonces = {k: v for k, v in self.nonces.items() if v[0] >= cutoff}

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
        if new_role == "admin":
            self.state["users"][new]["role_proof"] = getattr(self, "_cur_env", None)   # the admin's signed request
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
        self.state["users"][target]["role_proof"] = getattr(self, "_cur_env", None) if new_role == "admin" else None
        self._log("role.changed", dev, {"user": target, "old": old, "new": new_role, "by": user})
        return {"ok": True}

    def cmd_enroll_device(self, dev, user, role, args):
        self._require_admin(dev, role, "enroll_device")
        target, new_dev = _valid_id(args.get("user")), _valid_id(args.get("device"))
        try:
            sp, kp = c.b64d(args["sign_pub"]), c.b64d(args["kem_pub"])
        except (KeyError, c.CryptoError):
            raise Denied("bad_request", "missing keys", 400) from None
        if len(kp) != c.KEM_PQ_PUB + c.X_LEN or len(sp) != c.SIG_PUB:
            raise Denied("bad_request", "wrong key size", 400)
        from .client import device_fingerprint
        fp = device_fingerprint(new_dev, target, sp, kp)
        expect = args.get("expect_fingerprint")
        if expect is not None and not _fp_equal(expect, fp):
            raise Denied("fingerprint_mismatch", "key fingerprint differs from the one the admin verified", 409)
        if target not in self.state["users"] or not self.state["users"][target]["active"]:
            raise Denied("bad_request", "unknown or disabled user", 400)
        if new_dev in self.state["devices"]:
            raise Denied("conflict", "device id already used (ids are never reused)", 409)
        self.state["devices"][new_dev] = {
            "user": target, "status": "active", "sign_pub": c.b64e(sp), "kem_pub": c.b64e(kp),
            "enrolled_at": self.clock(), "enrolled_proof": getattr(self, "_cur_env", None),
        }
        for f in self.state["files"].values():
            if target in f["acl"]:
                f["needs_rotation"] = True   # the new device holds no wrap until the owner or an admin re-keys
        self._log("device.enrolled", dev, {"user": target, "device": new_dev, "by": user,
                                              "fingerprint": fp, "verified": expect is not None})
        return {"ok": True, "fingerprint": fp, "verified": expect is not None}

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
        self._record_revoked([target])
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
        self._record_revoked(self._devices_of(target))
        u["active"] = False
        for d in self._devices_of(target):
            self._apply_remove_device(d, "revoked")
        self._log("user.disabled", dev, {"user": target, "by": user, "devices": sorted(self._devices_of(target))})
        return {"ok": True}

    # files ------------------------------------------------------------------

    # ------------------------------------------------ ciphertext blob store
    # Ciphertext lives in content-addressed files (blobs/xx/<sha256>), written and fsynced
    # before the state commit that references them. state.json then stays small, and a
    # blob is verified against its hash on every read.

    def _blob_path(self, h: str) -> Path:
        return self.dir / "blobs" / h[:2] / h

    def _store_blob(self, raw: bytes) -> str:
        h = c.sha256_hex(raw)
        p = self._blob_path(h)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _atomic_write(p, raw)
        return h

    def _load_blob(self, h: str) -> str:
        try:
            raw = self._blob_path(h).read_bytes()
        except OSError:
            raw = b""
        if not raw or c.sha256_hex(raw) != h:
            self._log("storage.corrupt", "service", {"blob": h})
            raise Denied("storage_corrupt", "stored ciphertext is missing or failed its hash check", 500)
        return c.b64e(raw)

    def blob_hashes(self) -> set[str]:
        out = set()
        for f in self.state["files"].values():
            out.add(f["ct"])
            if f.get("prev"):
                out.add(f["prev"]["ct"])
        return out

    def _gc_blobs(self) -> None:
        keep = self.blob_hashes()
        root = self.dir / "blobs"
        if not root.exists():
            return
        for sub in root.iterdir():
            for p in sub.iterdir():
                if p.name not in keep:
                    p.unlink(missing_ok=True)

    @staticmethod
    def _check_commit(x: Any) -> str:
        """Key-commitment tag: HMAC(dek, file|epoch), checked by readers before they trust the key."""
        if not isinstance(x, str) or len(x) != 64 or set(x) - set("0123456789abcdef"):
            raise Denied("bad_request", "key commitment missing or malformed", 400)
        return x

    def _check_blob(self, ct_b64: Any) -> bytes:
        if not isinstance(ct_b64, str) or len(ct_b64) > MAX_FILE_BYTES * 4 // 3 + 64:
            raise Denied("bad_request", "ciphertext missing or too large", 400)
        return c.b64d(ct_b64)

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

    def _check_manifest(self, dev: str, fid: str, epoch: int, acl: list[str], owner: str, commit: str,
                        sig_b64: Any) -> dict[str, Any]:
        wuser = self.state["devices"][dev]["user"]
        """A new file version must carry its writer's signature over what the service is about to commit."""
        from .client import manifest_msg
        try:
            sig = c.b64d(sig_b64)
            pub = c.b64d(self.state["devices"][dev]["sign_pub"])
        except (c.CryptoError, KeyError, TypeError, ValueError):
            raise Denied("bad_request", "manifest_sig missing or malformed", 400) from None
        if not c.verify(pub, "manifest", manifest_msg(fid, epoch, acl, owner, commit, dev, wuser), sig):
            raise Denied("bad_request", "manifest signature does not match this version, acl and owner", 400)
        return {"writer": dev, "sig": c.b64e(sig)}

    def _manifest_out(self, m: dict[str, Any] | None) -> dict[str, Any] | None:
        if not m:
            return None
        dev = self.state["devices"].get(m["writer"])
        return {"writer": m["writer"], "sig": m["sig"], "writer_sign_pub": dev["sign_pub"] if dev else "",
                "writer_user": dev["user"] if dev else "", "enrollment": dev.get("enrolled_proof") if dev else None,
                "role_proof": (self.state["users"].get(dev["user"]) or {}).get("role_proof") if dev else None}

    def cmd_put_file(self, dev, user, role, args):
        fid = _valid_id(args.get("file_id"))
        if fid in self.state["files"]:
            raise Denied("conflict", "file exists; use rotate", 409)
        acl = self._acl(args, user)
        if user not in acl:
            raise Denied("bad_request", "creator must be in acl", 400)
        if len(self.state["files"]) >= MAX_FILES:
            raise Denied("quota", "file limit reached", 429)
        commit = self._check_commit(args.get("commit"))
        ct = self._store_blob(self._check_blob(args.get("ciphertext")))
        wraps = self._check_wraps(args.get("wraps"), acl)
        manifest = self._check_manifest(dev, fid, 1, acl, user, commit, args.get("manifest_sig"))
        self.state["files"][fid] = {
            "owner": user, "acl": acl, "epoch": 1, "ct": ct, "commit": commit, "manifest": manifest,
            "wraps": wraps, "needs_rotation": False, "prev": None,
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
        want = args.get("epoch")
        if want is not None and (isinstance(want, bool) or not isinstance(want, int)):
            raise Denied("bad_request", "epoch must be an integer", 400)
        if want is not None and want != f["epoch"]:
            return self._fetch_previous(dev, user, role, fid, f, want)
        floor = self.epoch_floor.get(fid)
        if floor and floor[0] > f["epoch"] and self.clock() - floor[1] > GRACE_S:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid, "action": "fetch",
                                              "why": f"replica is behind: epoch {floor[0]} exists, cutoff passed"},
                       "stale_replica", "this node has not yet received the current key version")
        wrap = f["wraps"].get(dev)
        if wrap is None:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid,
                                              "action": "fetch", "why": "no key wrapped for this device"},
                       "forbidden", "no key available for this device")
        self._log("access.granted", dev, {"device": dev, "user": user, "file": fid, "epoch": f["epoch"]})
        return {"file_id": fid, "epoch": f["epoch"], "ciphertext": self._load_blob(f["ct"]), "wrap": wrap, "commit": f["commit"],
                "can_rotate": self._may_rotate(user, role, f), "owner": f["owner"],
                "manifest": self._manifest_out(f.get("manifest")),
                "acl": f["acl"], "needs_rotation": f["needs_rotation"]}

    @staticmethod
    def _may_rotate(user: str, role: str, f: dict[str, Any]) -> bool:
        return role == "admin" or f["owner"] == user

    def _fetch_previous(self, dev, user, role, fid, f, want):
        """Rotation cutoff: the previous version is readable for GRACE_S seconds, then rejected."""
        prev = f.get("prev")
        now = self.clock()
        if not prev or prev["epoch"] != want:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid, "action": "fetch",
                                              "why": f"epoch {want} is not current or in grace"},
                       "key_version_retired", "that key version is no longer available")
        age = now - prev["rotated_at"]
        if age > GRACE_S:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid, "action": "fetch",
                                              "why": f"epoch {want} past cutoff ({age:.0f}s > {GRACE_S}s)"},
                       "key_version_retired", "that key version is past its rotation cutoff")
        wrap = prev["wraps"].get(dev)
        if wrap is None:
            self._deny("access.denied", dev, {"device": dev, "user": user, "file": fid, "action": "fetch",
                                              "why": "no grace key for this device"},
                       "forbidden", "no key available for this device")
        self._log("access.granted_grace", dev, {"device": dev, "user": user, "file": fid, "epoch": want,
                                                "age_s": round(age, 1)})
        return {"file_id": fid, "epoch": want, "ciphertext": self._load_blob(prev["ct"]), "wrap": wrap, "commit": prev["commit"],
                "can_rotate": self._may_rotate(user, role, f), "owner": f["owner"],
                "manifest": self._manifest_out(prev.get("manifest")),
                "acl": prev.get("acl", f["acl"]), "needs_rotation": True, "grace_remaining_s": round(GRACE_S - age, 1)}

    def cmd_rotate(self, dev, user, role, args):
        fid = _valid_id(args.get("file_id"))
        f = self._file_for(dev, user, role, fid, "rotate")
        if not self._may_rotate(user, role, f):
            # a member can read; only the owner or an admin can write a new version, so a member
            # cannot replace the content for everyone else
            self._deny("authz.denied", dev, {"device": dev, "user": user, "file": fid, "action": "rotate",
                                             "why": "only the owner or an admin may write a new version"},
                       "forbidden", "only the owner or an admin may rotate this file")
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
        commit = self._check_commit(args.get("commit"))
        ct_raw = self._check_blob(args.get("ciphertext"))
        wraps = self._check_wraps(args.get("wraps"), acl)
        manifest = self._check_manifest(dev, fid, f["epoch"] + 1, acl, f["owner"], commit, args.get("manifest_sig"))
        old_acl = f["acl"]
        ct = self._store_blob(ct_raw)             # durable before the state commit references it
        dropped = f["prev"]["ct"] if f.get("prev") else None
        self._crash("rotate_before_prepare")
        # Journal prepare, apply and persist, then journal commit. Recovery reads the pair.
        self._log("file.rotate_prepared", dev, {"file": fid, "from_epoch": f["epoch"], "to_epoch": f["epoch"] + 1})
        self._crash("rotate_after_prepare")
        # Keep the old version for in-flight readers, only for devices that stay eligible.
        f["prev"] = {"epoch": f["epoch"], "ct": f["ct"], "commit": f["commit"], "rotated_at": self.clock(),
                     "acl": f["acl"], "manifest": f.get("manifest"),
                     "wraps": {d: w for d, w in f["wraps"].items() if d in wraps}}
        f.update(acl=acl, ct=ct, commit=commit, manifest=manifest, wraps=wraps, epoch=f["epoch"] + 1, needs_rotation=False)
        self._persist()
        self._crash("rotate_mid_commit")
        self._log("file.rotated", dev, {"file": fid, "epoch": f["epoch"], "by": user,
                                        "acl_changed": acl != old_acl})
        if dropped and dropped not in self.blob_hashes():
            self._blob_path(dropped).unlink(missing_ok=True)
        self._crash("rotate_after_commit")
        return {"ok": True, "epoch": f["epoch"]}

    def cmd_list_files(self, dev, user, role, args):
        return {"files": [
            {"file_id": k, "epoch": f["epoch"], "needs_rotation": f["needs_rotation"],
             "has_key": dev in f["wraps"], "can_rotate": self._may_rotate(user, role, f)}
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

    # ------------------------------------------------------- replication (cluster)

    def _cert(self, body: dict[str, Any]) -> dict[str, Any]:
        return {"body": body, "sig": c.b64e(c.sign(self._sec, "cert", c.canonical(body)))}

    def certs_from_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Signed revocation / epoch certificates for audit entries (push or pull).

        Each entry's certificates are signed once and cached by sequence number, so a pull costs no new signatures.
        """
        out: list[dict[str, Any]] = []
        for e in entries:
            if e["type"] not in ("device.revoked", "device.lost", "user.disabled", "file.rotated"):
                continue
            hit = self._cert_cache.get(e["seq"])
            if hit is None:
                d, t, certs = e["data"], e["type"], []
                if t in ("device.revoked", "device.lost"):
                    certs.append(self._cert({"kind": "revoke", "device": d["device"], "seq": e["seq"], "ts": e["ts"]}))
                elif t == "user.disabled":
                    # the devices the user had when it was disabled (older entries fall back to the current list)
                    for dev in d.get("devices", self._devices_of(d["user"])):
                        certs.append(self._cert({"kind": "revoke", "device": dev, "seq": e["seq"], "ts": e["ts"]}))
                else:
                    certs.append(self._cert({"kind": "epoch", "file": d["file"], "epoch": d["epoch"],
                                             "seq": e["seq"], "ts": e["ts"]}))
                self._cert_cache[e["seq"]] = hit = certs
            out.extend(hit)
        return out

    def all_certs(self, after_seq: int = -1) -> list[dict[str, Any]]:
        """Pull path: the certificates a node that missed pushes needs, only those after ``after_seq``."""
        with self._lock:
            return self.certs_from_entries([e for e in self.audit.entries[max(after_seq + 1, 0):]])

    def sync_position(self) -> tuple[int, int]:
        """(restore generation, audit length): what a replica compares to decide whether it needs a new snapshot."""
        return int(self.state.get("restore_generation", 0)), len(self.audit.entries)

    def export_snapshot(self, have: set[str] | frozenset[str] = frozenset()) -> dict[str, Any]:
        """Signed state plus only the ciphertext blobs the caller does not already hold."""
        with self._lock:
            blobs = {h: self._load_blob(h) for h in self.blob_hashes() - set(have)}
            body = {"state": json.loads(json.dumps(self.state)), "version": len(self.audit.entries),
                    "generation": int(self.state.get("restore_generation", 0)), "blobs": blobs}
            return {"body": body, "sig": c.b64e(c.sign(self._sec, "snapshot", c.canonical(body)))}

    def install_snapshot(self, snap: dict[str, Any], primary_pub: bytes) -> bool:
        """Replica: install a newer, correctly signed snapshot. Local revocations always win.

        The new state is built and checked on the side; the live state is swapped only at the end.
        """
        with self._lock:
            try:
                ok = c.verify(primary_pub, "snapshot", c.canonical(snap["body"]), c.b64d(snap["sig"]))
                version = snap["body"]["version"]
                generation = snap["body"].get("generation", 0)
                if isinstance(generation, bool) or not isinstance(generation, int):
                    raise ValueError
                new_state = json.loads(json.dumps(snap["body"]["state"]))
                blobs = snap["body"].get("blobs", {})
                if not isinstance(blobs, dict) or isinstance(version, bool) or not isinstance(version, int):
                    raise ValueError
            except Exception:  # noqa: BLE001
                raise Denied("bad_snapshot", "malformed snapshot", 400) from None
            if not ok:
                raise Denied("bad_signature", "snapshot signature invalid", 400)
            if (generation, version) <= (self.snapshot_generation, self.snapshot_version):
                return False   # (restore generation, audit length) must strictly advance
            new_hashes = set()
            for f in new_state.get("files", {}).values():
                new_hashes.add(f["ct"])
                if f.get("prev"):
                    new_hashes.add(f["prev"]["ct"])
            staged: dict[str, bytes] = {}
            for h, b64 in blobs.items():
                raw = c.b64d(b64)
                if c.sha256_hex(raw) != h:
                    raise Denied("bad_snapshot", "snapshot blob does not match its hash", 400)
                staged[h] = raw
            if [h for h in new_hashes if h not in staged and not self._blob_path(h).exists()]:
                raise Denied("bad_snapshot", "snapshot references blobs that were not supplied", 400)
            # validated: now write blobs and swap
            for raw in staged.values():
                self._store_blob(raw)
            old_state, old_ver, old_gen = self.state, self.snapshot_version, self.snapshot_generation
            self.state, self.snapshot_version, self.snapshot_generation = self.store.adopt(new_state), version, generation
            try:
                self._enforce_revoked()
                self._persist()
            except BaseException:
                self.state, self.snapshot_version, self.snapshot_generation = old_state, old_ver, old_gen
                self.store.force_snapshot = True
                raise
            return True

    def apply_cert(self, cert: dict[str, Any], primary_pub: bytes) -> str:
        """Replica: apply a signed certificate. Returns what happened."""
        body = cert["body"]
        if not c.verify(primary_pub, "cert", c.canonical(body), c.b64d(cert["sig"])):
            raise Denied("bad_signature", "certificate signature invalid", 400)
        with self._lock:
            if body["kind"] == "revoke":
                self._record_revoked([body["device"]])
                changed = self._apply_remove_device(body["device"], "revoked")
                if changed:
                    self._persist()
                return "revoked"
            if body["kind"] == "epoch":
                cur = self.epoch_floor.get(body["file"], (0, 0.0))
                if body["epoch"] > cur[0]:
                    self.epoch_floor[body["file"]] = (body["epoch"], body["ts"])
                    self._persist()
                return "epoch"
        raise Denied("bad_request", "unknown certificate kind", 400)
