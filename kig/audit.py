"""Append-only, hash-chained, signed audit log.

Each entry commits to the previous one and is signed with the service's
ML-DSA key, so deleting, reordering or editing any entry is detectable by
anyone holding the service public key.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from . import crypto as c

GENESIS = "0" * 64


class AuditError(Exception):
    pass


def _entry_hash(body: dict[str, Any]) -> str:
    return c.sha256_hex(c.canonical(body))


def verify_chain(entries: list[dict[str, Any]], service_pub: bytes) -> tuple[bool, str]:
    """Check linkage, hashes and signatures. Returns (ok, reason)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        try:
            body = {k: e[k] for k in ("seq", "ts", "prev", "type", "actor", "data")}
            sig = c.b64d(e["sig"])
        except (KeyError, c.CryptoError):
            return False, f"entry {i}: malformed"
        if e["seq"] != i:
            return False, f"entry {i}: sequence gap or reorder (seq={e['seq']})"
        if e["prev"] != prev:
            return False, f"entry {i}: broken link"
        h = _entry_hash(body)
        if e.get("hash") != h:
            return False, f"entry {i}: content hash mismatch"
        if not c.verify(service_pub, "audit", h.encode("ascii"), sig):
            return False, f"entry {i}: bad signature"
        prev = h
    return True, "ok"


CHECKPOINT_EVERY = 8


def verify_checkpoint(entries: list[dict[str, Any]], ckpt: dict[str, Any] | None, service_pub: bytes) -> tuple[bool, str, int | None]:
    """A signed checkpoint pins (count, head hash). Catches tail truncation and rewrites before it."""
    if ckpt is None:
        return True, "ok", None
    body = ckpt.get("body", {})
    try:
        good = c.verify(service_pub, "checkpoint", c.canonical(body), c.b64d(ckpt["sig"]))
    except (KeyError, c.CryptoError):
        good = False
    if not good:
        return False, "checkpoint signature invalid", None
    n = body["count"]
    if len(entries) < n:
        return False, f"log truncated: checkpoint covers {n} entries, found {len(entries)}", len(entries)
    if n and entries[n - 1].get("hash") != body["head"]:
        return False, f"entry {n - 1}: does not match signed checkpoint", n - 1
    return True, "ok", None


def first_bad_seq(reason: str) -> int | None:
    import re
    m = re.search(r"entry (\d+)", reason)
    return int(m.group(1)) if m else None


class AuditLog:
    def __init__(self, path: Path, service_sec: bytes, service_pub: bytes):
        self.path = Path(path)
        self._sec = service_sec
        self.pub = service_pub
        self._lock = threading.Lock()
        self.entries: list[dict[str, Any]] = []
        self.recovered_torn_bytes = 0
        self.ckpt_path = self.path.with_suffix(".ckpt")
        if self.path.exists():
            self.entries = self._load()
            ok, why = self.verify()
            if not ok:
                raise AuditError(f"audit log failed verification on startup: {why}")

    def _read_ckpt(self) -> dict[str, Any] | None:
        import json
        try:
            return json.loads(self.ckpt_path.read_text())
        except (OSError, ValueError):
            return None if not self.ckpt_path.exists() else {"body": {}, "sig": ""}

    def _write_ckpt(self) -> None:
        import json
        body = {"count": len(self.entries), "head": self.head}
        ck = {"body": body, "sig": c.b64e(c.sign(self._sec, "checkpoint", c.canonical(body)))}
        tmp = self.ckpt_path.with_suffix(".ckpt.tmp")
        with open(tmp, "w") as fh:
            fh.write(json.dumps(ck))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.ckpt_path)

    def _load(self) -> list[dict[str, Any]]:
        import json

        out = []
        good_bytes = 0
        with open(self.path, "rb") as fh:
            for raw in fh:
                try:
                    if not raw.endswith(b"\n"):
                        raise ValueError("unterminated line")
                    out.append(json.loads(raw))
                except ValueError:
                    # A torn final write (crash mid-append). Only the very last line may be torn;
                    # drop it and keep the last complete, verified entry.
                    rest = fh.read()
                    if rest.strip():
                        raise AuditError("audit log corrupt before its final line") from None
                    self.recovered_torn_bytes = len(raw)
                    with open(self.path, "r+b") as w:
                        w.truncate(good_bytes)
                    return out
                good_bytes += len(raw)
        return out

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, ts: float, etype: str, actor: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            body = {
                "seq": len(self.entries),
                "ts": round(ts, 3),
                "prev": self.head,
                "type": etype,
                "actor": actor,
                "data": data,
            }
            h = _entry_hash(body)
            entry = dict(body)
            entry["hash"] = h
            entry["sig"] = c.b64e(c.sign(self._sec, "audit", h.encode("ascii")))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            import json

            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.entries.append(entry)
            if len(self.entries) % CHECKPOINT_EVERY == 0:
                self._write_ckpt()
            return entry

    def since(self, seq: int) -> list[dict[str, Any]]:
        return self.entries[max(0, seq):]

    def verify(self) -> tuple[bool, str]:
        ok, why = verify_chain(self.entries, self.pub)
        if not ok:
            return ok, why
        ok, why, _ = verify_checkpoint(self.entries, self._read_ckpt(), self.pub)
        return ok, why
