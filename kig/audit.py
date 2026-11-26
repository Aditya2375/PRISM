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


class AuditLog:
    def __init__(self, path: Path, service_sec: bytes, service_pub: bytes):
        self.path = Path(path)
        self._sec = service_sec
        self.pub = service_pub
        self._lock = threading.Lock()
        self.entries: list[dict[str, Any]] = []
        if self.path.exists():
            self.entries = self._load()
            ok, why = verify_chain(self.entries, self.pub)
            if not ok:
                raise AuditError(f"audit log failed verification on startup: {why}")

    def _load(self) -> list[dict[str, Any]]:
        import json

        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
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
            return entry

    def since(self, seq: int) -> list[dict[str, Any]]:
        return self.entries[max(0, seq):]

    def verify(self) -> tuple[bool, str]:
        return verify_chain(self.entries, self.pub)
