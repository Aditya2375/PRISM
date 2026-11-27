"""Append-only, hash-chained, signed audit log.

Each entry commits to the previous one and is signed with the service's
ML-DSA key, so deleting, reordering or editing any entry in the middle is detectable by
anyone holding the service public key. A head anchor file catches accidental truncation;
only an externally stored head defends against an attacker who controls the whole directory.
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


ENTRY_FIELDS = {"seq", "ts", "prev", "type", "actor", "data", "hash", "sig"}


def verify_chain(entries: list[dict[str, Any]], service_pub: bytes, sig_from: int = 0) -> tuple[bool, str]:
    """Check linkage, hashes and signatures. Returns (ok, reason).

    Links and hashes are always checked for every entry. Signatures are checked from
    ``sig_from`` on: entries before it are covered by a verified anchor entry whose hash
    commits to the whole prefix.
    """
    prev = GENESIS
    for i, e in enumerate(entries):
        try:
            if not isinstance(e, dict) or set(e) != ENTRY_FIELDS:
                raise KeyError("fields")        # an unsigned extra field is a change the signature does not cover
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
        if i >= sig_from and not c.verify(service_pub, "audit", h.encode("ascii"), sig):
            return False, f"entry {i}: bad signature"
        prev = h
    return True, "ok"


def _anchor_ok(entry: dict[str, Any], anchor: dict[str, Any], service_pub: bytes) -> bool:
    try:
        return (entry["hash"] == anchor["hash"] and entry["seq"] == anchor["seq"]
                and c.verify(service_pub, "audit", anchor["hash"].encode("ascii"), c.b64d(anchor["sig"])))
    except (KeyError, c.CryptoError, TypeError):
        return False


def first_bad_seq(reason: str) -> int | None:
    import re
    m = re.search(r"entry (\d+)", reason)
    return int(m.group(1)) if m else None


def check_log(entries: list[dict[str, Any]], anchor: dict[str, Any] | None, service_pub: bytes,
              expect_head: str | None = None) -> tuple[bool, str]:
    """Full verification: chain, anchor (the head pointer), and optionally an externally held head.

    The anchor is a copy of the newest entry's own signature, rewritten after every append. It
    catches truncation, a lost tail and a deleted anchor. It cannot stop an attacker who can write
    the whole data directory from truncating the log AND rewriting the anchor to match; only a head
    that is stored elsewhere (``expect_head``) closes that gap.
    """
    if entries and anchor is None:
        return False, "head anchor is missing while the log has entries (tail may have been removed)"
    sig_from = 0
    if anchor is not None:
        n = anchor.get("seq", -1) + 1 if isinstance(anchor.get("seq"), int) else -1
        if n < 0 or len(entries) < n:
            return False, f"log truncated: anchor covers {n} entries, found {len(entries)}"
        if n and not _anchor_ok(entries[n - 1], anchor, service_pub):
            return False, f"entry {max(n - 1, 0)}: does not match the signed head anchor"
        sig_from = n  # prefix is committed by the verified anchor's hash chain
    ok, why = verify_chain(entries, service_pub, sig_from)
    if not ok:
        return ok, why
    if expect_head is not None and (entries[-1]["hash"] if entries else GENESIS) != expect_head:
        return False, "log head does not match the externally recorded head"
    return True, "ok"


class AuditLog:
    def __init__(self, path: Path, service_sec: bytes, service_pub: bytes):
        self.path = Path(path)
        self._sec = service_sec
        self.pub = service_pub
        self._lock = threading.Lock()
        self.entries: list[dict[str, Any]] = []
        self.recovered_torn_bytes = 0
        self.ckpt_path = self.path.with_suffix(".head")
        if self.path.exists():
            self.entries = self._load()
            ok, why = self.verify()
            if not ok:
                raise AuditError(f"audit log failed verification on startup: {why}")
        elif self.ckpt_path.exists():
            raise AuditError("audit log is missing but its head anchor exists")

    def _read_anchor(self) -> dict[str, Any] | None:
        import json
        if not self.ckpt_path.exists():
            return None
        try:
            a = json.loads(self.ckpt_path.read_text())
            return a if isinstance(a, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_anchor(self, entry: dict[str, Any]) -> None:
        import json
        from . import vault
        vault.write_atomic(self.ckpt_path, json.dumps({"seq": entry["seq"], "hash": entry["hash"], "sig": entry["sig"]}).encode())

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
                except (ValueError, RecursionError):
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
        import json
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
            line = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            good = os.fstat(fd).st_size
            try:
                with os.fdopen(fd, "ab") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                # e.g. disk full: never leave a torn line in the middle of the log
                with open(self.path, "r+b") as w:
                    w.truncate(good)
                raise
            self.entries.append(entry)
            self._write_anchor(entry)
            return entry

    def since(self, seq: int) -> list[dict[str, Any]]:
        return self.entries[max(0, seq):]

    def verify(self, expect_head: str | None = None) -> tuple[bool, str]:
        return check_log(self.entries, self._read_anchor(), self.pub, expect_head)
