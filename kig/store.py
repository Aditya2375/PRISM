"""State storage: a signed snapshot plus a signed write-ahead journal.

The service keeps its state (users, devices, files and a few counters) in memory. Rewriting and
re-signing all of it on every change costs O(number of files). This module makes a change cost
O(size of what changed):

* ``state.json`` is a full snapshot, signed with the service's ML-DSA key, written atomically.
* ``state.wal`` is append-only. Each line holds only the records that changed since the previous
  line, is signed on its own, and carries the hash of the previous line and the id of the snapshot
  it extends. A torn last line is a write that was never acknowledged and is dropped.
* Every ``MAX_WAL_ENTRIES`` lines (or ``MAX_WAL_BYTES``) a new snapshot is written and the journal
  starts again, so replay at start-up stays short.

Which records changed is tracked by the containers themselves (``_Root``, ``_Sec`` and the nested
``_TD``/``_TL`` types), so code that edits ``state["files"][id]["wraps"][dev] = ...`` is noticed
without a manual "mark dirty" call that someone could forget.

Only SHA-256 hashing and ML-DSA signatures (from ``kig.crypto``) are used here, nothing new.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from . import crypto as c

SECTIONS = ("users", "devices", "files")
MAX_WAL_ENTRIES = 1000
MAX_WAL_BYTES = 16 * 1024 * 1024
GENESIS = "0" * 64


class StoreCorrupt(Exception):
    pass


# --------------------------------------------------------------------------- tracked containers
def _wrap(v: Any, notify: Callable[[], None]) -> Any:
    if isinstance(v, dict) and not isinstance(v, _TD):
        return _TD({k: _wrap(x, notify) for k, x in v.items()}, notify)
    if isinstance(v, list) and not isinstance(v, _TL):
        return _TL([_wrap(x, notify) for x in v], notify)
    if isinstance(v, (_TD, _TL)):      # re-home an existing tracked value under a new notifier
        return _wrap(json.loads(json.dumps(v)), notify)
    return v


class _TD(dict):
    def __init__(self, data: dict, notify: Callable[[], None]):
        super().__init__(data)
        self._n = notify

    def __setitem__(self, k, v):
        super().__setitem__(k, _wrap(v, self._n))
        self._n()

    def __delitem__(self, k):
        super().__delitem__(k)
        self._n()

    def pop(self, *a):
        r = super().pop(*a)
        self._n()
        return r

    def popitem(self):
        r = super().popitem()
        self._n()
        return r

    def clear(self):
        super().clear()
        self._n()

    def update(self, *a, **kw):
        for k, v in dict(*a, **kw).items():
            self[k] = v

    def setdefault(self, k, d=None):
        if k not in self:
            self[k] = d
        return self[k]

    def __ior__(self, other):
        self.update(other)
        return self

    def __deepcopy__(self, memo):
        return json.loads(json.dumps(self))


class _TL(list):
    def __init__(self, data: list, notify: Callable[[], None]):
        super().__init__(data)
        self._n = notify

    def _w(self, v):
        return _wrap(v, self._n)

    def append(self, v):
        super().append(self._w(v))
        self._n()

    def extend(self, vs):
        super().extend(self._w(v) for v in vs)
        self._n()

    def insert(self, i, v):
        super().insert(i, self._w(v))
        self._n()

    def __setitem__(self, i, v):
        super().__setitem__(i, self._w(v) if not isinstance(i, slice) else [self._w(x) for x in v])
        self._n()

    def __delitem__(self, i):
        super().__delitem__(i)
        self._n()

    def remove(self, v):
        super().remove(v)
        self._n()

    def pop(self, *a):
        r = super().pop(*a)
        self._n()
        return r

    def clear(self):
        super().clear()
        self._n()

    def sort(self, *a, **kw):
        super().sort(*a, **kw)
        self._n()

    def reverse(self):
        super().reverse()
        self._n()

    def __iadd__(self, other):
        self.extend(other)
        return self

    def __imul__(self, n):
        super().__imul__(n)
        self._n()
        return self

    def __deepcopy__(self, memo):
        return json.loads(json.dumps(self))


class _Sec(dict):
    """One of users/devices/files: a mapping id -> record. Remembers which ids changed."""

    def __init__(self, store: "StateStore", name: str):
        super().__init__()
        self._store, self._name = store, name

    def _mark(self, k) -> None:
        self._store.dirty.setdefault(self._name, set()).add(k)

    def __setitem__(self, k, v):
        super().__setitem__(k, _wrap(v, lambda k=k: self._mark(k)))
        self._mark(k)

    def __delitem__(self, k):
        super().__delitem__(k)
        self._mark(k)

    def pop(self, k, *d):
        had = k in self
        r = super().pop(k, *d)
        if had:
            self._mark(k)
        return r

    def clear(self):
        for k in list(self):
            self._mark(k)
        super().clear()

    def update(self, *a, **kw):
        for k, v in dict(*a, **kw).items():
            self[k] = v

    def setdefault(self, k, d=None):
        if k not in self:
            self[k] = d
        return self[k]

    def __deepcopy__(self, memo):
        return json.loads(json.dumps(self))


class _Root(dict):
    def __init__(self, store: "StateStore"):
        super().__init__()
        self._store = store

    def __setitem__(self, k, v):
        if k in SECTIONS:
            sec = _Sec(self._store, k)
            for kk, vv in dict(v).items():
                dict.__setitem__(sec, kk, _wrap(vv, lambda kk=kk, sec=sec: sec._mark(kk)))
            super().__setitem__(k, sec)
        else:
            super().__setitem__(k, _wrap(v, self._store.meta_touched))
        self._store.meta_touched()

    def __delitem__(self, k):
        super().__delitem__(k)
        self._store.meta_touched()

    def pop(self, *a):
        r = super().pop(*a)
        self._store.meta_touched()
        return r

    def update(self, *a, **kw):
        for k, v in dict(*a, **kw).items():
            self[k] = v

    def setdefault(self, k, d=None):
        if k not in self:
            self[k] = d
        return self[k]

    def __deepcopy__(self, memo):
        return json.loads(json.dumps(self))


# --------------------------------------------------------------------------------- the store
def encode_snapshot(plain: dict[str, Any], sec: bytes, snap_id: str, seq: int = 0, head: str = GENESIS) -> bytes:
    body = {k: v for k, v in plain.items() if k not in ("_sig", "_wal")}
    body["_wal"] = {"id": snap_id, "seq": seq, "head": head}
    body["_sig"] = c.b64e(c.sign(sec, "state", c.canonical({k: v for k, v in body.items() if k != "_sig"})))
    return json.dumps(body, sort_keys=True).encode()


def peek_meta(data_dir: str | Path) -> dict[str, Any]:
    """Best-effort read of the small top-level values (counters) from a directory. NOT verified.

    Used only as a hint, for example the highest backup counter a surviving directory remembers.
    """
    d = Path(data_dir)
    out: dict[str, Any] = {}
    try:
        out.update({k: v for k, v in json.loads((d / "state.json").read_text()).items() if k not in SECTIONS})
    except (OSError, ValueError, AttributeError):
        return out
    try:
        for line in (d / "state.wal").read_text().splitlines():
            try:
                out.update(json.loads(line)["e"]["meta"])
            except (ValueError, KeyError, TypeError):
                continue
    except OSError:
        pass
    return out


class StateStore:
    def __init__(self, data_dir: Path, sec: bytes, pub: bytes, crash: Callable[[str], None] = lambda p: None):
        self.dir = Path(data_dir)
        self._sec, self._pub, self._crash = sec, pub, crash
        self.snap_path, self.wal_path = self.dir / "state.json", self.dir / "state.wal"
        self.dirty: dict[str, set[str]] = {}
        self._reset(None)

    def _reset(self, snap_id: str | None) -> None:
        self.snap_id = snap_id
        self.seq = 0
        self.head = GENESIS
        self.wal_entries = 0
        self.wal_bytes = 0
        self.force_snapshot = snap_id is None
        self.dirty = {}

    def meta_touched(self) -> None:
        pass   # the small top-level values are written with every journal line

    def exists(self) -> bool:
        return self.snap_path.exists()

    def wrap(self, plain: dict[str, Any]) -> _Root:
        root = _Root(self)
        for k, v in plain.items():
            root[k] = v
        self.dirty = {}
        return root

    def adopt(self, plain: dict[str, Any]) -> _Root:
        """Replace the whole state (a replica installing a snapshot): next commit writes a full snapshot."""
        root = self.wrap(json.loads(json.dumps(plain)))
        self.force_snapshot = True
        return root

    # ------------------------------------------------------------------------------ load
    def load(self) -> _Root:
        try:
            st = json.loads(self.snap_path.read_text())
            sig = c.b64d(st.pop("_sig"))
            wal = st.pop("_wal")
            snap_id, seq, head = wal["id"], int(wal["seq"]), wal["head"]
            if not isinstance(snap_id, str) or not isinstance(head, str):
                raise ValueError
        except Exception:  # noqa: BLE001
            raise StoreCorrupt("state.json is unreadable or unsigned; restore from a verified backup") from None
        signed = dict(st)
        signed["_wal"] = {"id": snap_id, "seq": seq, "head": head}
        if not c.verify(self._pub, "state", c.canonical(signed), sig):
            raise StoreCorrupt("state.json failed its integrity signature; restore from a verified backup")
        c.require_suite(st, "state.json")
        self._reset(snap_id)
        self.force_snapshot = False
        self.seq, self.head = seq, head
        good_bytes = self._replay(st)
        if self.wal_path.exists() and self.wal_path.stat().st_size != good_bytes:
            with open(self.wal_path, "r+b") as fh:        # drop the torn tail so the next line starts clean
                fh.truncate(good_bytes)
                fh.flush()
                os.fsync(fh.fileno())
        self.wal_bytes = good_bytes
        root = self.wrap(st)
        return root

    def _replay(self, st: dict[str, Any]) -> int:
        """Apply journal lines to ``st``; return how many bytes of the file are good.

        A line counts only if it ends in a newline: the newline is the last byte written, and the
        write is acknowledged only after fsync, so an unterminated tail was never acknowledged
        (even if it happens to parse and verify) and is dropped.
        """
        if not self.wal_path.exists():
            return 0
        raw = self.wal_path.read_bytes()
        pos = 0
        for line in raw.split(b"\n")[:-1]:
            line_len = len(line) + 1
            if not line:
                raise StoreCorrupt("state.wal has an empty line; restore from a verified backup")
            try:
                doc = json.loads(line)
                entry, sig = doc["e"], c.b64d(doc["sig"])
                ok = c.verify(self._pub, "statewal", c.canonical(entry), sig)
            except Exception:  # noqa: BLE001
                raise StoreCorrupt("state.wal is damaged before its end; restore from a verified backup") from None
            if not ok:
                raise StoreCorrupt("state.wal entry failed its signature; restore from a verified backup")
            if entry["base"] != self.snap_id:
                pos += line_len
                continue            # left over from before the last snapshot; already included in it
            if entry["seq"] != self.seq + 1 or entry["prev"] != self.head:
                raise StoreCorrupt("state.wal is out of order or has a missing entry")
            for k, v in entry["meta"].items():
                st[k] = v
            for name, recs in entry["sec"].items():
                tgt = st.setdefault(name, {})
                for k, rec in recs.items():
                    if rec is None:
                        tgt.pop(k, None)
                    else:
                        tgt[k] = rec
            self.seq, self.head = entry["seq"], c.sha256_hex(c.canonical(entry))
            self.wal_entries += 1
            pos += line_len
        return pos

    # ---------------------------------------------------------------------------- commit
    def commit(self, state: dict[str, Any]) -> None:
        if (self.force_snapshot or self.wal_entries >= MAX_WAL_ENTRIES or self.wal_bytes >= MAX_WAL_BYTES):
            self._write_snapshot(state)
            return
        entry = {
            "base": self.snap_id, "seq": self.seq + 1, "prev": self.head,
            "meta": {k: v for k, v in state.items() if k not in SECTIONS},
            "sec": {name: {k: state[name].get(k) for k in sorted(keys)}
                    for name, keys in self.dirty.items() if keys},
        }
        sig = c.b64e(c.sign(self._sec, "statewal", c.canonical(entry)))
        line = json.dumps({"e": entry, "sig": sig}, sort_keys=True).encode() + b"\n"
        self._crash("before_state_rename")
        fd = os.open(self.wal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.seq, self.head = entry["seq"], c.sha256_hex(c.canonical(entry))
        self.wal_entries += 1
        self.wal_bytes += len(line)
        self.dirty = {}

    def _write_snapshot(self, state: dict[str, Any]) -> None:
        snap_id = os.urandom(8).hex()
        data = encode_snapshot(state, self._sec, snap_id)
        _atomic_write(self.snap_path, data, hook=lambda: self._crash("before_state_rename"))
        # new snapshot is durable; only now can the old journal go (a crash in between leaves a journal
        # whose base no longer matches, which load() ignores)
        fd = os.open(self.wal_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self._reset(snap_id)
        self.force_snapshot = False


def _atomic_write(path: Path, data: bytes, mode: int = 0o600, hook: Callable[[], None] | None = None) -> None:
    # a random exclusive temp name that never follows a symlink: a planted link cannot redirect the write
    tmp = path.with_name(f".{path.name}.{os.urandom(6).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if hook:
            hook()
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
