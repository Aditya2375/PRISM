"""``kig doctor``: check a data directory and say what is wrong in plain words.

Read-only: it never writes to the directory it checks, so it can run next to a live server. It works on a
temporary copy (blobs are linked, not copied), where it opens the service exactly as start-up does, so crash
recovery, the journal-behind-audit check and the audit chain are all exercised, and any clean-up they do
happens on the copy only. Then it compares the original's blobs to what state references and checks permissions.
Exit code 0 means no problems, 1 means at least one FAIL.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

from .service import GuardService


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mirror(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        if item.name == "blobs":
            continue
        if item.is_file():
            shutil.copy2(item, dst / item.name)
    blobs = src / "blobs"
    if blobs.is_dir():
        for sub in blobs.iterdir():
            if sub.is_dir():
                (dst / "blobs" / sub.name).mkdir(parents=True)
                for f in sub.iterdir():
                    os.symlink(f.resolve(), dst / "blobs" / sub.name / f.name)


def check(data: str | Path) -> list[tuple[str, str, str]]:
    """Return (level, check, detail) rows. Level is OK, WARN or FAIL."""
    d = Path(data)
    if not d.is_dir() or not (d / "audit.jsonl").exists() or not (d / "server_sign.pub").exists() \
            or not ((d / "state.json").exists() or (d / "state.wal").exists()):
        return [("FAIL", "open", f"no PRISM data in {d} (expected audit.jsonl, server_sign.pub and state.json)")]
    with tempfile.TemporaryDirectory(prefix="prism-doctor-") as tmp:
        work = Path(tmp) / "d"
        work.mkdir(mode=0o700)
        _mirror(d, work)
        return _check_copy(d, work)


def _check_copy(d: Path, work: Path) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    try:
        svc = GuardService(work)
    except Exception as e:  # any refusal to start is the finding
        return [("FAIL", "open", f"{type(e).__name__}: {e}")]
    rows.append(("OK", "open", f"state loaded, {len(svc.state['files'])} files, {len(svc.state['devices'])} devices"))
    ok, why = svc.audit.verify()
    rows.append(("OK", "audit", f"{len(svc.audit.entries)} entries, chain and signatures verify, head {svc.audit.head[:16]}")
                if ok else ("FAIL", "audit", why))
    keep = svc.blob_hashes()
    bad = missing = 0
    for h in keep:
        p = d / "blobs" / h[:2] / h
        if not p.exists():
            missing += 1
        elif _sha(p) != h:
            bad += 1
    rows.append(("FAIL" if bad or missing else "OK", "blobs",
                 f"{missing} missing, {bad} failing their hash" if bad or missing
                 else "every referenced blob is present and matches its hash"))
    root = d / "blobs"
    orphans = [p for s in root.iterdir() if s.is_dir() for p in s.iterdir() if p.name not in keep] if root.exists() else []
    rows.append(("WARN" if orphans else "OK", "orphans",
                 f"{len(orphans)} unreferenced blob files (the service removes them at its next start)" if orphans else "none"))
    loose = [f.name for f in (d / "server_sign.key", d / "state.json", d / "state.wal")
             if f.exists() and f.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)]
    writable = [f.name for f in [d / "audit.jsonl", *(p for s in root.iterdir() if s.is_dir() for p in s.iterdir())]
                if root.exists() and f.exists() and f.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)] \
        if root.exists() else [f.name for f in [d / "audit.jsonl"] if f.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)]
    msg = []
    if loose:
        msg.append(f"group/other access on {', '.join(loose)}")
    if writable:
        msg.append(f"group/other can write {len(writable)} file(s), e.g. {writable[0]}")
    rows.append(("WARN" if msg else "OK", "permissions", "; ".join(msg) if msg else "private files are owner-only"))
    return rows


def run(data: str | Path) -> int:
    rows = check(data)
    for lvl, name, detail in rows:
        print(f"{lvl:<5} {name:<12} {detail}")
    return 1 if any(r[0] == "FAIL" for r in rows) else 0
