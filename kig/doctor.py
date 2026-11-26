"""``kig doctor``: check a data directory and say what is wrong in plain words.

It opens the directory the same way the service does (so it runs normal crash recovery, and it refuses on
a journal that is behind the audit log), then checks the audit chain, every stored blob against its hash,
orphan blobs and file permissions. Exit code 0 means no problems, 1 means at least one FAIL.
"""
from __future__ import annotations

import stat
from pathlib import Path

from . import crypto as c
from .service import GuardService


def check(data: str | Path) -> list[tuple[str, str, str]]:
    """Return (level, check, detail) rows. Level is OK, WARN or FAIL."""
    d = Path(data)
    rows: list[tuple[str, str, str]] = []
    try:
        svc = GuardService(d)
    except Exception as e:  # any refusal to start is the finding
        return [("FAIL", "open", f"{type(e).__name__}: {e}")]
    rows.append(("OK", "open", f"state loaded, {len(svc.state['files'])} files, {len(svc.state['devices'])} devices"))
    from .audit import verify_chain
    ok, why = verify_chain(svc.audit.entries, svc.pub)
    rows.append(("OK", "audit", f"{len(svc.audit.entries)} entries, chain and signatures verify, head {svc.audit.head[:16]}")
                if ok else ("FAIL", "audit", why))
    bad = missing = 0
    for h in svc.blob_hashes():
        p = svc._blob_path(h)
        if not p.exists():
            missing += 1
        elif c.sha256_hex(p.read_bytes()) != h:
            bad += 1
    rows.append(("FAIL" if bad or missing else "OK", "blobs",
                 f"{missing} missing, {bad} failing their hash" if bad or missing else "every referenced blob is present and matches its hash"))
    keep = svc.blob_hashes()
    root = d / "blobs"
    orphans = [p for s in root.iterdir() for p in s.iterdir() if p.name not in keep] if root.exists() else []
    rows.append(("WARN" if orphans else "OK", "orphans", f"{len(orphans)} unreferenced blob files" if orphans else "none"))
    loose = [f.name for f in [d / "server_sign.key", d / "state.json", d / "state.wal"]
             if f.exists() and f.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)]
    rows.append(("WARN" if loose else "OK", "permissions", f"group/other access on {', '.join(loose)}" if loose else "private files are owner-only"))
    return rows


def run(data: str | Path) -> int:
    rows = check(data)
    for lvl, name, detail in rows:
        print(f"{lvl:<5} {name:<12} {detail}")
    return 1 if any(r[0] == "FAIL" for r in rows) else 0
