"""Backup state management."""
from dataclasses import dataclass
from typing import List, Optional

from .db import get_connection, write_transaction, initialize_schema

initialize_schema()


@dataclass(frozen=True)
class BackupState:
    id: int
    path: str
    manifest_hash: str
    status: str
    ts: str


def create(path: str, manifest_hash: str, status: str, ts: str) -> int:
    """Create a backup state entry. Returns the assigned ID."""
    with write_transaction() as conn:
        cur = conn.execute(
            """
            INSERT INTO backup_state (path, manifest_hash, status, ts)
            VALUES (?, ?, ?, ?)
            """,
            (path, manifest_hash, status, ts),
        )
        return cur.lastrowid


def get(backup_id: int) -> Optional[BackupState]:
    """Get a backup state entry by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, path, manifest_hash, status, ts FROM backup_state WHERE id = ?",
        (backup_id,),
    ).fetchone()
    if row is None:
        return None
    return BackupState(
        id=row["id"],
        path=row["path"],
        manifest_hash=row["manifest_hash"],
        status=row["status"],
        ts=row["ts"],
    )


def list_all() -> List[BackupState]:
    """List all backup state entries."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, path, manifest_hash, status, ts FROM backup_state ORDER BY id ASC"
    ).fetchall()
    return [
        BackupState(
            id=row["id"],
            path=row["path"],
            manifest_hash=row["manifest_hash"],
            status=row["status"],
            ts=row["ts"],
        )
        for row in rows
    ]


def update_status(backup_id: int, status: str) -> bool:
    """Update the status of a backup entry. Returns True if entry existed."""
    with write_transaction() as conn:
        cur = conn.execute(
            "UPDATE backup_state SET status = ? WHERE id = ?",
            (status, backup_id),
        )
        return cur.rowcount > 0