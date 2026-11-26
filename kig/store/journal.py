"""Rotation journal management."""
from dataclasses import dataclass
from typing import List, Optional

from .db import get_connection, write_transaction, initialize_schema

initialize_schema()


@dataclass(frozen=True)
class RotationEntry:
    id: int
    key_id: str
    from_version: int
    to_version: int
    state: str
    ts: str


def append(key_id: str, from_version: int, to_version: int, state: str, ts: str) -> int:
    """Append a rotation journal entry. Returns the assigned ID."""
    with write_transaction() as conn:
        cur = conn.execute(
            """
            INSERT INTO rotation_journal (key_id, from_version, to_version, state, ts)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key_id, from_version, to_version, state, ts),
        )
        return cur.lastrowid


def get(entry_id: int) -> Optional[RotationEntry]:
    """Get a rotation journal entry by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, key_id, from_version, to_version, state, ts FROM rotation_journal WHERE id = ?",
        (entry_id,),
    ).fetchone()
    if row is None:
        return None
    return RotationEntry(
        id=row["id"],
        key_id=row["key_id"],
        from_version=row["from_version"],
        to_version=row["to_version"],
        state=row["state"],
        ts=row["ts"],
    )


def list_for_key(key_id: str) -> List[RotationEntry]:
    """List all rotation entries for a key."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, key_id, from_version, to_version, state, ts FROM rotation_journal WHERE key_id = ? ORDER BY id ASC",
        (key_id,),
    ).fetchall()
    return [
        RotationEntry(
            id=row["id"],
            key_id=row["key_id"],
            from_version=row["from_version"],
            to_version=row["to_version"],
            state=row["state"],
            ts=row["ts"],
        )
        for row in rows
    ]


def update_state(entry_id: int, state: str) -> bool:
    """Update the state of a rotation entry. Returns True if entry existed."""
    with write_transaction() as conn:
        cur = conn.execute(
            "UPDATE rotation_journal SET state = ? WHERE id = ?",
            (state, entry_id),
        )
        return cur.rowcount > 0