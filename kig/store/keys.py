"""Key records management."""
from dataclasses import dataclass
from typing import Optional, List

from .db import get_connection, write_transaction, initialize_schema

initialize_schema()


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    version: int
    state: str
    owner: str
    purpose: str
    wrapped_blob: bytes
    created_at: str


def create(key_id: str, version: int, state: str, owner: str, purpose: str, wrapped_blob: bytes, created_at: str) -> None:
    """Create a new key record."""
    with write_transaction() as conn:
        conn.execute(
            """
            INSERT INTO key_records (key_id, version, state, owner, purpose, wrapped_blob, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (key_id, version, state, owner, purpose, wrapped_blob, created_at),
        )


def get(key_id: str, version: int) -> Optional[KeyRecord]:
    """Get a key record by key_id and version."""
    conn = get_connection()
    row = conn.execute(
        "SELECT key_id, version, state, owner, purpose, wrapped_blob, created_at "
        "FROM key_records WHERE key_id = ? AND version = ?",
        (key_id, version),
    ).fetchone()
    if row is None:
        return None
    return KeyRecord(
        key_id=row["key_id"],
        version=row["version"],
        state=row["state"],
        owner=row["owner"],
        purpose=row["purpose"],
        wrapped_blob=row["wrapped_blob"],
        created_at=row["created_at"],
    )


def get_latest(key_id: str) -> Optional[KeyRecord]:
    """Get the latest version of a key record."""
    conn = get_connection()
    row = conn.execute(
        "SELECT key_id, version, state, owner, purpose, wrapped_blob, created_at "
        "FROM key_records WHERE key_id = ? ORDER BY version DESC LIMIT 1",
        (key_id,),
    ).fetchone()
    if row is None:
        return None
    return KeyRecord(
        key_id=row["key_id"],
        version=row["version"],
        state=row["state"],
        owner=row["owner"],
        purpose=row["purpose"],
        wrapped_blob=row["wrapped_blob"],
        created_at=row["created_at"],
    )


def list_versions(key_id: str) -> List[KeyRecord]:
    """List all versions of a key record."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT key_id, version, state, owner, purpose, wrapped_blob, created_at "
        "FROM key_records WHERE key_id = ? ORDER BY version ASC",
        (key_id,),
    ).fetchall()
    return [
        KeyRecord(
            key_id=row["key_id"],
            version=row["version"],
            state=row["state"],
            owner=row["owner"],
            purpose=row["purpose"],
            wrapped_blob=row["wrapped_blob"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


def update_state(key_id: str, version: int, state: str) -> bool:
    """Update the state of a key record. Returns True if record existed."""
    with write_transaction() as conn:
        cur = conn.execute(
            "UPDATE key_records SET state = ? WHERE key_id = ? AND version = ?",
            (state, key_id, version),
        )
        return cur.rowcount > 0


def delete(key_id: str, version: int) -> bool:
    """Delete a key record. Returns True if record existed."""
    with write_transaction() as conn:
        cur = conn.execute(
            "DELETE FROM key_records WHERE key_id = ? AND version = ?",
            (key_id, version),
        )
        return cur.rowcount > 0