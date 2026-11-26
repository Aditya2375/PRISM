"""Audit log management."""
from typing import Iterator, Optional

from .db import get_connection, write_transaction, initialize_schema

initialize_schema()


def append(record: dict) -> int:
    """
    Append an audit record atomically. Returns the assigned sequence number.
    Expected keys: ts, actor, action, key_id, result, reason, entry_hash, prev_hash, signature
    """
    with write_transaction() as conn:
        cur = conn.execute(
            """
            INSERT INTO audit_records (ts, actor, action, key_id, result, reason, entry_hash, prev_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["ts"],
                record["actor"],
                record["action"],
                record.get("key_id"),
                record["result"],
                record.get("reason"),
                record["entry_hash"],
                record["prev_hash"],
                record.get("signature"),
            ),
        )
        return cur.lastrowid


def last() -> Optional[dict]:
    """Get the most recent audit record."""
    conn = get_connection()
    row = conn.execute(
        "SELECT seq, ts, actor, action, key_id, result, reason, entry_hash, prev_hash, signature "
        "FROM audit_records ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def iter(start_seq: int = 0) -> Iterator[dict]:
    """Iterate over audit records from start_seq (inclusive)."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT seq, ts, actor, action, key_id, result, reason, entry_hash, prev_hash, signature "
        "FROM audit_records WHERE seq >= ? ORDER BY seq ASC",
        (start_seq,),
    )
    for row in cur:
        yield dict(row)