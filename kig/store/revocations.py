"""Revocation management."""
from dataclasses import dataclass
from typing import List, Optional

from .db import get_connection, write_transaction, initialize_schema

initialize_schema()


@dataclass(frozen=True)
class Revocation:
    seq: int
    key_id: str
    version: int
    ts: str
    signer: str
    signature: bytes


def append(seq: int, key_id: str, version: int, ts: str, signer: str, signature: bytes) -> None:
    """Append a revocation record."""
    with write_transaction() as conn:
        conn.execute(
            """
            INSERT INTO revocations (seq, key_id, version, ts, signer, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (seq, key_id, version, ts, signer, signature),
        )


def get(seq: int) -> Optional[Revocation]:
    """Get a revocation by sequence number."""
    conn = get_connection()
    row = conn.execute(
        "SELECT seq, key_id, version, ts, signer, signature FROM revocations WHERE seq = ?",
        (seq,),
    ).fetchone()
    if row is None:
        return None
    return Revocation(
        seq=row["seq"],
        key_id=row["key_id"],
        version=row["version"],
        ts=row["ts"],
        signer=row["signer"],
        signature=row["signature"],
    )


def get_latest() -> Optional[Revocation]:
    """Get the most recent revocation."""
    conn = get_connection()
    row = conn.execute(
        "SELECT seq, key_id, version, ts, signer, signature FROM revocations ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return Revocation(
        seq=row["seq"],
        key_id=row["key_id"],
        version=row["version"],
        ts=row["ts"],
        signer=row["signer"],
        signature=row["signature"],
    )


def is_revoked(key_id: str, version: int) -> bool:
    """Check if a key version is revoked."""
    conn = get_connection()
    row = conn.execute(
        "SELECT 1 FROM revocations WHERE key_id = ? AND version = ? LIMIT 1",
        (key_id, version),
    ).fetchone()
    return row is not None


def list_revocations(key_id: Optional[str] = None) -> List[Revocation]:
    """List all revocations, optionally filtered by key_id."""
    conn = get_connection()
    if key_id is not None:
        rows = conn.execute(
            "SELECT seq, key_id, version, ts, signer, signature FROM revocations WHERE key_id = ? ORDER BY seq ASC",
            (key_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT seq, key_id, version, ts, signer, signature FROM revocations ORDER BY seq ASC"
        ).fetchall()
    return [
        Revocation(
            seq=row["seq"],
            key_id=row["key_id"],
            version=row["version"],
            ts=row["ts"],
            signer=row["signer"],
            signature=row["signature"],
        )
        for row in rows
    ]


def get_max_seq() -> int:
    """Get the maximum sequence number."""
    conn = get_connection()
    row = conn.execute("SELECT MAX(seq) as max_seq FROM revocations").fetchone()
    return row["max_seq"] if row and row["max_seq"] is not None else 0