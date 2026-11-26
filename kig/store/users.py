"""User management."""
from dataclasses import dataclass
from typing import Optional

from .db import get_connection, write_transaction, initialize_schema

initialize_schema()


@dataclass(frozen=True)
class User:
    user_id: str
    role: str
    status: str
    epoch: int
    created_at: str


def get(user_id: str) -> Optional[User]:
    """Get a user by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT user_id, role, status, epoch, created_at FROM users WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return User(
        user_id=row["user_id"],
        role=row["role"],
        status=row["status"],
        epoch=row["epoch"],
        created_at=row["created_at"],
    )


def create(user_id: str, role: str, status: str, epoch: int, created_at: str) -> None:
    """Create a new user."""
    with write_transaction() as conn:
        conn.execute(
            "INSERT INTO users (user_id, role, status, epoch, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, role, status, epoch, created_at),
        )


def update_status(user_id: str, status: str) -> bool:
    """Update user status. Returns True if user existed."""
    with write_transaction() as conn:
        cur = conn.execute(
            "UPDATE users SET status = ? WHERE user_id = ?",
            (status, user_id),
        )
        return cur.rowcount > 0


def update_epoch(user_id: str, epoch: int) -> bool:
    """Update user epoch. Returns True if user existed."""
    with write_transaction() as conn:
        cur = conn.execute(
            "UPDATE users SET epoch = ? WHERE user_id = ?",
            (epoch, user_id),
        )
        return cur.rowcount > 0


def seed_synthetic_users() -> None:
    """Create a deterministic set of synthetic users for testing."""
    users = [
        ("alice", "admin", "active", 1, "2024-01-01T00:00:00Z"),
        ("bob", "operator", "active", 1, "2024-01-01T00:00:00Z"),
        ("carol", "auditor", "active", 1, "2024-01-01T00:00:00Z"),
        ("dave", "operator", "suspended", 1, "2024-01-01T00:00:00Z"),
        ("eve", "admin", "active", 2, "2024-01-01T00:00:00Z"),
    ]
    with write_transaction() as conn:
        for user_id, role, status, epoch, created_at in users:
            conn.execute(
                "INSERT OR IGNORE INTO users (user_id, role, status, epoch, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, role, status, epoch, created_at),
            )