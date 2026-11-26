"""Database connection and schema management."""
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

_DB_PATH = None
_conn = None
_init_lock = threading.Lock()
_initialized = False
_write_lock = threading.Lock()


def get_db_path():
    global _DB_PATH
    if _DB_PATH is None:
        _DB_PATH = os.environ.get("KIG_DB_PATH", "/tmp/kig.db")
    return _DB_PATH


def set_db_path(path):
    global _DB_PATH, _conn, _initialized
    _DB_PATH = path
    _conn = None
    _initialized = False


def _create_connection():
    path = get_db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.row_factory = sqlite3.Row
    return conn


def get_connection():
    global _conn
    if _conn is None:
        _conn = _create_connection()
    return _conn


@contextmanager
def write_transaction():
    conn = get_connection()
    with _write_lock:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def initialize_schema():
    global _initialized
    if _initialized:
        return
    conn = get_connection()
    with write_transaction() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_records (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                key_id TEXT,
                result TEXT NOT NULL,
                reason TEXT,
                entry_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                signature BLOB
            );
            CREATE TABLE IF NOT EXISTS key_records (
                key_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                state TEXT NOT NULL,
                owner TEXT NOT NULL,
                purpose TEXT NOT NULL,
                wrapped_blob BLOB NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (key_id, version)
            );
            CREATE TABLE IF NOT EXISTS rotation_journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL,
                from_version INTEGER NOT NULL,
                to_version INTEGER NOT NULL,
                state TEXT NOT NULL,
                ts TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS backup_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                ts TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS revocations (
                seq INTEGER PRIMARY KEY,
                key_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                ts TEXT NOT NULL,
                signer TEXT NOT NULL,
                signature BLOB NOT NULL
            );
        """)
    _initialized = True


def close():
    global _conn, _initialized
    with _init_lock:
        if _conn is not None:
            _conn.close()
            _conn = None
        _initialized = False


def reset_for_testing():
    global _conn, _initialized
    with _init_lock:
        if _conn is not None:
            _conn.close()
            _conn = None
        _initialized = False
        path = get_db_path()
        if os.path.exists(path):
            os.remove(path)