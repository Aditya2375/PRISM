"""Tests for the database layer."""
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from kig.store import (
    reset_for_testing,
    set_db_path,
    get_db_path,
    initialize_schema,
    close,
    User,
    get_user,
    create_user,
    update_status,
    update_epoch,
    seed_synthetic_users,
    audit_append,
    audit_last,
    audit_iter,
    KeyRecord,
    key_create,
    key_get,
    key_get_latest,
    key_list_versions,
    key_update_state,
    key_delete,
    RotationEntry,
    journal_append,
    journal_get,
    journal_list_for_key,
    journal_update_state,
    BackupState,
    backup_create,
    backup_get,
    backup_list_all,
    backup_update_status,
    Revocation,
    revocation_append,
    revocation_get,
    revocation_get_latest,
    revocation_is_revoked,
    revocation_list_revocations,
    revocation_get_max_seq,
)


@pytest.fixture(autouse=True)
def temp_db():
    """Create a temporary database for each test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    set_db_path(db_path)
    initialize_schema()
    yield
    close()
    reset_for_testing()
    if os.path.exists(db_path):
        os.unlink(db_path)


def test_user_crud():
    """Test user create, read, update."""
    # Create
    create_user("test_user", "admin", "active", 1, "2024-01-01T00:00:00Z")

    # Read
    user = get_user("test_user")
    assert user is not None
    assert user.user_id == "test_user"
    assert user.role == "admin"
    assert user.status == "active"
    assert user.epoch == 1
    assert user.created_at == "2024-01-01T00:00:00Z"

    # Update status
    assert update_status("test_user", "suspended") is True
    user = get_user("test_user")
    assert user.status == "suspended"

    # Update epoch
    assert update_epoch("test_user", 2) is True
    user = get_user("test_user")
    assert user.epoch == 2

    # Non-existent user
    assert get_user("nonexistent") is None
    assert update_status("nonexistent", "active") is False
    assert update_epoch("nonexistent", 1) is False


def test_seed_synthetic_users():
    """Test deterministic synthetic user creation."""
    seed_synthetic_users()

    alice = get_user("alice")
    assert alice is not None
    assert alice.role == "admin"
    assert alice.status == "active"
    assert alice.epoch == 1

    bob = get_user("bob")
    assert bob is not None
    assert bob.role == "operator"

    carol = get_user("carol")
    assert carol is not None
    assert carol.role == "auditor"

    dave = get_user("dave")
    assert dave is not None
    assert dave.status == "suspended"

    eve = get_user("eve")
    assert eve is not None
    assert eve.epoch == 2

    # Idempotent
    seed_synthetic_users()
    alice2 = get_user("alice")
    assert alice2.user_id == alice.user_id


def test_audit_append_and_iter():
    """Test audit record append and iteration."""
    # Append a few records
    seq1 = audit_append({
        "ts": "2024-01-01T00:00:00Z",
        "actor": "alice",
        "action": "key_create",
        "key_id": "key1",
        "result": "success",
        "reason": "created",
        "entry_hash": "hash1",
        "prev_hash": "genesis",
        "signature": b"sig1",
    })
    assert seq1 == 1

    seq2 = audit_append({
        "ts": "2024-01-01T00:00:01Z",
        "actor": "bob",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
        "reason": "fetched",
        "entry_hash": "hash2",
        "prev_hash": "hash1",
        "signature": b"sig2",
    })
    assert seq2 == 2

    seq3 = audit_append({
        "ts": "2024-01-01T00:00:02Z",
        "actor": "carol",
        "action": "key_revoke",
        "key_id": "key1",
        "result": "success",
        "reason": "revoked",
        "entry_hash": "hash3",
        "prev_hash": "hash2",
        "signature": b"sig3",
    })
    assert seq3 == 3

    # Test last()
    last_record = audit_last()
    assert last_record is not None
    assert last_record["seq"] == 3
    assert last_record["actor"] == "carol"

    # Test iter from start
    records = list(audit_iter(0))
    assert len(records) == 3
    assert records[0]["seq"] == 1
    assert records[1]["seq"] == 2
    assert records[2]["seq"] == 3

    # Test iter from middle
    records = list(audit_iter(2))
    assert len(records) == 2
    assert records[0]["seq"] == 2
    assert records[1]["seq"] == 3

    # Test iter past end
    records = list(audit_iter(100))
    assert len(records) == 0


def test_concurrent_audit_appends():
    """Test concurrent audit appends from multiple threads - no duplicate or missing seq."""
    num_threads = 10
    records_per_thread = 50
    errors = []

    def worker(thread_id):
        try:
            for i in range(records_per_thread):
                audit_append({
                    "ts": f"2024-01-01T00:00:{thread_id:02d}:{i:02d}Z",
                    "actor": f"thread_{thread_id}",
                    "action": "test",
                    "key_id": f"key_{thread_id}_{i}",
                    "result": "success",
                    "reason": "test",
                    "entry_hash": f"hash_{thread_id}_{i}",
                    "prev_hash": f"prev_{thread_id}_{i}",
                    "signature": f"sig_{thread_id}_{i}".encode(),
                })
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Thread errors: {errors}"

    # Verify all sequences are present with no gaps
    records = list(audit_iter(0))
    assert len(records) == num_threads * records_per_thread
    seqs = [r["seq"] for r in records]
    assert seqs == list(range(1, num_threads * records_per_thread + 1))


def test_persistence_across_restart():
    """Test that data persists across database close/reopen."""
    db_path = get_db_path()

    # Create data
    create_user("persist_user", "admin", "active", 1, "2024-01-01T00:00:00Z")
    audit_append({
        "ts": "2024-01-01T00:00:00Z",
        "actor": "persist_user",
        "action": "test",
        "key_id": "key1",
        "result": "success",
        "reason": "test",
        "entry_hash": "hash1",
        "prev_hash": "genesis",
        "signature": b"sig1",
    })
    key_create("key1", 1, "active", "persist_user", "encryption", b"wrapped_data", "2024-01-01T00:00:00Z")
    journal_append("key1", 1, 2, "pending", "2024-01-01T00:00:00Z")
    backup_create("/tmp/backup1", "manifest_hash1", "completed", "2024-01-01T00:00:00Z")
    revocation_append(1, "key1", 1, "2024-01-01T00:00:00Z", "node1", b"signature1")

    # Close and reopen
    close()
    # Don't call reset_for_testing - we want to keep the file
    initialize_schema()

    # Verify data persisted
    user = get_user("persist_user")
    assert user is not None
    assert user.user_id == "persist_user"

    records = list(audit_iter(0))
    assert len(records) == 1
    assert records[0]["actor"] == "persist_user"

    key = key_get("key1", 1)
    assert key is not None
    assert key.key_id == "key1"

    journal_entries = journal_list_for_key("key1")
    assert len(journal_entries) == 1

    backups = backup_list_all()
    assert len(backups) == 1

    rev = revocation_get(1)
    assert rev is not None
    assert rev.key_id == "key1"


def test_key_records():
    """Test key record CRUD operations."""
    create_user("key_owner", "operator", "active", 1, "2024-01-01T00:00:00Z")

    # Create
    key_create("key1", 1, "active", "key_owner", "encryption", b"wrapped_v1", "2024-01-01T00:00:00Z")
    key_create("key1", 2, "active", "key_owner", "encryption", b"wrapped_v2", "2024-01-01T01:00:00Z")
    key_create("key2", 1, "active", "key_owner", "signing", b"wrapped_v3", "2024-01-01T00:00:00Z")

    # Get specific version
    key = key_get("key1", 1)
    assert key is not None
    assert key.version == 1
    assert key.wrapped_blob == b"wrapped_v1"

    # Get latest
    latest = key_get_latest("key1")
    assert latest is not None
    assert latest.version == 2
    assert latest.wrapped_blob == b"wrapped_v2"

    # List versions
    versions = key_list_versions("key1")
    assert len(versions) == 2
    assert versions[0].version == 1
    assert versions[1].version == 2

    # Update state
    assert key_update_state("key1", 1, "revoked") is True
    key = key_get("key1", 1)
    assert key.state == "revoked"

    # Delete
    assert key_delete("key1", 1) is True
    assert key_get("key1", 1) is None
    assert key_delete("key1", 1) is False  # Already deleted


def test_rotation_journal():
    """Test rotation journal operations."""
    journal_append("key1", 1, 2, "pending", "2024-01-01T00:00:00Z")
    journal_append("key1", 2, 3, "pending", "2024-01-01T01:00:00Z")
    journal_append("key2", 1, 2, "completed", "2024-01-01T00:00:00Z")

    # Get by ID
    entry = journal_get(1)
    assert entry is not None
    assert entry.key_id == "key1"
    assert entry.from_version == 1
    assert entry.to_version == 2
    assert entry.state == "pending"

    # List for key
    entries = journal_list_for_key("key1")
    assert len(entries) == 2
    assert entries[0].from_version == 1
    assert entries[1].from_version == 2

    # Update state
    assert journal_update_state(1, "completed") is True
    entry = journal_get(1)
    assert entry.state == "completed"


def test_backup_state():
    """Test backup state operations."""
    backup_create("/tmp/backup1", "hash1", "completed", "2024-01-01T00:00:00Z")
    backup_create("/tmp/backup2", "hash2", "pending", "2024-01-01T01:00:00Z")

    backups = backup_list_all()
    assert len(backups) == 2
    assert backups[0].path == "/tmp/backup1"
    assert backups[1].path == "/tmp/backup2"

    backup = backup_get(1)
    assert backup is not None
    assert backup.manifest_hash == "hash1"

    assert backup_update_status(1, "failed") is True
    backup = backup_get(1)
    assert backup.status == "failed"


def test_revocations():
    """Test revocation operations."""
    revocation_append(1, "key1", 1, "2024-01-01T00:00:00Z", "node1", b"sig1")
    revocation_append(2, "key1", 2, "2024-01-01T01:00:00Z", "node2", b"sig2")
    revocation_append(3, "key2", 1, "2024-01-01T02:00:00Z", "node1", b"sig3")

    # Get by seq
    rev = revocation_get(1)
    assert rev is not None
    assert rev.key_id == "key1"
    assert rev.version == 1
    assert rev.signer == "node1"
    assert rev.signature == b"sig1"

    # Get latest
    latest = revocation_get_latest()
    assert latest is not None
    assert latest.seq == 3

    # Is revoked
    assert revocation_is_revoked("key1", 1) is True
    assert revocation_is_revoked("key1", 2) is True
    assert revocation_is_revoked("key2", 1) is True
    assert revocation_is_revoked("key1", 3) is False
    assert revocation_is_revoked("key3", 1) is False

    # List revocations
    revs = revocation_list_revocations("key1")
    assert len(revs) == 2
    assert revs[0].seq == 1
    assert revs[1].seq == 2

    all_revs = revocation_list_revocations()
    assert len(all_revs) == 3

    # Max seq
    assert revocation_get_max_seq() == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])