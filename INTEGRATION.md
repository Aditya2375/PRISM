# Key Identity Guard - Integration Guide

## 1. Public Functions

### kig.store

**Table: users**
| Column | Type |
|--------|------|
| user_id | TEXT PRIMARY KEY |
| role | TEXT NOT NULL |
| status | TEXT NOT NULL |
| epoch | INTEGER NOT NULL |
| created_at | TEXT NOT NULL |

**Public functions:**
- `get(user_id: str) -> Optional[User]` - Get user by ID
- `create(user_id: str, role: str, status: str, epoch: int, created_at: str) -> None` - Create user
- `update_status(user_id: str, status: str) -> bool` - Update user status
- `update_epoch(user_id: str, epoch: int) -> bool` - Update user epoch
- `seed_synthetic_users() -> None` - Create deterministic test users

**Table: audit_records**
| Column | Type |
|--------|------|
| seq | INTEGER PRIMARY KEY AUTOINCREMENT |
| ts | TEXT NOT NULL |
| actor | TEXT NOT NULL |
| action | TEXT NOT NULL |
| key_id | TEXT |
| result | TEXT NOT NULL |
| reason | TEXT |
| entry_hash | TEXT NOT NULL |
| prev_hash | TEXT NOT NULL |
| signature | BLOB |

**Public functions:**
- `append(record: dict) -> int` - Append audit record, returns seq number. Keys: ts, actor, action, key_id, result, reason, entry_hash, prev_hash, signature
- `last() -> Optional[dict]` - Get most recent record
- `iter(start_seq: int = 0) -> Iterator[dict]` - Iterate records from seq

**Table: key_records**
| Column | Type |
|--------|------|
| key_id | TEXT NOT NULL |
| version | INTEGER NOT NULL |
| state | TEXT NOT NULL |
| owner | TEXT NOT NULL |
| purpose | TEXT NOT NULL |
| wrapped_blob | BLOB NOT NULL |
| created_at | TEXT NOT NULL |
| PRIMARY KEY (key_id, version) |

**Public functions:**
- `create(key_id: str, version: int, state: str, owner: str, purpose: str, wrapped_blob: bytes, created_at: str) -> None`
- `get(key_id: str, version: int) -> Optional[KeyRecord]`
- `get_latest(key_id: str) -> Optional[KeyRecord]`
- `list_versions(key_id: str) -> List[KeyRecord]`
- `update_state(key_id: str, version: int, state: str) -> bool`
- `delete(key_id: str, version: int) -> bool`

**Table: rotation_journal**
| Column | Type |
|--------|------|
| id | INTEGER PRIMARY KEY AUTOINCREMENT |
| key_id | TEXT NOT NULL |
| from_version | INTEGER NOT NULL |
| to_version | INTEGER NOT NULL |
| state | TEXT NOT NULL |
| ts | TEXT NOT NULL |

**Public functions:**
- `append(key_id: str, from_version: int, to_version: int, state: str, ts: str) -> int`
- `get(entry_id: int) -> Optional[RotationEntry]`
- `list_for_key(key_id: str) -> List[RotationEntry]`
- `update_state(entry_id: int, state: str) -> bool`

**Table: backup_state**
| Column | Type |
|--------|------|
| id | INTEGER PRIMARY KEY AUTOINCREMENT |
| path | TEXT NOT NULL |
| manifest_hash | TEXT NOT NULL |
| status | TEXT NOT NULL |
| ts | TEXT NOT NULL |

**Public functions:**
- `create(path: str, manifest_hash: str, status: str, ts: str) -> int`
- `get(backup_id: int) -> Optional[BackupState]`
- `list_all() -> List[BackupState]`
- `update_status(backup_id: int, status: str) -> bool`

**Table: revocations**
| Column | Type |
|--------|------|
| seq | INTEGER PRIMARY KEY |
| key_id | TEXT NOT NULL |
| version | INTEGER NOT NULL |
| ts | TEXT NOT NULL |
| signer | TEXT NOT NULL |
| signature | BLOB NOT NULL |

**Public functions:**
- `append(seq: int, key_id: str, version: int, ts: str, signer: str, signature: bytes) -> None`
- `get(seq: int) -> Optional[Revocation]`
- `get_latest() -> Optional[Revocation]`
- `is_revoked(key_id: str, version: int) -> bool`
- `list_revocations(key_id: Optional[str] = None) -> List[Revocation]`
- `get_max_seq() -> int`

### kig/channel.py

**Class: Session**
- `__init__(skey: bytes, rkey: bytes, send_counter: int = 0, recv_counter: int = -1, seen_nonces: OrderedDict = None, seen_nonces_lock = None) -> None`
- `send(data: bytes) -> bytes` - Encrypt and send, returns nonce+ciphertext. Raises ValueError if closed.
- `recv(framed: bytes) -> Tuple[Optional[bytes], bool]` - Decrypt and validate. Returns (data, success). Rejects counter <= recv_counter (replay).
- `_build_nonce(direction: str) -> bytes` - Internal: build 12-byte nonce from counter.

**Transport functions:**
- `set_session(my_id: str, their_id: str, session: Session) -> None` - Store session in transport dict.
- `get_session(my_id: str, their_id: str) -> Optional[Session]` - Retrieve session.
- `remove_session(my_id: str, their_id: str) -> None` - Remove session.

**Handshake functions:**
- `execute_handshake_initiator(my_id: str, their_id: str, long_term_sk: bytes, their_kem_sk: bytes) -> Optional[Session]`
- `execute_handshake_responder(my_id: str, their_id: str, long_term_sk: bytes, client_hello_parsed: Dict, their_kem_sk: bytes) -> Optional[Session]`
- `handshake(peer_info: Dict) -> Optional[Session]` - Full handshake. peer_info keys: node_id, their_id, long_term_sk, their_kem_sk, is_initiator.

**Crypto helpers (internal):**
- `_split_sig_priv(sk: bytes) -> Tuple[bytes, bytes]` - Split hybrid SK into Ed25519+ML-DSA parts.
- `_derive_ed25519_pk_from_sk(sk: bytes) -> bytes` - Derive Ed25519 pub key from hybrid SK.
- `_derive_sig_pk_from_sk(sk: bytes) -> bytes` - Derive hybrid pub key (32+1952=1984 bytes).

### kig/node_network.py

**Class: Node**
- `__init__(node_id: str, long_term_sk: bytes)` - Initialize node with signing key.
- `revoke(target_id: str, reason: str = "") -> Dict` - Revoke target node. Returns cert dict with: revoker_id, target_id, seq, timestamp, reason, signature.hex().
- `heal() -> Set[str]` - Synchronize revoked set with all transport nodes. Returns unified revoked set.
- `heartbeat(target_id: str) -> None` - Send heartbeat (no-op in single-threaded mode).
- `get_revoked() -> Set[str]` - Return local revoked set.

**Class: NodeNetwork**
- `__init__() -> None` - Initialize 3-node network (node1, node2, node3) with fully-connected transport.
- `revoke_node(revoker_id: str, target_id: str, reason: str = "") -> Optional[Dict]` - Revoke via specified node.
- `heal_network() -> Set[str]` - Synchronize across all 3 nodes. Returns unified revoked set.
- `get_revoked() -> Set[str]` - Return all revoked node IDs across network.
- `is_revoked(node_id: str) -> bool` - Check if node is revoked.
- `execute_handshake(initiator_id: str, responder_id: str) -> Optional[Session]` - Create session between two nodes.

### kig/detector.py

**Class: Alert**
- `__init__(rule: str, actor: str, ts: str, detail: str)` - Alert representation. `__repr__` shows all fields.

**Class: AnomalyDetector**
- `__init__(access_hour_cutoff: int = 22, failed_fetch_threshold: int = 5, burst_threshold: int = 10, window_seconds: int = 60) -> None`
  - `access_hour_cutoff`: Hours >= cutoff are anomalous (default 22, meaning 22:00-23:59 and 00:00 if cutoff>=23).
  - `failed_fetch_threshold`: N failed fetches within W seconds to trigger (default 5).
  - `burst_threshold`: M fetches within W seconds to trigger burst (default 10).
  - `window_seconds`: W window in seconds (default 60).
- `observe(event: dict) -> List[Alert]` - Process event, return triggered alerts. Event shape: `{"actor": str, "ts": str (ISO), "key_id": str, "action": str, "result": str}`.
- `metrics() -> dict` - Return `{"total_events": int, "alerts_per_rule": dict, "alerts_per_actor": dict, "first_alert_latency": dict, "num_actors_tracked": int, "num_rules_triggered": int}`.
- `reset() -> None` - Reset all state for testing.

## 2. Table Columns Summary

| Table | Columns |
|-------|---------|
| users | user_id, role, status, epoch, created_at |
| audit_records | seq, ts, actor, action, key_id, result, reason, entry_hash, prev_hash, signature |
| key_records | key_id, version, state, owner, purpose, wrapped_blob, created_at |
| rotation_journal | id, key_id, from_version, to_version, state, ts |
| backup_state | id, path, manifest_hash, status, ts |
| revocations | seq, key_id, version, ts, signer, signature |

## 3. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KIG_DB_PATH` | `/tmp/kig.db` | Path to SQLite database file. Used by `kig.store.db.get_db_path()`. |

No other environment variables are required at runtime. The code is sandbox-safe with no network calls.

## 4. 3-Node Revocation Example

```python
from kig.node_network import NodeNetwork

# Create the 3-node network
network = NodeNetwork()

# Node 1 revokes node 3
cert = network.revoke_node("node1", "node3", "misbehavior")
print(f"Revoked: {cert['target_id']} by {cert['revoker_id']}")

# Check global revoked set
print(f"Revoked nodes: {network.get_revoked()}")

# Heal synchronizes state across all nodes
revoked = network.heal_network()
print(f"After heal: {revoked}")

# Node 2 revokes node 2 (different revoker)
network.revoke_node("node2", "node2", "policy violation")
print(f"Now revoked: {network.get_revoked()}")

# Final heal
revoked = network.heal_network()
print(f"Final revoked: {revoked}")
```

## 5. Detector observe(event)

Call `detector.observe(event)` where `event` is a dict with these keys:
- `actor` (str): The actor performing the action
- `ts` (str): ISO timestamp string (e.g., `"2024-01-15T14:30:00Z"`)
- `key_id` (str): Key identifier associated with the event
- `action` (str): Action name (e.g., `"fetch"`, `"download"`)
- `result` (str): Outcome, e.g., `"success"` or `"failure"`

Example:
```python
alerts = detector.observe({
    "actor": "alice",
    "ts": "2024-03-15T23:35:00Z",
    "key_id": "key-42",
    "action": "fetch",
    "result": "failure"
})
# Returns list of Alert objects (may be empty if no thresholds triggered)
```

## 6. crypto_local.py Module Mapping

If replacing `kig/crypto_local.py` with a different crypto module, rename/adapt these functions:

| Current Name | Purpose | Replacement Action |
|-------------|---------|-------------------|
| `kem_keygen() -> Tuple[KEMPublicKey, KEMPrivateKey]` | Generate KEM key pair (X25519+ML-KEM-768) | Rename/adapt to match your KEM keygen signature |
| `kem_encaps(pk: KEMPublicKey) -> Tuple[KEMCiphertext, KEMSharedSecret]` | Encapsulate shared secret to peer's KEM public key | Rename/adapt |
| `kem_decaps(sk: KEMPrivateKey, ct: KEMCiphertext) -> KEMSharedSecret` | Decapsulate shared secret from ciphertext | Rename/adapt |
| `sig_keygen() -> Tuple[SIGPublicKey, SIGPrivateKey]` | Generate hybrid signature key pair (Ed25519+ML-DSA-65) | Rename/adapt |
| `sign(sk: SIGPrivateKey, msg: bytes) -> Signature` | Sign message with hybrid Ed25519+ML-DSA | Rename/adapt |
| `verify(pk: SIGPublicKey, msg: bytes, sig: Signature) -> bool` | Verify hybrid signature (both Ed25519 AND ML-DSA must pass) | **Critical**: Your verify must return True only if BOTH sub-signatures verify. The current code uses `ed25519_pk.verify(ed25519_sig, msg)` AND `_ml_dsa_65.verify(ml_dsa_pk, msg, ml_dsa_sig)`. |
| `_split_sig_priv(sk: bytes) -> Tuple[bytes, bytes]` | Split hybrid SK into Ed25519 (32 bytes) and ML-DSA (4032 bytes) parts | Rename/adapt |
| `_split_sig_pk(pk: bytes) -> Tuple[bytes, bytes]` | Split hybrid PK into Ed25519 (32 bytes) and ML-DSA (1952 bytes) parts | Rename/adapt |
| `_split_sig(sig: bytes) -> Tuple[bytes, bytes]` | Split hybrid sig into Ed25519 (64 bytes) and ML-DSA (3309 bytes) parts | Rename/adapt |
| `kem_encaps` / `kem_decaps` shared secret format: `32 bytes (X25519) + 32 bytes (ML-KEM)` | KEM shared secret format | Adjust if your KEM uses different split |
| Signature format: `64 bytes (Ed25519) + 3309 bytes (ML-DSA-65)` | Hybrid signature format | Adjust if using different DSA variant |
| Public key format: `Ed25519 (32 bytes) + ML-DSA (1952 bytes) = 1984 bytes` | Hybrid public key format | Adjust if using different DSA variant |

The most critical adaptation is the `verify` function, which must check both the Ed25519 and ML-DSA sub-signatures and return True only if both pass.

## 7. Requirements

```
cryptography==50.0.2
kyber_py==1.2.0
dilithium_py==1.5.1
```

These are the exact versions tested and known to work. Install with:
```
pip install cryptography==50.0.2 kyber_py==1.2.0 dilithium_py==1.5.1
```

## 8. Run All Tests

```bash
python -m pytest tests/
```

Or individually:
```bash
python -m pytest tests/test_store.py tests/test_detector.py tests/test_channel.py tests/test_node_network.py
```

All 29 tests must pass.