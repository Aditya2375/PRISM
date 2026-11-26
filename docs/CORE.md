# P.R.I.S.M. core: keys, vault, rotation, recovery, backup, storage

P.R.I.S.M. (Post-quantum Resilient Identity & Security Management). This page covers the
key-management core. Behaviour described here is covered by tests; the test name is given
where a claim could be doubted.

## Key hierarchy
| Key | Algorithm | Where it lives |
| --- | --- | --- |
| File key (DEK), one per file version | random 256-bit, AES-256-GCM | never on the server; wrapped per device |
| Device wrap key | X25519 + ML-KEM-768 hybrid, library HPKE suite | device key file |
| Device and server signing keys | ML-DSA-65 | device key file, `server_sign.key` |
| Backup key | X25519 + ML-KEM-768 hybrid | offline, operator held |

All primitives come from `cryptography==50.0.2` (event minimum: 50.0.2). There is no hand-written combiner: the hybrid
KEM is the library's standard `MLKEM768_X25519` HPKE suite with HKDF-SHA256 and
ChaCha20-Poly1305. Binding data (file id, device id, version, purpose) goes in the HPKE `info`
input and in the AEAD associated data of the layer above, so a wrap cannot be moved to another
file, device or version.

## Vault (keys at rest)
Device, server and backup secret keys can be sealed with a passphrase (`PRISM_PASSPHRASE` or an
explicit argument): scrypt (N=2^15, r=8, p=1) into AES-256-GCM, with the header authenticated.
Files are written atomically with fsync, mode 0600. Wrong passphrase, any flipped byte, a swapped
label or hostile KDF parameters are all refused (`tests/test_vault.py`).

## Rotation
* Versions are monotonic integers. A rotation is a compare-and-set on the version the client read.
* Journal: `file.rotate_prepared` is appended (signed, fsynced), the new version is stored and the
  state committed, then `file.rotated` closes it. On restart any prepare without a close is
  resolved from state to `file.rotate_recovered` or `file.rotate_aborted`.
* In-flight transfers get a fixed **30 s** grace: the previous version stays readable, only for
  devices that were still eligible. After the cutoff the node answers `key_version_retired`.
  A revoked device gets no grace.
* A client remembers the newest version it has seen and refuses an older one (rollback check).
  With `state_path` it persists this across restarts. The check is skipped only when the caller
  passes an explicit `epoch=`; a server-sent grace field never bypasses it.
* Only a file's owner or an admin can write or rotate it. ACL members read. Each version carries a
  key-commitment tag (HMAC of the file key over file id and version), so a wrong or substituted
  key is refused. A client auto-rotates only when the server says `can_rotate`.
* Enrolling a device flags files shared with that user `needs_rotation`.

### Crash matrix (`tests/test_crash_and_cutoff.py`, `tests/test_chaos.py`)
| Kill point | After restart |
| --- | --- |
| before prepare | version unchanged, nothing journaled |
| after prepare | version unchanged, prepare closed as aborted |
| mid commit (state saved, commit record missing) | new version active, prepare closed as recovered |
| after commit | new version active |
| after revoked-set journal / after audit append / before state rename (revocation) | device stays revoked |

Each case asserts one consistent active version, the revoked set never shrinks, the audit chain
verifies and the data still decrypts. `test_chaos.py` repeats this with random operations and random
kill points over 12 seeds.

## Revocation durability
The revoked set is its own append-only file, fsynced before anything else and checked first. It is
union-only: restoring an older `state.json` cannot bring a device back, because the revoked set is
re-applied at start-up. A torn last line is truncated at load (it was never acknowledged), so the
next record is never glued to it. Restoring an older *backup* is guarded separately (see below);
the file itself is not tamper-proof against someone who can rewrite the whole data directory.
Replica fields (`snapshot_version`, `epoch_floor`) are persisted in the signed state.

## Storage
* `state.json` is a full snapshot (users, devices, files with their wrapped keys), signed with ML-DSA, written
  by temp file, fsync, atomic rename and directory fsync. `state.wal` is an append-only journal: each line holds
  only the records that changed, is signed on its own, names the snapshot it extends and the hash of the line
  before it. Start-up verifies the snapshot, then every line (signature, snapshot id, sequence, hash chain) and
  replays them. A bad signature, a line changed, reordered or removed from the middle stops start-up
  (`StateCorrupt`). A torn last line was never acknowledged and is cut off. A new snapshot is written after
  1000 lines or 16 MB, which keeps replay short (`kig/store.py`, `tests/test_store.py`).
* Changed records are found by the state containers themselves (nested edits are noticed), and a test reloads
  the directory after random operations and compares it with memory.
* `blobs/xx/<sha256>`: ciphertext, content addressed, fsynced before the state that references it,
  verified against its hash on every read (`storage_corrupt` fails closed and is logged). The
  previous version is removed after the next rotation; orphans from a crash are deleted at start-up.
* Reads do not rewrite state. Measured on 300 files of 2 KB (this machine): fetch 2.6 ms, put 8 ms,
  rotate 17 ms.

## Backup and restore
A backup is a standard tar archive: `manifest.json`, `meta.sealed.json` and `blobs/<sha256>`. The metadata
(state, audit log, revoked set) is sealed with a random AES-256-GCM key that is wrapped to the backup public
key. Blobs are already ciphertext made on the clients and are named by their hash, so they are copied from disk
one file at a time, not re-encrypted. The manifest lists every blob hash, a monotonic counter, the audit length
and head and the hash of the sealed metadata, and is ML-DSA signed with the service key. Restore verifies the
signature, the metadata tag, the audit chain and a streamed hash of every blob before writing anything, and
only into an empty directory. Only the three expected member kinds are accepted (no paths, links or extras).
Memory follows the size of the metadata, not of the stored data (`test_backup_memory_does_not_grow_with_blob_size`
holds a 30 MB backup under 12 MB of peak allocations). The service pauses writes while a backup is built. An older valid backup is refused
unless `allow_older` is set. Restore needs evidence for two guards, or an explicit `accept_rollback`:
the counter (`min_counter`, the highest counter you know, or `live_dir`) and the live revoked log
(`live_revoked_log`). `accept_counter_rollback` and `accept_lost_revocations` waive them separately
(`accept_rollback` is both); what was waived is written into the restored audit chain as
`restore.completed`. The counter is kept in the signed state, so deleting `backup.counter`
does not reset it. **Record each backup counter outside the data directory**; without it nothing
can tell a stale backup from a fresh one. The service key is opened and matched to its public key
before anything is written; the directory is built as `dest.partial` and renamed, and removed on
failure. A restored `revoked.log` is timestamped with the backup creation time. 200 random single-byte
flips are all rejected (`tests/test_backup.py`).

## Limits
* A revoked device keeps what it already decrypted. Rotation protects later versions only.
* The server is trusted for the device directory (no out-of-band fingerprint check).
* Python cannot wipe key material from memory. A passphrase in the environment is visible to the
  process owner. A hardware keystore would be the production answer.
* Write access is owner or admin only; there are no per-user write grants. The client trusts the ACL
  and device directory the server returns, so a malicious server could add recipients to future wraps.
* Any active device of a user can revoke all other devices of that user, by design.
* The log is checked at start-up against the number of entries `state.json` has seen (state is saved
  after every logged event) and the `audit.head` copy of the last entry. That catches accidents, not
  an attacker with write access to the directory. Keep a head outside the host (printed after each
  backup or at shutdown) and check it with `verify-log --expect-head`.
* Failed authentication never locks anyone out. R2 and R3 alert only. Valid-signature traffic is
  limited per device (240/min). Failed requests share a per-source budget (1200/min) and a small
  pre-auth log budget; events after a valid signature (revoked device, replay, stale) are logged per
  device and are never crowded out by anonymous noise. 10,000 file cap.
* Owner or admin compromise, server-supplied `can_rotate`, and unrecoverable files (an admin must be in
  the ACL): see THREAT_MODEL.md. `python -m kig.cli rotate-pending` re-keys every flagged file.
* After a valid signature the first log line per device and class is always written; extras share a
  global cap of 300 per minute.
* An identical retried envelope gets 409 with no cached result. Replicas accept a snapshot only if
  (restore generation, audit length) strictly advances, so a restored primary converges.
* Backup holds the metadata (state, audit log) in memory while sealing it, so memory grows with the number of
  files and audit entries, not with blob bytes.
* A write costs time proportional to the size of the changed records, not the number of files: `put_file` took
  5.6 to 7.4 ms at 300, 600, 900, 1200 and 1500 files (it was 24.5 to 99.9 ms with whole-state rewrites).
  Every 1000 journal lines a full snapshot is written, a pause that grows with total state size. Start-up
  reads all records. The audit log is the witness for the journal: if, after replay, the audit log is ahead of
  state by more than the one command that could have been in flight (more than two state-changing entries),
  start-up refuses (`StateCorrupt`), so deleting or truncating `state.wal`, or restoring an older copy, is caught
  and no blobs are garbage-collected. Not caught: removing only the last command or two, which looks like a
  crash before acknowledgement. Revocations survive that either way, because `revoked.log` is separate.
  An unterminated last journal line is dropped even if it parses, because it was never acknowledged.
  `peek_meta` (used for backup counters of a surviving directory) reads unverified values and can only cause
  a refusal or a needless override, never a wrong restore. Replica nodes write their whole epoch map with every
  journal line, so replica writes cost grows with the number of files.
* Single host. The cluster nodes in `kig/cluster.py` are in-process simulations with their own data
  directories, not separate machines.
