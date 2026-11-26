# PRISM core: keys, vault, rotation, recovery, backup, storage

PRISM (Post-quantum Resilient Identity & Security Management). This page covers the
key-management core. Behaviour described here is covered by tests; the test name is given
where a claim could be doubted.

## Key hierarchy
| Key | Algorithm | Where it lives |
| --- | --- | --- |
| File key (DEK), one per file version | random 256-bit, AES-256-GCM | never on the server; wrapped per device |
| Device wrap key | X25519 + ML-KEM-768 hybrid, library HPKE suite | device key file |
| Device and server signing keys | ML-DSA-65 | device key file, `server_sign.key` |
| Backup key | X25519 + ML-KEM-768 hybrid | offline, operator held |

All primitives come from `cryptography>=50.0.2`. There is no hand-written combiner: the hybrid
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
union-only: restoring an older state or backup cannot bring a device back. A torn last line is
ignored because it was never acknowledged.

## Storage
* `state.json`: metadata and wrapped keys, signed with ML-DSA, written by temp file, fsync, atomic
  rename and directory fsync. A bad signature stops start-up (`StateCorrupt`).
* `blobs/xx/<sha256>`: ciphertext, content addressed, fsynced before the state that references it,
  verified against its hash on every read (`storage_corrupt` fails closed and is logged). The
  previous version is removed after the next rotation; orphans from a crash are deleted at start-up.
* Reads do not rewrite state. Measured on 300 files of 2 KB (this machine): fetch 2.6 ms, put 8 ms,
  rotate 17 ms.

## Backup and restore
Canonical payload (state, audit log, revoked set, blobs), sealed with a random AES-256-GCM key that is
wrapped to the backup public key, then ML-DSA signed together with a manifest holding a monotonic
counter, payload hash and audit head. Restore verifies signature, tag, hashes, audit chain and blob
hashes before writing anything, and only into an empty directory. An older valid backup is refused
unless `allow_older` is set, and the live revoked set is always unioned in. 200 random single-byte
flips are all rejected (`tests/test_backup.py`).

## Limits
* A revoked device keeps what it already decrypted. Rotation protects later versions only.
* The server is trusted for the device directory (no out-of-band fingerprint check).
* Python cannot wipe key material from memory. A passphrase in the environment is visible to the
  process owner. A hardware keystore would be the production answer.
* Any member of a file's ACL can rotate it, which includes replacing its content. Per-file write
  roles are not implemented.
* Every mutation rewrites `state.json`, so write cost grows with the number of files. Fine for the
  prototype scale measured above, not for millions of files.
* Single host. The cluster nodes in `kig/cluster.py` are in-process simulations with their own data
  directories, not separate machines.
