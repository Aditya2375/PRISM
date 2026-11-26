# P.R.I.S.M. core: keys, vault, rotation, recovery, backup, storage

P.R.I.S.M. (Post-quantum Resilient Identity & Security Management). This page covers the
key-management core. Behaviour described here is covered by tests; the test name is given
where a claim could be doubted.

## Key hierarchy
| Key | Algorithm | Where it lives |
| --- | --- | --- |
| File key (DEK), one per file version | random 256-bit, AES-256-GCM | never on the server; wrapped per device |
| Device wrap key | X25519 + ML-KEM-768 hybrid, library HPKE suite | device key file |
| Device and server signing keys | ML-DSA-65 | device key file, `server_sign.key` or a `KeyStore` (see Key storage interface) |
| Backup key | X25519 + ML-KEM-768 hybrid | offline, operator held |

All primitives come from `cryptography==50.0.2` (event minimum: 50.0.2), except the optional k-of-n key split, which
uses PyCryptodome's Shamir (see below). There is no hand-written combiner: the hybrid
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
* The server is trusted for the device directory at first contact. The fingerprint check is optional, and clients pin writers after first sight (see Signed manifest).
* Python cannot wipe key material from memory. A passphrase in the environment is visible to the
  process owner. A hardware keystore would be the production answer.
* Write access is owner or admin only; there are no per-user write grants. A malicious server cannot forge a
  signed manifest, but it can withhold updates, and it still decides which devices receive wraps for a device no client has seen.
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
  state by more than the last single command (more than one state-changing entry),
  start-up refuses (`StateCorrupt`), so deleting or truncating `state.wal`, or restoring an older copy, is caught
  and no blobs are garbage-collected. Not caught: removing only the last single command, which looks like a
  crash before acknowledgement. Revocations survive that either way, because `revoked.log` is separate.
  An unterminated last journal line is dropped even if it parses, because it was never acknowledged.
  `peek_meta` (used for backup counters of a surviving directory) reads unverified values and can only cause
  a refusal or a needless override, never a wrong restore. Replica nodes write their whole epoch map with every
  journal line, so replica writes cost grows with the number of files.
* Single host. The cluster nodes in `kig/cluster.py` are in-process simulations with their own data
  directories, not separate machines.

## Measured cost (`python -m kig.bench`)

One run on a development machine (Python 3.10, in-process service, 2 KB files, medians, times in ms; stores above 800 files are spread over several owners because one owner is limited to 1,000 files):

| files | put | fetch | rotate | backup | restore | backup peak RAM | restore peak RAM | start-up replay |
|---|---|---|---|---|---|---|---|---|
| 100 | 10.0 | 3.9 | 18 | 80 | 159 | 11 MB | 13 MB | 63 |
| 900 | 12.0 | 4.6 | 22 | 579 | 1103 | 73 MB | 86 MB | 428 |
| 2000 | 11.8 | 4.1 | 21 | 1101 | 2493 | 134 MB | 159 MB | 313 |

Put, fetch and rotate stay flat as the store grows (journaled state). Backup and restore are linear in time,
and their memory grows with the number of files, because the sealed state metadata (about 7 KB per file with four
devices) is built in memory. Blob bytes are streamed and do not add to peak memory. Treat the memory column as
a known limit for stores beyond a few thousand files.

## Enrolment fingerprint

`Device.fingerprint()` is a SHA-256 over the device id, user and both public keys (length-prefixed), printed as
8 groups of 8 hex digits. The enrolling person reads it from their own device. The admin passes it as
`expect_fingerprint` to `enroll_device`, and the service refuses with `fingerprint_mismatch` if the keys it
received hash differently, which is what a swap of keys in transit produces. The fingerprint and whether it was
checked are written to the audit entry. The check only helps if the fingerprint is compared over a channel the
attacker does not control, and it is optional: without `expect_fingerprint` the enrolment is recorded as
`verified: false`. The signed per-version manifest (below) covers what happens after enrolment.

## `kig doctor`

`python -m kig.cli doctor --data DIR` is read-only and never creates files, so it can run next to a live server.
It checks a temporary copy (blobs linked), opened exactly as start-up does: crash recovery, the journal-behind-audit
check and the audit chain run there. On the original it then hashes every referenced blob, lists orphan blobs
(it does not delete them) and checks permissions. A path without PRISM data is a FAIL. Exit code 1 on any FAIL.

## Demo

`python -m kig.demo` is the lost-device story. `python -m kig.demo --story` adds a blob tamper, an edited audit
copy, a crash in the middle of a rotation with recovery on restart, and a claim-to-evidence table. It exits 1 if
any of those checks fails. Step 6 shows per-node revocation timings on the simulated three-node cluster.

## Enrolling a device from the command line

On the new device: `python -m kig.cli keygen --user U --device D --out key.json > pub.json`. The command prints the
public keys to stdout and the fingerprint to stderr. The new device's owner reads the fingerprint to the admin over
a channel the server does not control. The admin runs
`python -m kig.cli enroll --url URL --key admin.json --pub pub.json --expect-fingerprint FP`. Case, dashes and
spaces in FP do not matter. `--unverified` is the only way to skip the comparison, and the audit entry then says so.

`doctor` needs the passphrase env var if the server key is sealed. Run against a live server it can show a transient
FAIL if it copies a file mid-write; run it again before believing a FAIL.

## Signed manifest per file version

Every write (`put_file`, `rotate`) carries `manifest_sig`: an ML-DSA-65 signature, by the writing device, over
`{file, epoch, acl, owner, commit, writer, writer_user}` (domain-separated purpose `manifest`). The service refuses a
write whose signature does not match what it is about to commit and stores it with the version (the previous version
keeps its own for the grace window). `fetch` returns the signature, the writer's id, user and public key, and the
enrolment proof for that writer. The client checks all of it before it unwraps anything.

When the client has a `state_path` (the shipped CLI sets one next to the key file), it keeps a `.pins` file:
the first writer key and owner it sees for each file are pinned (trust on first use; the enrolment fingerprint is
the out-of-band check for that key). A later writer for the same file is accepted only with the `enroll_device`
request that an already pinned writer of that file signed (the service keeps that signed request as the proof).
A writer is also checked for authority: its user must be the file's owner, or an admin proven by the `create_user` /
`set_role` request (role admin) that the owner, or an admin already proven, signed with a pinned writer device of
this file. A member cannot write a version the client will accept. Known limit: the bootstrap admin has no such
signed request, so a bootstrap admin who is not the file's owner is refused by clients that pinned the owner; the
owner (or an admin the owner created) has to rotate that file. A changed owner, a changed key for a pinned writer, or an unproven new writer is refused.

What this stops: someone with the service's signing key or write access to its disk, but no device key, cannot add a
user to a file's ACL, change its owner or key commitment, invent a writer device, or present an older version's
signature on a newer one. Earlier builds accepted any writer key the service supplied; this closes that.
What it does not stop: first contact is trust on first use. The service is still trusted for who receives key wraps
and for availability. The manifest covers the key commitment, which is bound to the ciphertext by the AEAD and the
reader's key check, but it does not sign a hash of the ciphertext itself. Without a `state_path` (library use
without persistence) pins last only as long as the Client object. Files without a manifest are refused. The frozen
fixtures hold throwaway private keys on purpose.


## Standalone verifier

`verifier/prism_verify.py` checks evidence without the service and without importing any of its code (a test checks
the imports). It needs Python and the `cryptography` package, reads files only and needs no private key:

```
python verifier/prism_verify.py audit  --log data/audit.jsonl --pub data/server_sign.pub --anchor data/audit.head [--expect-head HASH]
python verifier/prism_verify.py backup --file x.bak --pub data/server_sign.pub
python verifier/prism_verify.py state  --file data/state.json --pub data/server_sign.pub
```

`audit` rejects entries with fields outside the signed set, rejects an empty log, and re-derives every entry hash and checks every signature, the links, the sequence and the head anchor if one is given. With no
`--expect-head` it exits 2 and says completeness is not established. `backup` checks the manifest signature, the signed blob list and every blob's
hash, without the backup key (it does not open the sealed metadata). `state` checks the signed snapshot. It does not
check that the journal after the snapshot is complete (the service does that at start-up). Tail removal can only be
excluded with a head or anchor recorded outside the directory. The format rules are written out a second time in
this file from the docs, which is the point: a bug in the service's own checker cannot hide a bad log.

## Splitting the backup private key (k of n)

`kig backup-key split --key backup.key -k 3 -n 5 --out-dir shares/` writes n share files (0600) and prints one
fingerprint per share; record those elsewhere. `kig backup-key combine --shares a.json b.json c.json --out backup.key`
recovers the key. `kig/threshold.py` contains no secret-sharing maths. A random 32-byte wrapping key seals the secret
with AES-256-GCM (`cryptography`); the wrapping key is split as two 16-byte halves with PyCryptodome's Shamir
(`Crypto.Protocol.SecretSharing`, pinned in `requirements.txt`) at the same indices, so the AES key keeps its full 256
bits. Fields are validated before Shamir sees them (a share index of -1 once made the library loop forever). Each
share carries a fingerprint of its own bytes. The fingerprint catches accidents only, since anyone can recompute it. Damaged
shares are named and skipped; when more than k shares are offered and one fails to open, combine leaves out one share at
a time, then two (200 attempts), then tries up to 3000 random subsets of k (every subset when there are fewer than that).
AES-GCM tells it when a subset is right. The exact condition: if C(offered,k) is at most 3000, every subset is tried and
recovery succeeds whenever k honest shares are offered. Above that it samples 3000 subsets, seeded from the shares so
the same input always gives the same result, and succeeds with probability 1-(1-p)^3000 where p = C(honest,k) / C(offered,k).
It can miss a rare honest subset (for example 14 bad of 30 with k=15 almost surely fails); the error says the search
was bounded. A failing search takes around ten seconds. A stray share from
another split is ignored if exactly one set has enough intact shares; if two sets do, it refuses. The CLI refuses to
overwrite existing share files or an existing output key unless `--force` is given, and creates the share directory 0700. Limits: the sealed secret is repeated in every share; no verifiable sharing, so a forged share with a
matching fingerprint is found only by trying subsets; the library is one we use and did not audit.

## Key storage interface

`kig/keystore.py` defines `KeyStore` (`get(name)`, `put(name, secret)`). `GuardService(dir, keystore=...)` then keeps
the signing key there instead of in `server_sign.key`. We ship `FileKeyStore` (0600 files, sealed by the passphrase
vault when a passphrase is set) and `MemoryKeyStore` (tests). We ship no HSM or KMS driver: the interface is the seam
for one, and it is not a claim of hardware protection. On every start the public key is derived from the stored signing seed and `server_sign.pub` must equal it,
otherwise start-up refuses (StateCorrupt); with a key store a missing public file is rewritten from the seed. If the
store has no key but the public file exists, start-up refuses rather than generating a new key. First creation runs under
an exclusive file lock (`.keylock`), the secret is stored before the public file, and temp files are random, exclusive
and never follow symlinks. Exclusive writes use a hard link; on a filesystem without hard links they check and then
rename (content is never partial, but two writers racing at the same instant could collide). `FileKeyStore` without a passphrase stores the key unencrypted (mode 0600) and logs a warning. Backup and the CLI still use their own key files.
