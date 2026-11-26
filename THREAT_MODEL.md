# Threat model (one page)

## Protected assets
1. File contents (confidentiality and integrity).
2. File keys (DEKs) and each device's private keys.
3. The identity directory: users, roles, device status.
4. The audit log (integrity and completeness).

## Attackers considered
- **Thief of a lost device**, holding its private keys but not the owner's other devices.
- **Network attacker** who can read, replay and modify requests (not break TLS or the crypto).
- **Malicious or compromised member** trying to read files outside their ACL or become admin.
- **Insider with database access** trying to edit or delete audit entries.
- **Harvest-now-decrypt-later attacker** who records ciphertext and wrapped keys today.

## Controls
| Threat | Control |
| --- | --- |
| Lost device keeps working | `report_lost` and `revoke_device` delete its wrapped keys at once; its signed requests are denied and raise R1 |
| Old key still decrypts new data | next authorised read rotates to a fresh DEK and epoch; wraps are bound to file, device and epoch |
| Replay and forgery | signature over the whole envelope, 30 s freshness window, per-device nonce, refusal of requests signed before a restart |
| Lockout abuse (DoS by claiming a victim's id) | there are no lockouts: failed authentication raises an alert and is log-bounded, so an attacker cannot lock a victim out, and a client retrying its own envelope is not penalised |
| Privilege escalation | admin-only role changes, last admin cannot be demoted, every promotion alerts (R4) |
| Audit tampering | each entry is hash-chained and signed with ML-DSA; the service refuses to start on a broken chain or when the log is shorter than the number of entries state.json has seen. State is saved after every logged event. This is NOT tamper-evidence for the log tail: someone with write access to the data directory can cut the tail and rebuild `audit.head` and state without any key if they also have the service key, and `audit.head` is only a copy of the last entry. The real control is an external head: print `verify-log` output or the backup manifest head after each backup or at shutdown, keep it off the host, and check with `verify-log --expect-head` |
| Quantum adversary | hybrid ML-KEM-768 + X25519 key wrapping, ML-DSA-65 signatures |
| Crash mid-revocation | audit entry is written before state; on restart, removals found in the audit log are re-applied (fails closed) |

## Assumptions
- The service host and its `data/` directory (signing key, operator token) are not compromised.
- Transport is TLS-protected in deployment (the demo binds to localhost).
- Device clocks are within 30 s of the service.
- Libraries (`cryptography`) are correct. No custom primitives are used.

## Known limits (stated honestly)
- **A revoked device keeps anything it already decrypted or copied.** Rotation protects future versions only.
- **The service is trusted for the device directory.** A compromised service could hand clients a wrong public key when files are shared. Not mitigated here (key fingerprints out-of-band would be the fix).
- **Private keys sit on the device in a file** (mode 0600) in this prototype. No hardware keystore.
- **Nonces are kept in memory.** A restart is covered by refusing older timestamps; a multi-node deployment would need a shared store.
- **Metadata is visible to the service:** file ids, ACLs, device ids, access times.
- **Rule-based detection only.** It catches the listed patterns, not novel behaviour. No ML by design.
- **Single-node, single-file-store.** State is one JSON file with atomic replace; throughput and file size (5 MB cap) are prototype-grade.
- **Availability:** a stolen request cannot lock out a victim's device. Nobody is locked out by failures. Valid-signature traffic has a per-device budget (240/min). Failed or unauthenticated requests share a per-source budget (1200/min) and a small pre-auth log budget. Events after a valid signature (revoked device use, replay, stale, wrong audience) are logged per device and never share the anonymous budget. A 10,000 file cap bounds state size. Signature checks still cost CPU, so a distributed flood can slow the service.
- **Behind a proxy:** with `KIG_TRUSTED_PROXY=1` the source is the address the trusted proxy appended (hop `KIG_PROXY_HOPS` from the right, default 1). Never enable it without a proxy that overwrites or appends X-Forwarded-For.
- **Retries:** an identical envelope resent from the same source gets a 409 `replay` with no cached result; the client should build a new envelope.
- **Owner/admin compromise:** a compromised owner or admin device can still overwrite or wipe a file (the previous version is kept for 30 s only). The server cannot verify wraps or ciphertext it is given. `needs_rotation` is serviced only when an owner or admin device holding a wrap fetches the file, and `can_rotate` is supplied by the server, so after a revocation the old key can stay live until then. `rotate-pending` (CLI) walks every flagged file for that purpose. An admin must be in the file's ACL to rotate, so a file whose owner lost every device is unrecoverable by design.
- **Replica restore:** snapshots carry a restore generation and the audit length. Replicas accept a snapshot only if (generation, length) is strictly greater than what they hold, so a primary restored from an older backup converges. Pass `live_dir` to restore so the generation is bumped above the surviving directory's; without it the generation is the backup's own plus one.
- **Bootstrap crash:** `bootstrap` saves state before it logs, so a crash in between leaves a working directory whose first audit entries (`service.bootstrapped`, `device.enrolled`) may be missing from the log. Nothing else is lost.
- **Proxy:** `KIG_TRUSTED_PROXY=1` is only safe when the service port is reachable only through your proxy; otherwise a client can send its own X-Forwarded-For and pick its source address. `KIG_PROXY_HOPS` must be an integer from 1 to 16 or the service refuses to start.
- **Client trust in the server:** the client uses the ACL and device directory the server supplies, so a malicious server can add recipients to future wraps. Out-of-band fingerprints would be the fix.
- **Revoke scope:** any active device of a user can revoke all other devices of that user, by design (lost-phone recovery from the laptop).
- **Write roles:** ACL members read. Only the file owner or an admin can write or rotate. Each version carries a key-commitment tag, so a wrong key is rejected rather than decrypting garbage.
- **Backup memory:** backup and restore hold the whole payload in RAM (about 2.7x the data size). Streaming is not implemented.
