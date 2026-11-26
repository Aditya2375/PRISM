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
| Audit tampering | each entry is hash-chained and signed with ML-DSA; the service refuses to start on a broken chain or when the log is shorter than the fsynced head anchor (`audit.head`). The anchor catches accidental truncation; an attacker who can rewrite the whole data directory can roll back log and anchor together, so record the head outside it (`verify-log --expect-head`) |
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
- **Availability:** a stolen request cannot lock out a victim. Per-device (240/min) and per-source (1200/min) rate limits, a 10,000 file cap and bounded audit logging limit abuse, but a distributed flood can still burn CPU.
- **Client trust in the server:** the client uses the ACL and device directory the server supplies, so a malicious server can add recipients to future wraps. Out-of-band fingerprints would be the fix.
- **Revoke scope:** any active device of a user can revoke all other devices of that user, by design (lost-phone recovery from the laptop).
- **Write roles:** ACL members read. Only the file owner or an admin can write or rotate. Each version carries a key-commitment tag, so a wrong key is rejected rather than decrypting garbage.
- **Backup memory:** backup and restore hold the whole payload in RAM (about 2.7x the data size). Streaming is not implemented.
