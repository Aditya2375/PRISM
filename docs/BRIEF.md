# P.R.I.S.M. brief

**Post-quantum Resilient Identity & Security Management.** DevForge Yugaantar, Track 4: Post-Quantum Security
("Trust, But Verify"). Team "Do You Care". Repository: https://github.com/Aditya2375/PRISM (MIT, Python 3.12 and 3.13 in CI).

## The problem

A user keeps encrypted files on several devices. One device is lost. Today's keys, wrapped with RSA or elliptic curves,
can be recorded now and broken later by a quantum computer, and most systems cannot prove afterwards what was
decided, by whom, or whether the record was changed.

## What we built

A key-management service plus client for one workflow: **a user shares an encrypted file across devices; a device is
reported lost; its access is cut, the file is re-keyed, an alert explains why, and the evidence can be verified by
someone who does not trust the service.**

* **Hybrid post-quantum keys.** Each file version gets a fresh AES-256-GCM key. It is wrapped per device with
  ML-KEM-768 + X25519 (HPKE). A device that is no longer eligible gets no wrap. Every signature is ML-DSA-65.
* **Revocation that fails closed.** The revoked set is written first, survives restarts, and only grows. A three-node
  cluster pushes signed revocation certificates, and a node cut off from the primary refuses everyone once its lease
  runs out. It runs as three real OS processes over TCP on localhost (`python -m kig.netcluster`) and as an in-process
  simulation that keeps the fast tests fast.
* **Powerful devices are guarded.** A phone can be enrolled as a limited device that never acts as an admin. Removing
  an admin's device, or disabling an admin, needs another admin whose device is at least 15 minutes old, and removing
  a limited device of an admin raises an alert. Deleted file ids are never reused by accident.
* **Re-keying with crash recovery.** A rotation is journalled; killing the process at any point leaves one consistent
  version and no lost revocation.
* **Trust, but verify.** Every decision is a signed, hash-chained audit entry. Each file version carries a
  device-signed manifest (ACL, owner, key commitment) that clients check and pin. `verifier/prism_verify.py` re-checks
  the audit log, a backup or the state snapshot with no service code and no private key.
* **Backup and restore.** Signed, sealed to an offline key, streamed; restore needs evidence about rollback or an
  audited waiver. The backup key can be split k-of-n.
* **Explainable detection.** Five rules (revoked-device use, replay, auth-failure burst, privilege escalation, removal of an admin's limited device). No ML. Alerts name the device, user, node, triggering event and source (`unknown` when not logged).
  Measured with `python -m kig.bench_detect` on one machine: 0 false alerts in 1,265 benign requests (0.0 per
  1,000); nine labelled attack scenarios x 20 runs, precision 1.00, recall 0.67, F1 0.80, median time to alert 5 to
  15 ms wall (0 to 2 s on the service clock) for the rules that fire. Three scenarios (slow guessing, probing,
  a valid insider) are missed on purpose and counted. Rules and scenarios have the same authors.

## How to see it in 90 seconds

```
pip install -r requirements.txt
python -m kig.demo --story     # lost phone, 3 simulated nodes, tamper, crash and recovery, claim-to-evidence table
python -m kig.demo --net       # revocation across 3 real node processes over TCP on localhost
python -m pytest -q            # 500+ tests, green on a clean clone
```

## Grace period

Rotation: yes, 30 s, in-flight reads of the previous version by still-eligible devices only; then `key_version_retired`.
Revoked or lost device: zero. A replica cut off from the primary: no grace, but it may serve until its lease runs out
(`lease_s`: 2 s in the real three-process harness, 5 s in the simulation), then refuses everyone.

## Evidence, not assertion

| Claim | Evidence |
| --- | --- |
| Lost device is denied on every node | demo step 6; `docs/REVOCATION.md` attack table, each row names its test |
| Server never holds plaintext or keys | `test_service_never_holds_plaintext_or_dek`, `tests/test_server_holds_no_secrets.py` |
| A malicious server cannot swap a recipient key, invent a file or change who reads it, after a root fingerprint was pinned out of band (trust on first use otherwise) | `tests/test_manifest.py`, `tests/test_manifest_writers.py`, `tests/test_round_fixes.py` |
| Tamper, truncation and reordering of the log are detected | `tests/test_audit.py`, `tests/test_standalone_verifier.py` |
| Crashes do not lose a revocation or half-apply a rotation | `tests/test_chaos.py` (random kill points), `tests/test_crash_and_cutoff.py` |
| Library behaviour matches NIST | `tests/test_crypto_proof.py` (ACVP vectors, commit pinned) |
| Hostile inputs give clean errors | `tests/test_fuzz.py`, `tests/test_hardening.py` |

## Rules of the event

No AI or ML in the product. No hard-coded secrets (keys are generated at first start, files mode 0600). No custom
cryptography: every primitive comes from the pinned `cryptography` library; the only other library is PyCryptodome's
Shamir for the optional key split. All code written during the event; every commit by the team lead's account.

## Honest limits

* A revoked device keeps what it already decrypted. Rotation protects later versions.
* The three real node processes share one machine, one clock and loopback, so their millisecond figures are not a
  network measurement. A cut-off replica can serve a lost device for at most one lease (2 s in the real-process test,
  5 s in the in-process simulation). Sync between nodes is plain HTTP and needs TLS across hosts, and the shared
  cluster token lets its holder force repeated snapshots.
* A stolen full admin device is an admin until the host removes it. The 15 minute cooling-off uses the service clock.
* The audit log is a hash chain. Removing its last entries together with its anchor is undetectable unless you keep a
  head elsewhere; the verifier says so and exits 2 in that case.
* The server is trusted at first contact for the device directory; the enrolment fingerprint check narrows that.
* Signatures are post-quantum only (not hybrid). Python cannot wipe memory. No hardware key store driver is shipped.

## Where to read more

`README.md` (run it), `THREAT_MODEL.md` (assets, attackers, limits), `docs/CRYPTO.md` (what we use and claim),
`docs/CORE.md` (storage, backup, verifier, key split), `docs/REVOCATION.md`, `docs/QA.md` (likely judge questions),
`docs/RELATED.md` (Vault, Sigstore Rekor), `docs/CORE_HARDENING.md` (device classes, removal rules, deleted ids, limits), `docs/DEMO_SCRIPT.md` (video walk-through), `docs/ARCHITECTURE_NOTES.md` (architecture paragraphs). What we do not build, and why: `THREAT_MODEL.md`, "Out of scope".
