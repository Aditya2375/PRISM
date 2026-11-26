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
  cluster (simulated in one process) pushes signed revocation certificates; a node cut off from the primary refuses
  everyone after a 5 s lease.
* **Re-keying with crash recovery.** A rotation is journalled; killing the process at any point leaves one consistent
  version and no lost revocation.
* **Trust, but verify.** Every decision is a signed, hash-chained audit entry. Each file version carries a
  device-signed manifest (ACL, owner, key commitment) that clients check and pin. `verifier/prism_verify.py` re-checks
  the audit log, a backup or the state snapshot with no service code and no private key.
* **Backup and restore.** Signed, sealed to an offline key, streamed; restore needs evidence about rollback or an
  audited waiver. The backup key can be split k-of-n.
* **Explainable detection.** Four rules (revoked-device use, replay, auth-failure burst, privilege escalation). No ML.

## How to see it in 90 seconds

```
pip install -r requirements.txt
python -m kig.demo --story     # lost phone, 3 nodes, tamper, crash and recovery, claim-to-evidence table
python -m pytest -q            # 350+ tests, green on a clean clone
```

## Evidence, not assertion

| Claim | Evidence |
| --- | --- |
| Lost device is denied on every node | demo step 6; `docs/REVOCATION.md` attack table, each row names its test |
| Server never holds plaintext or keys | `test_service_never_holds_plaintext_or_dek`, `tests/test_server_holds_no_secrets.py` |
| A malicious server cannot change who reads a file unnoticed | `tests/test_manifest.py`, `tests/test_manifest_writers.py` |
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
* The cluster nodes are in-process simulations; the printed millisecond figures are dominated by a delay we inject.
  A cut-off replica can serve for at most 5 s.
* The audit log is a hash chain. Removing its last entries together with its anchor is undetectable unless you keep a
  head elsewhere; the verifier says so and exits 2 in that case.
* The server is trusted at first contact for the device directory; the enrolment fingerprint check narrows that.
* Signatures are post-quantum only (not hybrid). Python cannot wipe memory. No hardware key store driver is shipped.

## Where to read more

`README.md` (run it), `THREAT_MODEL.md` (assets, attackers, limits), `docs/CRYPTO.md` (what we use and claim),
`docs/CORE.md` (storage, backup, verifier, key split), `docs/REVOCATION.md`, `docs/QA.md` (likely judge questions),
`docs/RELATED.md` (Vault, Sigstore Rekor).
