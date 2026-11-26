# Questions a judge may ask, and where the answer is proven

Each answer says what is true, what is not, and where to see it. "Test" means a test in `tests/`; run all with
`python -m pytest -q`.

## Quantum and cryptography

**Why is this post-quantum?** File keys are wrapped with a hybrid of ML-KEM-768 and X25519 (library HPKE suite), and
every signature is ML-DSA-65 (FIPS 204). An attacker recording ciphertext today needs to break both KEM halves.
`docs/CRYPTO.md`; `tests/test_crypto_proof.py` (NIST ACVP vectors for key generation and one signature-verify case).

**Did you write any cryptography?** No. Every primitive is called from the pinned `cryptography` library. The one other
library is PyCryptodome's Shamir, used only to split the backup key. The code we wrote is glue (what is bound to what).
`docs/CRYPTO.md`, "No custom crypto".

**Are signatures hybrid?** No. They are ML-DSA only, a stated choice to avoid writing a composite scheme.
`docs/CRYPTO.md`, "What we claim".

**Is AES-GCM key-committing?** No, so each file version carries an HMAC key commitment that the client checks.
Test `test_wrong_commitment_is_refused_by_the_client`.

**Can you prove the library is correct?** Only partly. ACVP vectors cover ML-DSA/ML-KEM key generation and one
verify case. Encapsulation, decapsulation, hybrid HPKE and signing are tested by round trips and tampering, and we rely on
the library. `docs/CRYPTO.md` says so.

## The workflow: lost device

**Show me the lost phone is cut off.** `python -m kig.demo --story`, steps 2 to 5 and 6 (three nodes). Tests
`test_lost_device_scenario`, `test_old_wrap_cannot_decrypt_new_epoch`, `test_revoked_device_gets_no_grace`.

**Does the thief keep reading?** What the phone already decrypted or copied stays with the thief. Rotation protects the
next version. This is written in the README, `THREAT_MODEL.md` and `docs/CRYPTO.md`.

**What if the request was captured before revocation and replayed after?** Denied on every node.
`docs/REVOCATION.md`, tests `test_revoked_device_rejected_everywhere_including_captured_request`,
`test_replay_and_stale_and_bad_signature`.

**How fast does revocation reach the other nodes, honestly?** The nodes are in-process simulations. The printed
times are dominated by the 5 to 50 ms network delay we inject, so they are not network measurements. A replica cut off
from the primary can serve for at most the 5 s lease, then refuses everyone. `docs/REVOCATION.md`, "Limits".

**What if a replica is malicious?** A malicious replica can ignore revocation for clients that talk only to it. The
documentation says so; a client needing protection must ask a second node.

**Can an attacker lock the victim out by claiming their id?** No lockouts exist. Failed auth raises alerts and is
rate bounded. Test `test_auth_failure_burst_alerts_but_never_locks_anyone_out`.

## Evil server and insiders

**Does the server ever see plaintext or private keys?** It never holds plaintext, file keys or device private keys. It does see ciphertext, file ids, ACLs, device ids and public keys, and it supplies the recipient public keys. Clients check each recipient key against the device's signed enrolment chain up to a pinned root, so a swapped key is refused (`test_f2_server_substituted_kem_key_is_refused`). Tests `test_service_never_holds_plaintext_or_dek` and
`tests/test_server_holds_no_secrets.py` scan the whole data directory and a backup for plaintext and device private keys.

**Can an evil server add a reader to my file?** Not without being caught by clients that have seen the file before:
each version has a device-signed manifest of ACL, owner and key commitment. Tests in `tests/test_manifest.py`
(`test_service_side_acl_edit_is_caught_by_client`, `test_owner_swap_is_caught`). After a root fingerprint was pinned out of band, a file never seen before is also checked: its writer must chain to the root (`test_f3_forged_first_sight_file_is_refused`). Without a pinned root, the root is trusted on first use, backed by the enrolment fingerprint check (`kig enroll --expect-fingerprint`). A server can still withhold updates.

**Can a member write or become admin?** Writes need owner or admin authority, proven by signed requests.
Tests `test_admin_proven_by_the_owner_may_write_but_a_member_may_not`, `test_privilege_escalation_alert`.

**Can someone edit or cut the audit log?** Edits, reordering, middle deletion and a stale anchor are detected.
Removing the last entries together with the anchor is not, unless you hold a head recorded elsewhere. Tests
`test_edit_delete_reorder_detected`, `test_tail_truncation_detected_by_checkpoint`; `THREAT_MODEL.md`, "Audit tampering".

**Can I check evidence without trusting your code?** Yes: `verifier/prism_verify.py` imports nothing from the service.
Exit 0 means complete, 1 a failed check, 2 verified but completeness unknown. `docs/CORE.md`,
`tests/test_standalone_verifier.py`.

## Crashes, restores and keys

**Kill the process mid-revocation or mid-rotation.** One consistent version, revocations never lost. Tests
`test_crash_during_revocation_never_loses_it`, `test_rotation_crash_leaves_one_consistent_version`,
`tests/test_chaos.py` (random kill points, 12 seeds). Demo step 8.

**Roll back state.json or the whole directory.** Refused at start-up, or the revoked set is re-applied. Tests
`test_state_file_rollback_cannot_resurrect_a_revoked_device`, `test_rolling_back_state_and_audit_together_is_refused_at_start`.
Not caught: removing only the last single command, which looks like a crash before acknowledgement. Revocations survive
it either way.

**Lose the server completely.** `test_total_loss_then_restore_then_keep_working`; backups are signed, sealed to an
offline key, and restore needs rollback evidence or an audited waiver (`test_restore_without_any_rollback_evidence_is_refused`).

**Lose the backup key.** The backup is unreadable by design. Split the key k-of-n with `kig backup-key split` so no
single holder is a single point of failure or compromise. `docs/CORE.md`, `tests/test_threshold.py`.

**Corrupt a stored blob.** Detected on read and in `kig doctor`; test `test_corrupt_blob_reported`, demo step 7.

**Where is the signing key kept?** In a file (0600, passphrase-sealed if a passphrase is set) or behind the `KeyStore`
interface. We ship no HSM driver. `docs/CORE.md`, `tests/test_keystore.py`.

## Abuse of the service

**Send huge, deep or malformed requests.** Clean 4xx, no 500 and no unbounded memory:
`test_huge_timestamp_and_deep_json_are_clean_4xx_not_500`, `tests/test_fuzz.py`, body cap 413.

**Flood it.** Per-device and per-source budgets bound log writes; signature checks still cost CPU, so a distributed flood
can slow it. `THREAT_MODEL.md`, "Availability".

## Scope and honesty

**Is the cluster real?** No. It is a simulation of the replication logic in one process.
**Is there TLS?** Out of scope: the demo binds to localhost; deployment is assumed to add TLS.
**Is there AI or ML?** No. Detection is four explainable rules (README table).
**Performance?** `python -m kig.bench`; the table and its limits are in `docs/CORE.md` (backup memory grows with the
number of files).
**What would you do with more time?** A real multi-host cluster, a hardware key store driver, a Merkle-tree log with
witnesses (see `docs/RELATED.md`), and a streaming backup of metadata.
