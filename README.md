# P.R.I.S.M.

Post-quantum Resilient Identity & Security Management. Package `kig` is the code name of P.R.I.S.M. (see docs/CRYPTO.md). Core design notes: `docs/CORE.md`; cryptography and claims: `docs/CRYPTO.md`.

DevForge Yugaantar, Track 4: Post-Quantum Security ("Trust, But Verify").

**Workflow protected:** a user shares an encrypted file across their devices. A device is later reported lost. The prototype cuts that device's access, re-keys the file, raises an explainable alert and leaves a signed audit trail an operator can verify.

## Try it in 90 seconds

```bash
pip install -r requirements.txt
python -m kig.demo --story     # lost phone, 3 nodes, tamper, crash and recovery, claim-to-evidence table
python -m kig.bench            # measured cost of put, fetch, rotate, backup, restore
python -m pytest -q            # the full suite
```

`--story` exits 1 if any of its checks fails. Every claim row it prints points at the step that shows it.

## Architecture

```
 device (laptop, phone)                         service (primary + 2 replicas)
 ----------------------                         ------------------------------
 ML-DSA-65 signing key   --signed request-->    check signature, audience, nonce, revoked set
 hybrid ML-KEM-768+X25519 key                   store ciphertext + per-device wrapped keys only
 encrypts file (AES-256-GCM)  <--wrap, manifest-- state journal (signed snapshot + signed WAL)
 checks signed manifest, pins keys              signed hash-chained audit log, revoked.log first
                                                signed encrypted backups, doctor, bench
```

* Revocation, replicas and what is simulated: `docs/REVOCATION.md`.
* Storage, journal, backup and the signed manifest: `docs/CORE.md`.
* Cryptography, known-answer tests, naming: `docs/CRYPTO.md`.
* Assets, attackers and limits: `THREAT_MODEL.md`. Reporting a problem: `SECURITY.md`.

## What is different here

* Nothing custom in the cryptography. HPKE, AES-256-GCM, ML-DSA-65 and scrypt come from one pinned library, and NIST
  known-answer vectors run in the tests.
* The server cannot silently change who may read a file: each file version carries a device-signed manifest of its
  ACL, owner and key commitment, and clients pin the writers.
* The audit log is the witness for the state journal, so deleting or truncating state is detected.
* Backups are signed and sealed, stream their blobs, and are restored with explicit, audited waivers.
* Revocation survives restarts, partitions, replays and rolled-back nodes, with the one bounded exposure window
  documented as a number.
* Every limit is written down next to the claim it limits.

## What it does

| Core objective | Where to see it |
| --- | --- |
| Normal operation | `python -m kig.demo` step 1, `tests/test_service.py::test_normal_operation` |
| Security control | `report_lost` / `revoke_device` / `disable_user` commands, rules R1 to R4 in `kig/detect.py` |
| Reliability | stale or replayed requests, epoch conflicts, restart recovery, crash between audit and state (fails closed): `tests/test_service.py` |
| Verifiable outcome | every decision is a signed, hash-chained audit entry; each alert lists the audit sequence numbers that triggered it |

## Design in one paragraph

Each device holds an ML-DSA-65 signing key and a hybrid ML-KEM-768 + X25519 key. A file is encrypted on the client with a random AES-256-GCM key (the DEK). The DEK is wrapped separately for each eligible device with the hybrid KEM. The service stores ciphertext and wrapped keys only, never a DEK. Every request is a device-signed envelope with timestamp and nonce. Revoking a device takes effect on the primary at once (replicas follow in tens of milliseconds, with a 5 s bound for a cut-off replica, see `docs/REVOCATION.md`), removes its wrapped keys and flags files for rotation, and the next authorised read re-encrypts under a fresh DEK and epoch. See `THREAT_MODEL.md` for assets, attackers, assumptions and limits.

## Clean-machine setup

Python 3.10 or newer (tested on 3.10, 3.12 and 3.13).

```bash
git clone https://github.com/Aditya2375/PRISM.git
cd PRISM
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q          # all tests
python -m kig.demo           # the lost-device scenario, end to end
```

Run the API (binds to 127.0.0.1):

```bash
KIG_DATA=./data uvicorn --factory kig.server:app --host 127.0.0.1 --port 8443
```

Create the first admin (once), enrol more devices, call commands:

```bash
python -m kig.cli init --data ./data --user asha --device asha-laptop --out asha-laptop.json
python -m kig.cli keygen --user asha --device asha-phone --out asha-phone.json > phone-pub.json
python -m kig.cli call --url http://127.0.0.1:8443 --key asha-laptop.json enroll_device "$(cat phone-pub.json)"
```

First start creates `data/server_sign.key`, `data/operator.token` (both mode 0600) and the audit log. Operator reads need header `X-KIG-Operator-Token`. Nothing secret is stored in the repository.

## API

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/command` | device signature | all state changes and key fetches |
| `GET /v1/overview` | operator token | users, devices, files, audit head |
| `GET /v1/audit?since=N` | operator token | audit entries (signed, chained) |
| `GET /v1/audit/verify` | operator token | verify the whole chain |
| `GET /v1/alerts` | operator token | alerts with rule, severity, evidence, response |
| `GET /v1/server-key` | none | service ML-DSA public key, for offline audit verification |
| `GET /healthz` | none | liveness |

Commands for `POST /v1/command` (`cmd` field): `whoami`, `eligible`, `create_user`, `set_role`, `enroll_device`, `revoke_device`, `report_lost`, `disable_user`, `put_file`, `fetch`, `rotate`, `list_files`. Build envelopes with `kig.client.Client` (`Client.envelope`).

Operator CLI: `python -m kig.cli rotate-pending --url URL --key device.json` re-keys every file flagged `needs_rotation` that this device may rotate (owner or admin in the ACL). Behind a reverse proxy (the service port must be reachable only through it) set `KIG_TRUSTED_PROXY=1` and `KIG_PROXY_HOPS` (default 1) so the source address is the one your proxy appended.

## Detection rules

| Rule | Severity | Fires when | Response |
| --- | --- | --- | --- |
| R1-REVOKED-DEVICE-USE | critical | a validly signed request arrives from a revoked or lost device | denied, no key material released |
| R2-REPLAY | high | a nonce is reused | denied and alerted when it comes from another source or with a different body; an identical retry from the same source is refused quietly. Nobody is locked out |
| R3-AUTH-FAILURE-BURST | high | 3 failed authentications for one device from one source in 60 s | alert only. Nobody is locked out; logging is rate bounded and summarised as `auth.failures_suppressed` |
| R4-PRIVILEGE-ESCALATION | high, or critical if the user's first device was enrolled under 10 min earlier | a user becomes admin | recorded; demote with `set_role` |

## Layout

```
kig/crypto.py    hybrid HPKE KEM, ML-DSA, AES-256-GCM (cryptography package only)
kig/vault.py     passphrase-sealed key files
kig/backup.py    signed encrypted backups, verify before restore
kig/audit.py     signed hash-chained log + standalone verifier
kig/store.py     signed snapshot + signed journal (O(1) writes)
kig/cluster.py   primary + two replicas, signed revocation certificates, lease
kig/doctor.py    read-only directory checker
kig/bench.py     measured cost at several sizes
kig/demo.py      the lost-device story
kig/detect.py    explainable rules
kig/service.py   identity directory, access decisions, revocation, recovery
kig/client.py    device-side crypto and request signing
kig/api.py       FastAPI app
tests/           pytest suite
```

## Licence

MIT.
