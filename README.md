# P.R.I.S.M.

In this document `kig X` means `python -m kig.cli X`.

Post-quantum Resilient Identity & Security Management. Package `kig` is the code name of P.R.I.S.M. (see docs/CRYPTO.md). Core design notes: `docs/CORE.md`; cryptography and claims: `docs/CRYPTO.md`.

DevForge Yugaantar, Track 4: Post-Quantum Security ("Trust, But Verify").

**Workflow protected:** a user shares an encrypted file across their devices. A device is later reported lost. The prototype cuts that device's access, re-keys the file, raises an explainable alert and leaves a signed audit trail an operator can verify.

**Contents:** [Try it](#try-it-in-90-seconds) | [Architecture](#architecture) | [What is different](#what-is-different-here) | [Setup](#clean-machine-setup) | [Grace period](#grace-period-and-cutoff-the-organizers-wording) | [Detection, measured](#detection-measured-python--m-kigbench_detect) | [API](#api) | [Web console](#web-console) | [Layout](#layout) | [Licence](#licence)

**Start here**

| What | Where |
|---|---|
| Live demo (hosted, read-only demo data; first load can take about 40 s) | https://prism-demo-xp6h.onrender.com |
| Demo video (intro by Yashaswin, then a screen recording with on-screen captions, 4 minutes, unlisted) | https://youtu.be/RADunkfenVM |
| 2-page brief (PDF, in the repo) | [docs/PRISM_brief.pdf](docs/PRISM_brief.pdf) |
| Narration script (PDF; the video uses only a short spoken intro) | [docs/PRISM_narration_script.pdf](docs/PRISM_narration_script.pdf) |
| Run it yourself, offline after install | [Try it in 90 seconds](#try-it-in-90-seconds) |
| What is claimed and what is not | [THREAT_MODEL.md](THREAT_MODEL.md), [docs/QA.md](docs/QA.md) |

## Try it in 90 seconds

```bash
pip install -r requirements.txt
python -m kig.demo --story     # lost phone, 3 simulated nodes, tamper, crash and recovery, claim-to-evidence table
python -m kig.demo --net       # the same revocation across 3 real node processes over TCP on localhost (about 7 s)
python -m kig.bench            # measured cost of put, fetch, rotate, backup, restore
python -m pytest -q            # the full suite
```

The hosted demo runs on a free plan that sleeps when idle, so the first load can take about 40 seconds.

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

* Revocation, the in-process simulation and the real three-process cluster: `docs/REVOCATION.md`. Device classes, removal rules, deleted ids and the limits that remain: `docs/CORE_HARDENING.md`. Video walk-through of the core: `docs/DEMO_SCRIPT.md`. Architecture paragraphs: `docs/ARCHITECTURE_NOTES.md`. Measured revocation time, throughput and the clock-skew window: `docs/PERFORMANCE.md`. Scheduled backups, the smoke test, monitoring, rollback and audit-log size: `docs/OPERATIONS.md`.
* Two-page brief: `docs/BRIEF.md`. Likely judge questions with evidence: `docs/QA.md`. How this relates to Vault and Sigstore Rekor: `docs/RELATED.md`.
* Storage, journal, backup, the signed manifest and the standalone verifier (`verifier/prism_verify.py`): `docs/CORE.md`.
* Cryptography, known-answer tests, naming: `docs/CRYPTO.md`.
* Assets, attackers and limits: `THREAT_MODEL.md`. Reporting a problem: `SECURITY.md`.

## What is different here

* Nothing custom in the cryptography. HPKE, AES-256-GCM, ML-DSA-65 and scrypt come from the pinned `cryptography` library, and NIST
  known-answer vectors run in the tests. One more vetted library, PyCryptodome, is used only for the optional k-of-n
  split of the backup key (`kig/threshold.py`, Shamir from `Crypto.Protocol.SecretSharing`); we wrote no
  secret-sharing maths. Both are pinned in `requirements.txt`.
* A server that never held a private key cannot silently change who may read a file, **after the client has pinned a root
  fingerprint that reached it out of band** (`--root-fingerprint`, printed by `init`; always pass it in the quick start): each file version carries a device-signed manifest of its ACL,
  owner and key commitment, every recipient key is checked against the device's signed enrolment, and clients pin the
  writers. Without one, the client pins whatever root the server shows on first use, so a server that is malicious from the first call chooses the root. A server can
  still withhold updates and see ciphertext and metadata.
* Operations: run **one** service process per data directory (a lock file makes a second one refuse to start; do not
  use `uvicorn --workers`). Keep a rollback pin outside the data directory with `KIG_PIN_FILE=/path/outside/pin.json`;
  the service then refuses to start on a data directory older than the pin. Per-user limits: 1,000 files and 256 MB;
  service limit 4 GB. Only admins can add other users to a file's list; owners and admins can delete files
  (`delete_file`). If every admin device is lost, the operator runs `kig recover-admin --data DIR --user U --device NEW
  --out KEY` on the host (an audited operator action) and clients pin the roots it prints (`kig pin-root --key KEYFILE --fingerprint FP` for existing clients; the fingerprint must reach them out of band). Recovery restores
  control, not file keys: files keyed only to lost devices stay unreadable until restored from a backup.
  An admin-capable device (any device not enrolled `--limited`) of an admin can be removed only by another admin user whose device is at least 15 minutes old, or offline with `kig revoke-device --data DIR --device ID [--reason TEXT]` (audited operator action; it still refuses to remove the last admin device), so a stolen device cannot lock the owner out. Residual: a stolen ADMIN-CAPABLE device is an admin until the operator removes it offline or an older admin device disables the user it made, and for 15 minutes it can act freely; use `--limited` for phones, and a sole admin must enrol every phone that way. A stolen full admin device can also remove the owner's limited devices (it raises the high alert R5-ADMIN-LIMITED-DEVICE-REMOVED, which is also expected when you report your own phone lost); for a sole admin the recovery for a stolen full admin device is the host: `kig revoke-device` and `kig recover-admin`. The 15 minute wait uses the service's own clock, so someone who can step that clock (an operator) can shorten it. The client also refuses any enrolment or role proof signed by a limited device. Members can remove their own devices. A deleted file id comes back only for its owner or an admin, at the next epoch (an admin who re-creates another owner's id becomes its owner, and readers that pinned the old owner refuse it); the service remembers one small record per deleted id (cap 2,000 per owner, `KIG_MAX_DELETED_IDS` changes it). Roots given with `--root-fingerprint` or `KIG_ROOT_FINGERPRINTS` are used alone; `kig unpin-root --key KEYFILE --fingerprint FP` removes a stale pin. High and critical alerts are in the audit log and printed as one line on the service's stderr; nothing else pushes them out, so the operator has to watch that output or the activity page.
* The audit log is the witness for the state journal, so deleting or truncating state is detected.
* Backups are signed and sealed, stream their blobs, and are restored with explicit, audited waivers.
* Revocation survives restarts, partitions, replays and rolled-back nodes, with the one bounded exposure window
  documented as a number.
* Every limit is written down next to the claim it limits.

## What it does

| Core objective | Where to see it |
| --- | --- |
| Normal operation | `python -m kig.demo` step 1, `tests/test_service.py::test_normal_operation` |
| Security control | `report_lost` / `revoke_device` / `disable_user` commands, rules R1 to R10 in `kig/detect.py`, outside logs through `kig/ingest.py` |
| Reliability | stale or replayed requests, epoch conflicts, restart recovery, crash between audit and state (fails closed): `tests/test_service.py` |
| Verifiable outcome | every decision is a signed, hash-chained audit entry; each alert lists the audit sequence numbers that triggered it |

## Design in one paragraph

Each device holds an ML-DSA-65 signing key and a hybrid ML-KEM-768 + X25519 key. A file is encrypted on the client with a random AES-256-GCM key (the DEK). The DEK is wrapped separately for each eligible device with the hybrid KEM. The service stores ciphertext and wrapped keys only, never a DEK. Every request is a device-signed envelope with timestamp and nonce. Revoking a device takes effect on the primary at once (replicas follow through signed revocation certificates: in the three-process cluster, `python -m kig.netcluster`, the last node refused the device after tens of milliseconds on one machine, a loopback figure and not a network measurement; in the in-process simulation, within the injected 5 to 50 ms delay; a cut-off replica is bounded by its lease, 2 s in the real-process harness and 5 s in the simulation; see `docs/REVOCATION.md`), removes its wrapped keys and flags files for rotation, and the next authorised read re-encrypts under a fresh DEK and epoch. See `THREAT_MODEL.md` for assets, attackers, assumptions and limits.

## Clean-machine setup

Python 3.10 or newer (CI runs 3.12 and 3.13; the suite is also run locally on 3.10).

```bash
git clone https://github.com/Aditya2375/PRISM.git
cd PRISM
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q          # all tests
python -m kig.demo           # the lost-device scenario, end to end
```

Create the first admin **before** starting the service (once). `init` writes the key file and prints the root fingerprint. Give that fingerprint to every client as `--root-fingerprint`; the commands below keep it in `$FP`:

```bash
K="python -m kig.cli"; U=http://127.0.0.1:8443
FP=$($K init --data ./data --user asha --device asha-laptop --out asha-laptop.json | sed -n 's/^root fingerprint.*: //p')
```

Run the API (binds to 127.0.0.1), in a second terminal or in the background:

```bash
KIG_DATA=./data uvicorn --factory kig.server:app --host 127.0.0.1 --port 8443
```

Enrol a second device. `keygen` prints the new device's fingerprint on stderr: read it from the new device, compare it, then enrol:

```bash
$K keygen --user asha --device asha-phone --out asha-phone.json > phone-pub.json 2> phone-fp.txt
PF=$(sed -n 's/^fingerprint.*: //p' phone-fp.txt)
$K enroll --url $U --root-fingerprint $FP --key asha-laptop.json --pub phone-pub.json --expect-fingerprint $PF --limited
# --limited: the phone acts as a plain member even for an admin user. The admin can remove it from the laptop (next step),
# and stealing it gives no admin power. Without --limited the phone is admin-capable and only another admin or the operator can remove it.
```

Store a file (put a line of text in `a.txt` first), read it on the phone, report the phone lost, and check the evidence without the service:

```bash
$K put --url $U --root-fingerprint $FP --key asha-laptop.json --file-id doc --path a.txt
$K get --url $U --root-fingerprint $FP --key asha-phone.json --file-id doc --out b.txt
$K call --url $U --root-fingerprint $FP --key asha-laptop.json report_lost '{"device":"asha-phone"}'
$K get --url $U --root-fingerprint $FP --key asha-phone.json --file-id doc --out c.txt   # denied: revoked
python verifier/prism_verify.py audit --log data/audit.jsonl --pub data/server_sign.pub --anchor data/audit.head
# exit 2 and a NOTE: the chain verifies, but only a head you recorded elsewhere (--expect-head) proves nothing was cut off the end
```

First start creates `data/server_sign.key`, `data/operator.token` (both mode 0600) and the audit log. Operator reads need header `X-KIG-Operator-Token`. Nothing secret is stored in the repository.

## Grace period and cutoff (the organizers' wording)

* **Key rotation: a grace period applies, 30 seconds.** After a rotation the previous key version stays readable for
  30 s (`GRACE_S`), only for devices that were still eligible, so a transfer in flight can finish. After the cutoff
  the node answers `key_version_retired`. A client also refuses a version older than the newest it has seen.
* **Revoked or lost device: grace period zero.** The primary refuses it on its next request. A revoked device gets
  no grace on rotation either.
* **Replica that cannot reach the primary: no grace, but a bounded window.** It may keep serving until its lease
  (`lease_s`) runs out, 2 s in the real three-process harness and 5 s in the in-process simulation. After that it
  refuses every request with `node_stale` until it has synced.

## Detection, measured (`python -m kig.bench_detect`)

Alerts are structured. Each one carries `rule`, `severity`, `explanation`, `evidence` (audit sequence numbers),
`device`, `user`, `service` (the node that raised it), `event` (the audit entry type that triggered it), `source`
(network source, when the request was logged) and `actor`, plus `services` (the raising node and every service named by
the evidence, a list), `files` (the files involved; empty unless the rule is about file access), `identity`,
`identity_verified`, `path` (services in the order reached, for R6-LATERAL-SERVICE) and `ordering`. `device` and `user`
hold only proven values; otherwise they say `unknown`, never a guess. `identity` is always filled: the proven user or
device, or for unauthenticated failures the id the sender claimed and its source (`identity_verified: false`). The
per-minute suppressed-burst alert (R3) names the top five claimed ids and sources.

`ordering` is `uncertain` when the evidence holds events of one identity from different services less than 30 s apart:
inside the +/-30 s skew we assume, their order is not known. An event arriving more than 30 s older than one already seen
for that identity raises R10-OUT-OF-ORDER (low).

Outside logs: `python -m kig.ingest logs.jsonl [--config map.json]` feeds JSON-lines or CSV logs from other services
(identity, service, event, timestamp; every field name is configurable) into the same rules. See `docs/INGEST.md`.

`python -m kig.bench_detect` (default 20 runs per scenario) builds a fresh in-process service for each run, replays a benign trace, then runs twelve
labelled attack scenarios 20 times each, then a separate outside-log benchmark through `kig.ingest`. Time to alert runs
from the first malicious request to the alert: wall milliseconds on this machine, and seconds on the service clock (the
clock the rules use). Result on one run (Linux x86_64, 4 vCPU, Python 3.13; wall times depend on the machine):

| Measure | Result |
| --- | --- |
| Benign requests replayed | 1,265 |
| False alerts | 0 (0.0 per 1,000 requests) |
| Attack runs (12 scenarios x 20) | 240: 200 detected, 40 missed, 0 false positives |
| Precision / recall / F1 | 1.000 / 0.833 / 0.909 |

| Scenario | Caught | Median wall ms (min-max) | Median service-clock s |
| --- | --- | --- | --- |
| lost device used after it was reported lost (R1) | 20/20 | 7.1 (4.5-17.4) | 0 |
| captured request replayed from another source (R2) | 20/20 | 6.3 (3.9-10.8) | 0 |
| three bad signatures in a minute from one source (R3) | 20/20 | 15.7 (12.1-40.7) | 2 |
| flood of unknown device ids, summary alert (R3) | 20/20 | 55.2 (46.0-79.0) | 61 |
| fresh account promoted to admin (R4) | 20/20 | 6.6 (4.8-16.2) | 0 |
| admin account created, first device enrolled 60 s later (R4 critical, fires on the enrolment) | 20/20 | 17.1 (13.0-23.2) | 0 for the high alert, 60 for the critical one |
| admin device removes the owner's limited phone (R5) | 20/20 | 7.9 (6.3-11.5) | 0 |
| slow guessing, 2 bad signatures per 65 s for 11 minutes (R8) | 20/20 | 113.3 (89.6-163.6) | 220 |
| valid admin device reads 20 files in under a minute (R7) | 20/20 | 107.4 (87.5-200.4) | 14 |
| valid member reads 5 files it never read before (R6) | 20/20 | 29.2 (22.3-41.4) | 15 |
| member probes a file outside its list | 0/20 | not detected | |
| valid insider reads one new file every 10 minutes | 0/20 | not detected | |

Outside logs (`kig.ingest`, synthetic: 40 identities, 6 services, 8 hours, per-service clock offsets up to 20 s):

| Measure | Result |
| --- | --- |
| Benign events | 2,470, 0 false alerts (0.0 per 1,000). Five other seeds of the same generator: 1 false alert in 12,231 events (0.08 per 1,000) |
| Established identity reaches a new service (R6-LATERAL-SERVICE) | caught, on the event itself (0 s) |
| New identity hops web -> files -> hr in 40 s (R6-LATERAL-SERVICE) | caught, 40 s after the first hop (needs the third service) |
| Three failed logins in a minute (R3) | caught, 20 s (on the third) |
| Revoked credential used (R1) | caught, 0 s |
| Admin created, first credential 60 s later (R4 critical) | caught, 60 s (on the enrolment) |
| Precision / recall / F1 | 1.0 / 1.0 / 1.0 on 5 scenarios we wrote. That says the rules do what we built them for, not that they will score this on unseen data. |

How to read it. The two misses are in the denominator on purpose: the rules are thresholds over audit events, so they do
not flag a denied probe (it is a refusal, not an access pattern) or an insider who stays under every window by reading one
new file every ten minutes. The recall rose from 0.67 to 0.83 because we added rules R6 to R9, changed two scenarios to fit them and added two misses we cannot catch. It is a re-measure after tuning the rules against our own scenarios, not an independent improvement. The access rules (R6, R7) and R8 are new and tuned by us on the same traces we test them on, so
treat the thresholds as defaults for a small team, not as measured on real traffic. The scenarios and the
rules were written by the same people, so this shows what the rules do on these traces and is not a claim about real
traffic. The flood scenario waits for the one-minute summary, so its 61 s is the rule's design, not slowness.
R5 fires the same way for the owner reporting a lost phone and for a thief holding the laptop; the alert says so.

## API

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/command` | device signature | all state changes and key fetches |
| `GET /v1/overview` | operator token | users, devices, files, audit head |
| `GET /v1/audit?since=N` | operator token | audit entries (signed, chained) |
| `GET /v1/audit/verify` | operator token | verify the whole chain |
| `GET /v1/metrics[?format=prometheus]` | operator token | counts only: users, devices by status, files, files needing rotation, audit events by type |
| `GET /v1/alerts` | operator token | alerts with rule, severity, evidence, response, and device, user, service, event, source, actor |
| `GET /v1/server-key` | none | service ML-DSA public key, for offline audit verification |
| `GET /healthz` | none | liveness |

Commands for `POST /v1/command` (`cmd` field): `whoami`, `eligible`, `my_devices`, `my_activity`, `create_user`, `set_role`, `enroll_device`, `revoke_device`, `report_lost`, `disable_user`, `put_file`, `fetch`, `rotate`, `list_files`. Build envelopes with `kig.client.Client` (`Client.envelope`).

Browser front end on another origin: CORS is off by default. Set `KIG_CORS_ORIGINS=http://localhost:5173` (exact origins, comma separated, no path or trailing slash; `*` is refused, and so is a set variable that lists nothing) to let that page call the API. CORS is a browser-side rule only. It does not authenticate anyone and does not replace the operator token. It only lets the browser read answers: operator routes still need `X-KIG-Operator-Token`, and device commands still need a device signature, which a browser cannot make. `python -m kig.demo --json` prints the three-node scene (per-node revocation times, the cut-off replica) as JSON for a status screen; it is simulated, in one process.

Operator CLI: `python -m kig.cli rotate-pending --url URL --key device.json` re-keys every file flagged `needs_rotation` that this device may rotate (owner or admin in the ACL). Behind a reverse proxy (the service port must be reachable only through it) set `KIG_TRUSTED_PROXY=1` and `KIG_PROXY_HOPS` (default 1) so the source address is the one your proxy appended.

### Local backend for a browser user screen (optional)

A browser cannot make ML-DSA signatures, so a page for an ordinary device holder needs a small process on that person's machine that holds the device key: `python -m kig.webapi --key asha-laptop.json --url http://127.0.0.1:8443 [--port 8788]` (passphrase from `PRISM_PASSPHRASE` if the key file is sealed). It binds to 127.0.0.1 only, accepts only `Host: 127.0.0.1`, `localhost` or `[::1]`, and needs the random session token it prints at start-up in an `X-PRISM-Session` header. Endpoints, all JSON except the download: `GET /me`, `GET /files`, `POST /files` (`file_id`, `acl`, `content_b64`), `GET /files/<id>` (raw bytes after the client has checked the signed manifest and pins), `GET /devices` (own devices only), `POST /devices/lost` (`device`, `reason`), `POST /devices/preview` and `POST /devices/enroll` (`pub`, optional `limited: true`, and `expect_fingerprint` or `unverified: true`, which skips the fingerprint check and is recorded as unverified, so a UI should hide it behind an explicit warning; the service allows enrolment to admins only), `GET /activity?limit=` (audit entries about your own devices, with a fixed set of plain fields). It never returns keys, wrapped keys, the passphrase or the operator token. CORS is off unless `KIG_CORS_ORIGINS` lists exact origins, and it is not authentication. Even a 401 or a wrong-host answer carries the CORS headers, so a page sees the real error; calls are served one at a time and the service call times out after 10 s. A UI must show every returned string as text, never as markup. Limits: the unlocked device key lives in that process, so anything on the same machine that has the session token can act as the device; there is no TLS because it never leaves the loopback interface.

## Web console

The primary console is `web-p3/`: a React app in the red design contributed by Abhishek, wired to the real API (no sample data). It has an operator console (alerts with device, user, node, event and source; devices; files; the signed audit log with a chain check) and a device-holder view (upload, download, enrol, report lost). It holds no keys. To run it with demo data: `bash web-p3/run_demo.sh` (Node 20 or newer), then open http://localhost:4173. Limits and credits: `web-p3/README.md`. `web/` now holds only a notice; `web-p3/` is the current console.

## Detection rules

| Rule | Severity | Fires when | Response |
| --- | --- | --- | --- |
| R1-REVOKED-DEVICE-USE | critical | a validly signed request arrives from a revoked or lost device | denied, no key material released |
| R2-REPLAY | high | a nonce is reused | denied and alerted when it comes from another source or with a different body; an identical retry from the same source is refused quietly. Nobody is locked out |
| R3-AUTH-FAILURE-BURST | high | 3 failed authentications for one device from one source in 60 s | alert only. Nobody is locked out; logging is rate bounded and summarised as `auth.failures_suppressed` |
| R4-PRIVILEGE-ESCALATION | high, or critical if the user's first device was enrolled under 10 min earlier | a user becomes admin | recorded; demote with `set_role` |
| R5-ADMIN-LIMITED-DEVICE-REMOVED | high | a limited device of an admin is removed | alert only; expected after a lost phone, a sign of a stolen acting device otherwise |
| R6-LATERAL-MOVEMENT | medium | a device that already had a read history (2 or more files older than 5 min) reads 4 files it never read before within 5 min | alert only; the reads were valid. A pattern, not proof; names the files. Known false positive: a member newly shared several files who opens them at once |
| R7-BULK-READ | critical for an admin's device, else high | one device reads 15 different files within 60 s | alert only; names the device, user and files |
| R8-SLOW-GUESSING | medium | 8 failed authentications from one source within an hour (too slow for R3) | alert only; requests were already denied |
| R9-CLOCK-SKEW | low | 3 requests from one device refused as stale (outside the +/-30 s window) within 60 s | alert only; states the offsets seen. A drifting device clock and replay of old traffic look alike |

The rules see the service's own audit entries only. They do not read logs in another system's format: there is no adapter for
the organizers' log format, and we do not have a sample of it. Anything that can write our audit entries (type, actor and data)
can feed them.

## Layout

```
kig/crypto.py    hybrid HPKE KEM, ML-DSA, AES-256-GCM (cryptography package only)
kig/vault.py     passphrase-sealed key files
kig/keystore.py  pluggable key storage interface (file and memory stores)
kig/threshold.py k-of-n split of a secret (vetted Shamir)
kig/backup.py    signed encrypted backups, verify before restore
kig/audit.py     signed hash-chained log (the service's own checker)
kig/store.py     signed snapshot + signed journal (O(1) writes)
kig/cluster.py   primary + two replicas, signed revocation certificates, lease (in one process; the fast-test path)
kig/node.py      one cluster node as its own OS process over HTTP
kig/netcluster.py three node processes on localhost, TCP relays, measured revocation time
kig/doctor.py    read-only directory checker
kig/bench.py     measured cost at several sizes
kig/bench_detect.py false alerts per 1,000 benign requests, time to alert, precision, recall and F1 of the rules
kig/demo.py      the lost-device story
verifier/        standalone audit, backup and state verifier (no kig imports)
kig/detect.py    explainable rules
kig/ingest.py    feeds outside JSON-lines / CSV logs to the rules (docs/INGEST.md)
kig/service.py   identity directory, access decisions, revocation, recovery
kig/client.py    device-side crypto and request signing
kig/api.py       FastAPI app
kig/webapi.py    optional local backend for a browser user screen
kig/server.py    app factory used by uvicorn (`kig.server:app`)
tests/           pytest suite
```

## No committed keys

The repository holds no private key and no passphrase. Tests that need on-disk PRISM-1 data (`tests/test_frozen_format.py`)
generate it at run time with fresh keys and a random passphrase (`v1_data` in `tests/conftest.py`), and a test fails if a key file
or the old fixture passphrase reappears in the tree. The only committed test data is the published NIST known-answer vectors in
`tests/vectors/` (public). The service and the demo generate all of their keys at first start.

Trade-off, stated plainly: because the fixture is written by the current code, the suite checks that restart and backup restore
round-trip and that no PRISM-1 field was removed or renamed, but it no longer opens bytes written by an older build.

## Licence

MIT.

## Reproducible install

`requirements.lock` pins every dependency by hash: `pip install --require-hashes -r requirements.lock`. It is generated with `uv pip compile requirements.txt --generate-hashes`; `requirements.txt` stays the readable list.
