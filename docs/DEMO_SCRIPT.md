# Demo script: the key-management core (about 4 minutes)

Run everything from the repository root after `pip install -r requirements.txt`. Output shown is what the
commands print. Millisecond figures change from run to run; say "about", never a fixed number.

## 0. Open (10 s)
Say: "A file is shared across devices. One device is lost. We show how access is cut, the key is replaced,
and every step leaves evidence. Then what this does not protect against."

## 1. The whole story (60 s)
Command: `python -m kig.demo --story`

Point at these lines as they appear:
* Step 1: both Ravi and Asha's phone read "salary table: confidential".
* Step 2: the phone is reported lost. The reply lists `payroll-2026` as needing a new key.
* Step 3: someone holding the phone sends a validly signed request. Result: `denied: revoked (device is lost)`.
* Step 4: Ravi's next read re-keys the file automatically. The epoch goes to 1 and the wrapped keys list only
  the laptops.
* Step 5: a critical alert, R1, with the audit entry numbers as evidence. `audit chain verifies: True`.

Say: "Keys never leave a device unwrapped. The server stores ciphertext and per-device wrapped keys only."

## 2. Vault: keys at rest (20 s)
Say, over the key files the demo creates: "Device, server and backup private keys can be sealed with a
passphrase: scrypt into AES-256-GCM, header authenticated. A wrong passphrase, one flipped byte, or a swapped
label is refused." Evidence: `python -m pytest -q tests/test_vault.py` (all pass).

Say the limit: "Python cannot wipe memory, and a passphrase given through the environment is visible to the
process owner. For production use a hardware key store."

## 3. Rotation and crash safety (30 s)
Same story output, steps 7 and 8:
* Step 7: a stored ciphertext is changed on disk. Result: `read refused: storage_corrupt`, and
  `doctor: FAIL blobs`. One edited audit line makes `doctor` fail too.
* Step 8: the process is killed in the middle of a key rotation (`rotate_mid_commit`). After restart Ravi still
  reads the file, the audit log shows `file.rotate_prepared` then `file.rotate_recovered`, and the chain is valid.

Say: "A crash never loses or half-applies a rotation."

## 4. Revocation across 3 real nodes (60 s)
Command: `python -m kig.demo --net`   (takes about 7 s)

Expected shape of the output:
```
"simulated": false,
"note": "three OS processes over TCP on one host (loopback), one clock; not a WAN measurement",
"processes": 3,
"revocation_to_last_node_ms": { "min": ..., "median": ..., "max": ... },
"partition": { "node": "node-c", "inside_lease": "served", "after_lease": "node_stale", "after_heal": "revoked" }
```
Say: "These are three separate operating-system processes talking over TCP. The lost device is refused on all
three, on this machine in tens of milliseconds (about 35 ms on the machine we measured; the run prints the current figure)."

Then the partition line: "Cut one node off from the primary. For the length of its lease, 2 seconds in this
test, it can still serve the lost device. After the lease it refuses everyone with `node_stale`. When the
network heals it learns the revocation. It fails closed, and a revocation is never undone."

For a longer run: `python -m kig.netcluster --runs 10`.

## 5. Backup and restore (30 s)
Command: `python -m pytest -q tests/test_backup.py`

Say: "A backup is a tar file. The state, audit log and revoked list are sealed to an offline backup key; the
whole backup is signed by the service. Flip any byte, truncate it, use the wrong key, or use another service's
backup, and restore refuses and writes nothing. An older valid backup is refused unless you say so, and even
then revocations newer than the backup are kept."

Optional speed figures: `python -m kig.bench` prints put, fetch, rotate, backup and restore times for 100, 500
and 2000 files. Read them off the screen.

Say: "The backup key can be split k-of-n with `kig backup-key`, using a vetted Shamir implementation. We wrote no
secret-sharing maths."

## 6. Honest limits (40 s, say all of them)
* A revoked device keeps what it already decrypted. Rotation protects later versions only.
* The three nodes share one machine, one clock and loopback. The numbers are not a network measurement.
* Sync between nodes is plain HTTP in this prototype. Across hosts it needs TLS.
* The cluster token is shared. Whoever holds it can make nodes pull a full snapshot again and again.
* The root of trust is trust on first use unless a fingerprint is pinned out of band.
* A stolen full admin device is an admin until the host removes it.
* Python cannot wipe key bytes from memory.

Close: "Nothing custom in the cryptography. Everything shown is covered by tests that run on Python 3.12 and 3.13."

## If something goes wrong on camera
* `--net` prints a port or startup error: run it again. Each start retries on fresh ports.
* Tests are slow: the full suite takes about 2.5 minutes. Do not run it live. Show the step you need.

## Optional: the web console (screen recording)
Command: `bash web/run_demo.sh` (needs Node 20+; it builds the app, starts the service, the local backend and the console, seeds a lost-phone story and prints the address and two tokens).
Open http://localhost:4173. Operator console: paste the operator token, show the two alerts with device, user, node and event, then "Verify chain" and say it is the service checking itself; the independent check is `verifier/prism_verify.py`. Device holder: paste the session token, show files, the lost phone and the activity list. See web/README.md for limits.
