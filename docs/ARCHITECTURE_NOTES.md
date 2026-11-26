# Architecture paragraphs for the two-page brief (core part)

## Key management and revocation

Every device holds two private keys: an ML-DSA-65 key that signs its requests, and a hybrid ML-KEM-768 and X25519
key that unwraps file keys. A file is encrypted on the device with a random AES-256-GCM key. That key is wrapped
separately for each eligible device, so the server stores only ciphertext and wrapped keys and never holds
anything that opens a file. Private keys at rest are sealed with a passphrase (scrypt into AES-256-GCM). All
primitives come from one pinned, vetted library, with a second vetted library used only for k-of-n splitting of
the backup key. Nothing is custom. Each file version carries a device-signed manifest of its access list, and
clients check it and pin the writers. When a device is reported lost, the service records the revocation in an
append-only file before anything else, refuses the device from then on, and marks its files for re-keying. The
next legitimate read creates a new file key wrapped only for the remaining devices. Every decision is a signed
entry in a hash-chained audit log, and each alert names the entries that triggered it. A crash at any point in a
rotation or revocation is recovered on restart: the revoked set never shrinks, and the audit chain still verifies.

## Three nodes and the lease

One primary takes writes and two replicas serve reads, each as a separate operating-system process with its own
keys, data and audit log. The primary pushes a signed revocation certificate to each replica, and a replica also
pulls a signed snapshot, certificates and blobs, and carries a signed freshness proof. A replica that has not
confirmed it is current within its lease refuses every request with `node_stale`: it fails closed. A replica cut
off from the primary can therefore still serve a lost device for up to one lease (2 seconds in the real-process
test, 5 seconds in the in-process simulation), and after that it serves nobody until it syncs. On one machine, a
revocation reached the last node in about 40 to 50 ms at the median; `python -m kig.netcluster` prints the
current figure.

## What this does not protect against

A revoked device keeps everything it decrypted before the revocation, and rotation protects only later versions.
The three processes share one host, one clock and loopback, so the timings are not a network measurement. Sync
traffic is plain HTTP and needs TLS across hosts, and the cluster token is shared, so a holder can force repeated
snapshots. The root of trust is trust on first use unless a fingerprint is pinned out of band. A stolen full
admin device remains an admin until the host removes it. Python cannot wipe key material from memory, and no
hardware key store driver is shipped.

## Note for the brief owner
`docs/BRIEF.md`, `docs/CORE_HARDENING.md` and `README.md` still say the cluster is an in-process simulation.
`docs/REVOCATION.md` now describes both the simulation and the real three-process version.
