# Security

P.R.I.S.M. is a hackathon project (DevForge Yugaantar, Track 4). It has not had an outside audit.

## Report a problem

Use GitHub Security Advisories: https://github.com/Aditya2375/PRISM/security/advisories/new (private to the
maintainers). Please include steps to reproduce. There is no bug bounty.

## What is and is not claimed

* The exact guarantees, and the attacks that are out of scope, are in `THREAT_MODEL.md` and `docs/CORE.md`.
* All cryptography comes from the pinned `cryptography` library (ML-KEM-768 with X25519 in HPKE, AES-256-GCM,
  ML-DSA-65, scrypt). The project adds no cryptographic primitive of its own. `docs/CRYPTO.md` lists the
  constructions and the known-answer tests that check them.
* Python cannot wipe key material from memory. A revoked device keeps what it already decrypted.
* Cluster nodes in this repository are in-process simulations.
