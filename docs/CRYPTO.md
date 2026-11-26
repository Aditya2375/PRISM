# P.R.I.S.M. cryptography: what we use, what we claim

Suite id (written into every key file, vault file, state file and backup, refused if different):
`PRISM-1:HPKE(MLKEM768-X25519,HKDF-SHA256,ChaCha20Poly1305)+AES-256-GCM+ML-DSA-65+scrypt`

## No custom crypto
Every primitive is called from the pinned `cryptography>=50.0.2` package. P.R.I.S.M. does not implement a cipher,
hash, KDF, KEM, signature scheme or mode, and does not combine two secrets itself. What P.R.I.S.M. writes is
protocol glue: which key encrypts what, and what bound data goes into the associated data.

| Need | Primitive (from `cryptography`) | Where |
| --- | --- | --- |
| Protect a file key for a device or the backup key | HPKE (RFC 9180) with the library's `MLKEM768_X25519` hybrid KEM (an IETF draft construction, not an RFC), HKDF-SHA256, ChaCha20-Poly1305 | `crypto.kem_encaps`, `kem_decaps` |
| Encrypt file content, backups, key files | AES-256-GCM, random 96-bit nonce, one fresh key per file version | `crypto.aead_encrypt` |
| Sign state, snapshots, certificates, backups, audit entries | ML-DSA-65 (FIPS 204), purpose string prefixed to the message | `crypto.sign`, `verify` |
| Passphrase to key | scrypt N=2^15 r=8 p=1, random salt, parameters authenticated | `vault.seal` |
| Key commitment | HMAC-SHA256 keyed with the file key over file id and version | `client._commit` |
| Hashes | SHA-256 | blob names, audit chain |

Evidence about the library (`cryptography==50.0.2`, pinned in `requirements.txt`): `tests/test_crypto_proof.py`
runs NIST ACVP vectors (usnistgov/ACVP-Server, commit pinned in `tests/vectors/acvp.json`):
* ML-DSA-65 key generation: 25 cases, public key from seed.
* ML-KEM-768 key generation: 25 cases, encapsulation key from seed.
* ML-DSA-65 signature verification: exactly 1 case (an invalid signature, which must be rejected). The
  library's API takes no context string, so only vectors with an empty context can be expressed, and ACVP
  has only that one for ML-DSA-65.

Not independently tested: ML-KEM encapsulation and decapsulation (the library exposes no way to inject the
randomness or load an expanded key), the hybrid HPKE KEM, and ML-DSA signing. For those we test round trips,
tampering and cross-purpose rejection, and rely on the library for correctness.

## Key hierarchy
1. Per file version: a random 256-bit file key (DEK) encrypts the content. It is never sent to the service.
2. The DEK is wrapped once per eligible device with the hybrid KEM. The HPKE `info` carries the file id, device
   id and version; the AEAD that protects the DEK carries the file id and version. A wrap cannot be replayed for
   another file, device or version.
3. A rotation creates a new DEK and new wraps for the devices still eligible. A revoked device gets no wrap.
4. The service signs state, backups and audit entries with its own ML-DSA-65 key. Devices sign each request.
5. Backups are sealed to an offline backup key (hybrid KEM) and signed by the service.

## What we claim, and what we do not
* Confidentiality of keys in transit and at rest is hybrid: an attacker needs to break both X25519 and
  ML-KEM-768. If only one is broken, the other still protects it.
* Signatures are **post-quantum only** (ML-DSA-65). They are not hybridised with a classical signature, so
  authenticity rests on ML-DSA alone. This was a deliberate choice to avoid writing a composite scheme.
* A revoked device keeps what it already decrypted. Rotation protects later versions only.
* AES-GCM is not key-committing by itself. P.R.I.S.M. adds an HMAC commitment per file version and the client
  checks it before using the plaintext.
* Random 96-bit GCM nonces are safe here because each DEK encrypts one message. The vault and backup keys
  likewise encrypt one message per key or per salt.
* Python cannot zeroise memory. Keys live in process memory while in use.
* Libraries, not P.R.I.S.M., are the trusted base for constant-time behaviour.

* Symmetric margin: AES-256 keeps about 128-bit strength against Grover-style attacks. The KEM and signatures
  are the post-quantum parts.
* Transport security (TLS) is out of scope: the demo binds to localhost and deployment is assumed to add TLS.

## Format guard
* Carry a suite id and are refused if it differs or is missing: key files, vault files, `state.json`, backups.
  Nothing was released before this id existed, so there is no older format to upgrade from.
* Versioned by the `kig/v1/...` context strings inside HPKE `info` and AEAD associated data (a different
  version fails authentication): file ciphertext, wraps, snapshots and certificates (purpose strings).
* Unversioned: `revoked.log`, the audit log entries (signed, no suite field), and the client's seen-epoch file.
  Changing any of these would need a deliberate migration.
Frozen data written by this release is opened by `tests/test_frozen_format.py`.

## Naming
P.R.I.S.M. is the project. `PRISM` is the repo and the string in identifiers. `kig` (Key Identity Guard) is the
original code name of the Python package and is kept so teammates' branches keep importing.
