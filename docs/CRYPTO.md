# PRISM cryptography: what we use, what we claim

Suite id (written into every key file, vault file, state file and backup, refused if different):
`PRISM-1:HPKE(MLKEM768-X25519,HKDF-SHA256,ChaCha20Poly1305)+AES-256-GCM+ML-DSA-65+scrypt`

## No custom crypto
Every primitive is called from the pinned `cryptography>=50.0.2` package. PRISM does not implement a cipher,
hash, KDF, KEM, signature scheme or mode, and does not combine two secrets itself. What PRISM writes is
protocol glue: which key encrypts what, and what bound data goes into the associated data.

| Need | Primitive (from `cryptography`) | Where |
| --- | --- | --- |
| Protect a file key for a device or the backup key | HPKE (RFC 9180) with the library's hybrid KEM `MLKEM768_X25519`, HKDF-SHA256, ChaCha20-Poly1305 | `crypto.kem_encaps`, `kem_decaps` |
| Encrypt file content, backups, key files | AES-256-GCM, random 96-bit nonce, one fresh key per file version | `crypto.aead_encrypt` |
| Sign state, snapshots, certificates, backups, audit entries | ML-DSA-65 (FIPS 204), purpose string prefixed to the message | `crypto.sign`, `verify` |
| Passphrase to key | scrypt N=2^15 r=8 p=1, random salt, parameters authenticated | `vault.seal` |
| Key commitment | HMAC-SHA256 keyed with the file key over file id and version | `client._commit` |
| Hashes | SHA-256 | blob names, audit chain |

Evidence that the pinned library implements the standards: `tests/test_crypto_proof.py` runs NIST ACVP
vectors (usnistgov/ACVP-Server, commit pinned in `tests/vectors/acvp.json`): 25 ML-DSA-65 key generation
cases, 25 ML-KEM-768 key generation cases and the ML-DSA-65 signature verification cases that use an empty
context, which is what the library's API exposes.

## Key hierarchy
1. Per file version: a random 256-bit file key (DEK) encrypts the content. It is never sent to the service.
2. The DEK is wrapped once per eligible device with the hybrid KEM. Binding data (file id, device id, version,
   purpose) is in the HPKE `info` and in the AEAD associated data, so a wrap cannot be replayed for another file,
   device or version.
3. A rotation creates a new DEK and new wraps for the devices still eligible. A revoked device gets no wrap.
4. The service signs state, backups and audit entries with its own ML-DSA-65 key. Devices sign each request.
5. Backups are sealed to an offline backup key (hybrid KEM) and signed by the service.

## What we claim, and what we do not
* Confidentiality of keys in transit and at rest is hybrid: an attacker needs to break both X25519 and
  ML-KEM-768. If only one is broken, the other still protects it.
* Signatures are **post-quantum only** (ML-DSA-65). They are not hybridised with a classical signature, so
  authenticity rests on ML-DSA alone. This was a deliberate choice to avoid writing a composite scheme.
* A revoked device keeps what it already decrypted. Rotation protects later versions only.
* AES-GCM is not key-committing by itself. PRISM adds an HMAC commitment per file version and the client
  checks it before using the plaintext.
* Random 96-bit GCM nonces are safe here because each DEK encrypts one message. The vault and backup keys
  likewise encrypt one message per key or per salt.
* Python cannot zeroise memory. Keys live in process memory while in use.
* Libraries, not PRISM, are the trusted base for constant-time behaviour.

## Format guard
Unknown or missing suite ids are refused (`crypto.require_suite`). Frozen data written by this release is
opened by `tests/test_frozen_format.py`, so later changes cannot silently orphan existing data.
