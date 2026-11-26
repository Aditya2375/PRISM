# Related systems (only where we use or mirror an idea)

We compare P.R.I.S.M. with two public systems whose published documents we read. We make no claim about others.

## HashiCorp Vault: split the key that protects everything

Vault's default seal uses Shamir's Secret Sharing to split its root key into a configured number of shares, and a
threshold of them must be presented to reconstruct it (Vault docs: Seal/Unseal, `operator init`
`-key-shares` and `-key-threshold`). P.R.I.S.M. uses the same idea for one secret, the backup private key
(`kig backup-key split`, see `docs/CORE.md`). Differences: Vault runs the unseal process inside a server; ours is an
offline command. Vault also offers auto unseal through an HSM or KMS; we ship no such driver (`kig/keystore.py` is only
the interface). We did not write the sharing maths: the split uses PyCryptodome's Shamir implementation.

Sources: https://developer.hashicorp.com/vault/docs/concepts/seal and
https://developer.hashicorp.com/vault/docs/commands/operator/init

## Sigstore Rekor: a signed commitment to the log's state

Rekor's checkpoint is a commitment by the log to its current state (root hash and size) signed with the log's key; a
client verifies the checkpoint, then an inclusion proof against it (Rekor specification). Our audit log
publishes the same kind of thing in a simpler form: a signed head hash (`audit.head`), and `--expect-head` in
`verifier/prism_verify.py` compares the log's end with a head you recorded elsewhere. What we do not have, and Rekor
does: a Merkle tree, so no logarithmic inclusion proofs, no consistency proofs between two heads, and no independent
witnesses cosigning checkpoints. Our log is a linear hash chain that you re-read in full. An anchor stored beside
the log is not independent, which is why the verifier says completeness is not established unless you give it a
head from somewhere else.

Sources: https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md and
https://github.com/sigstore/architecture-docs/blob/main/rekor-v2-spec.md

## Not compared

We did not study TUF or key-transparency systems for this project and draw no conclusions from them.
