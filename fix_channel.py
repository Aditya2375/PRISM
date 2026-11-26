"""Fix HKDF .finalize() -> .derive() and add public key derivation for verify."""
import re

content = open('C:\\Users\\Windows 11\\Desktop\\prism backend\\kig\\channel.py').read()

# Fix 1: Replace .finalize() with .derive(key_material) in both HKDF calls
old_finalize1 = """send_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-send').finalize()

    recv_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-recv').finalize()"""

new_derive1 = """send_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-send').derive(key_material)

    recv_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-recv').derive(key_material)"""

content = content.replace(old_finalize1, new_derive1)

# Fix 2: Add public key derivation before verify in execute_handshake_responder
# We need to derive the Ed25519 public key from the hybrid private key
# Insert after "    # 2. Verify client signature over transcript" section

# Find the verify call in responder and add pub key derivation before it
# The verify call is: sig_valid = verify(long_term_sk, transcript, client_sig)
# We need to first derive the pub key, then verify

# Actually, looking at the code flow, the simplest fix is to derive the Ed25519
# public key from the hybrid private key before calling verify.

# Let me find the exact location and add the derivation
# I'll add: ed25519_pk_bytes = _derive_ed25519_pk_from_sk(long_term_sk)
# then: ed25519_pk = Ed25519PublicKey.from_public_bytes(ed25519_pk_bytes)
# then: verify(ed25519_pk, transcript, client_sig)

# But I need to add the helper function. Let me just modify the verify call
# to use the derived public key instead.

# Strategy: Replace the verify call in the responder with derived pub key

# Find "sig_valid = verify(long_term_sk, transcript, client_sig)" in the responder
# and replace with derived pub key version

# Actually, let me just add the public key derivation right before the verify call.
# I'll insert after the transcript is built.

# Let me search for the pattern and add the derivation
pattern = "            sig_valid = verify(long_term_sk, transcript, client_sig)"
replacement = """            # Derive Ed25519 public key from hybrid private key
            ed25519_sk_bytes, _ = _split_sig_priv(long_term_sk)
            ed25519_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_sk_bytes)
            ed25519_pk = ed25519_sk.public_key()

            sig_valid = verify(ed25519_pk, transcript, client_sig)"""

content = re.sub(pattern, replacement, content, count=1)  # Only first occurrence (responder)

# Also need to add the _split_sig_priv import/function if not already there
# Check if _split_sig_priv is already in the file
if '_split_sig_priv' not in content:
    # Add the helper function after the existing helpers
    # Find a good place to add it
    pass

open('C:\\Users\\Windows 11\\Desktop\\prism backend\\kig\\channel.py', 'w').write(content)
print("Fixes applied")
print("Length:", len(content))