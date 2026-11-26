"""Tests for the Secure Messenger handshake protocol."""

import pytest
import os
import struct
import time as _time

from kig.channel import (
    Session, parse_client_hello, parse_server_hello,
    build_client_hello, build_server_hello,
    execute_handshake_initiator, execute_handshake_responder,
    handshake, set_session, get_session, remove_session,
    MSG_CLIENT_HELLO, MSG_SERVER_HELLO,
)
from kig.crypto_local import sig_keygen, sign, verify, kem_keygen, kem_encaps


def test_session_send_recv():
    """Test basic Session send/recv with replay protection."""
    # Use the SAME key for sending and receiving (simplified test)
    key = b'\x01' * 32
    s = Session(skey=key, rkey=key)

    # Send a message - AES-GCM ciphertext = len(plaintext) + 16 (tag)
    data_to_send = b"hello"
    framed = s.send(data_to_send)
    # framed = nonce(12) + ciphertext(len(plaintext)+16)
    expected_len = 12 + len(data_to_send) + 16
    assert len(framed) == expected_len, f"Expected {expected_len}, got {len(framed)}"

    # Receive the same message
    received, success = s.recv(framed)
    assert success is True, f"Decryption failed: {received}"
    assert received == data_to_send

    # Replay the same message - should be rejected (counter already seen)
    received2, success2 = s.recv(framed)
    assert success2 is False, "Replay should be detected"

    # Send a different message
    framed2 = s.send(b"world")
    received3, success3 = s.recv(framed2)
    assert success3 is True, f"Decryption failed for world: {received3}"
    assert received3 == b"world"


def test_handshake_initiator():
    """Test handshake initiator executes correctly."""
    sig_pk, sig_sk = sig_keygen()
    our_kem_pk, our_kem_sk = kem_keygen()

    session = execute_handshake_initiator(
        my_id="node1",
        their_id="node2",
        long_term_sk=sig_sk,
        their_kem_sk=our_kem_sk,
    )
    assert session is not None
    assert session.skey is not None
    assert session.rkey is not None
    remove_session("node1", "node2")


def test_handshake_responder():
    """Test handshake responder executes correctly."""
    sig_pk, sig_sk = sig_keygen()

    # Generate proper KEM key pairs for both nodes
    our_kem_pk, our_kem_sk = kem_keygen()
    their_kem_pk, their_kem_sk = kem_keygen()

    # Encapsulate to their KEM public key - this produces real KEM ct/ss
    ct, shared_secret = kem_encaps(their_kem_pk)

    # Build a client hello with proper KEM ciphertext
    eph_pk = b'\x00' * 32
    nonce = b'\x00' * 12
    timestamp = _time.time()

    # Sign the transcript
    transcript = b"node1" + eph_pk + ct + nonce + struct.pack('d', timestamp)
    signature = sign(sig_sk, transcript)
    client_hello = build_client_hello(eph_pk, ct, nonce, timestamp, signature)

    # Responder executes handshake with proper KEM keys
    session = execute_handshake_responder(
        my_id="node2",
        their_id="node1",
        long_term_sk=sig_sk,
        client_hello_parsed=parse_client_hello(client_hello),
        their_kem_sk=their_kem_sk,
    )
    assert session is not None
    assert session.skey is not None
    assert session.rkey is not None
    remove_session("node2", "node1")


def test_wrong_signer_rejected():
    """Test that handshake with wrong signer is rejected."""
    sig_pk1, sig_sk1 = sig_keygen()
    sig_pk2, sig_sk2 = sig_keygen()

    # Initiator with sig_sk1 produces a session
    session1 = execute_handshake_initiator(
        my_id="node1",
        their_id="node2",
        long_term_sk=sig_sk1,
        their_kem_sk=kem_keygen()[1],
    )
    assert session1 is not None

    # Now test responder with a DIFFERENT signing key (sig_sk2)
    # but the client hello was signed with sig_sk1, so verification should fail
    eph_pk = b'\x00' * 32
    # Use proper KEM ciphertext (not all zeros)
    their_kem_pk, their_kem_sk = kem_keygen()
    ct, _ = kem_encaps(their_kem_pk)
    nonce = b'\x00' * 12
    timestamp = _time.time()
    # Sign with CORRECT key (sig_sk1), but verify with WRONG key (sig_sk2)
    transcript = b"node1" + eph_pk + ct + nonce + struct.pack('d', timestamp)
    correct_sig = sign(sig_sk1, transcript)  # signed with key 1
    # Build client hello with the correct signature, but try verification with wrong key
    bad_client_hello = build_client_hello(eph_pk, ct, nonce, timestamp, correct_sig)

    parsed = parse_client_hello(bad_client_hello)
    # Responder uses sig_sk2 (wrong key) for verification
    session = execute_handshake_responder(
        my_id="node2",
        their_id="node1",
        long_term_sk=sig_sk2,  # wrong signer
        client_hello_parsed=parsed,
        their_kem_sk=their_kem_sk,
    )
    # Should be None (rejected: signature verified with wrong key)
    assert session is None, "Wrong signer should be rejected"

    remove_session("node1", "node2")


def test_sessions_derive_different_keys():
    """Test that two independent sessions derive different keys."""
    sig_pk1, sig_sk1 = sig_keygen()
    sig_pk2, sig_sk2 = sig_keygen()

    session1 = execute_handshake_initiator(
        my_id="node1", their_id="node2",
        long_term_sk=sig_sk1,
        their_kem_sk=kem_keygen()[1],
    )

    session2 = execute_handshake_initiator(
        my_id="node3", their_id="node4",
        long_term_sk=sig_sk2,
        their_kem_sk=kem_keygen()[1],
    )

    # Sessions should have different keys
    keys_differ = (session1.skey != session2.skey or session1.rkey != session2.rkey)
    assert keys_differ, "Two independent sessions should derive different keys"

    remove_session("node1", "node2")
    remove_session("node3", "node4")


def test_handshake_message_parsing():
    """Test that handshake messages parse correctly."""
    sig_pk, sig_sk = sig_keygen()

    # Build ClientHello and parse it
    eph_pk = b'\x00' * 32
    kem_ct = b'\x00' * 1120
    nonce = b'\x00' * 12
    timestamp = _time.time()
    # Use 3373-byte hybrid signature (64 Ed25519 + 3309 ML-DSA)
    signature = b'\x00' * 3373
    client_hello = build_client_hello(eph_pk, kem_ct, nonce, timestamp, signature)

    parsed = parse_client_hello(client_hello)
    assert parsed is not None
    assert parsed["msg_type"] == MSG_CLIENT_HELLO
    assert parsed["eph_pk"] == eph_pk
    assert parsed["kem_ct"] == kem_ct
    assert parsed["nonce"] == nonce
    assert abs(parsed["timestamp"] - timestamp) < 1e-6
    assert parsed["signature"] == signature

    # Test ServerHello parsing too
    server_hello = build_server_hello(kem_ct, eph_pk, nonce, timestamp, signature)
    parsed_s = parse_server_hello(server_hello)
    assert parsed_s is not None
    assert parsed_s["msg_type"] == MSG_SERVER_HELLO
    assert parsed_s["kem_ct"] == kem_ct
    assert parsed_s["server_eph_pk"] == eph_pk
    assert parsed_s["nonce"] == nonce
    # Use the same timestamp variable, not a new _time.time() call
    assert abs(parsed_s["timestamp"] - timestamp) < 1e-6
    assert parsed_s["signature"] == signature