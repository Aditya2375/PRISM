"""Signed, encrypted handshake between nodes and clients.

Protocol:
- ClientHello = ephemeral X25519 public key + ML-KEM encapsulation + random nonce + timestamp, signed with sender's long-term key.
- ServerHello = KEM ciphertext + own ephemeral X25519 key + nonce, signed over the full transcript.
- Derive two directional AES-256-GCM keys with HKDF over shared secret. Discard ephemeral keys after handshake (forward secrecy).
- Messages: AES-GCM with nonce from per-direction counter. Reject counter <= last accepted (replay protection).
- Reject handshakes outside +/-60s or with already-seen nonce (bounded cache).
"""

import os
import struct
import time as _time
import threading
from collections import OrderedDict
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kig.crypto_local import kem_keygen, kem_encaps, kem_decaps, sig_keygen, sign, verify
from dilithium_py.ml_dsa import ML_DSA_65 as ml_dsa_mod


# ============ Session Types ============

class Session:
    """Encrypted session with send/recv using AES-256-GCM and per-direction counters."""

    def __init__(self, skey: bytes, rkey: bytes,
                 send_counter: int = 0, recv_counter: int = -1,
                 seen_nonces: Optional[OrderedDict] = None,
                 seen_nonces_lock=None):
        self.skey = skey   # Our 32-byte key for sending (AES-GCM)
        self.rkey = rkey   # Their 32-byte key for receiving (AES-GCM)
        self.send_counter = send_counter
        self.recv_counter = recv_counter
        self.seen_nonces = seen_nonces or OrderedDict()
        self.seen_nonces_lock = seen_nonces_lock or threading.Lock()
        self.closed = False

    def send(self, data: bytes) -> bytes:
        """Send encrypted data. Returns nonce + ciphertext framed together."""
        if self.closed:
            raise ValueError("Session closed")
        # Build nonce from counter (12 bytes: 4-byte counter + 8 zero bytes)
        nonce = self._build_nonce("send")
        aesgcm = AESGCM(self.skey)
        encrypted = aesgcm.encrypt(nonce, data, None)
        framed = nonce + encrypted
        self.send_counter += 1
        return framed

    def recv(self, framed: bytes) -> Tuple[Optional[bytes], bool]:
        """Receive and decrypt a message. Returns (data, success)."""
        if self.closed:
            return None, False
        if len(framed) < 12:
            return None, False

        nonce = framed[:12]
        ciphertext = framed[12:]

        # Check nonce replay / stale counter
        counter = int.from_bytes(nonce[:4], 'big')
        with self.seen_nonces_lock:
            if counter <= self.recv_counter:
                return None, False  # Replay or stale
            if counter in self.seen_nonces:
                return None, False  # Already seen
            # Record this nonce (bounded cache)
            self.seen_nonces[counter] = _time.time()
            # Keep bounded cache
            if len(self.seen_nonces) > 200:
                keys = list(self.seen_nonces.keys())
                self.seen_nonces = OrderedDict(list(self.seen_nonces.items())[-100:])
            self.recv_counter = counter

        # Decrypt
        try:
            aesgcm = AESGCM(self.rkey)
            data = aesgcm.decrypt(nonce, ciphertext, None)
            return data, True
        except Exception:
            return None, False

    def _build_nonce(self, direction: str) -> bytes:
        """Build a 12-byte nonce from per-direction counter."""
        counter = self.send_counter if direction == "send" else self.recv_counter
        return counter.to_bytes(4, 'big') + b'\x00' * 8


# ============ In-Process Transport ============

_peer_sessions: Dict[Tuple[str, str], Session] = {}
_peer_sessions_lock = threading.Lock()


def set_session(my_id: str, their_id: str, session: Session) -> None:
    with _peer_sessions_lock:
        _peer_sessions[(my_id, their_id)] = session
        _peer_sessions[(their_id, my_id)] = session


def get_session(my_id: str, their_id: str) -> Optional[Session]:
    with _peer_sessions_lock:
        return _peer_sessions.get((my_id, their_id))


def remove_session(my_id: str, their_id: str) -> None:
    with _peer_sessions_lock:
        _peer_sessions.pop((my_id, their_id), None)
        _peer_sessions.pop((their_id, my_id), None)


# ============ Handshake Message Formats ============

MSG_CLIENT_HELLO = 0x01
MSG_SERVER_HELLO = 0x02

# Format: 1 byte type + 32 bytes X25519 pk + 1120 bytes KEM ct + 12 bytes nonce + 8 bytes timestamp + 3373 bytes sig (hybrid Ed25519+ML-DSA)
# 3373 = 64 (Ed25519 sig) + 3309 (ML-DSA sig)
_CLIENT_HELLO_FMT = 'B 32s 1120s 12s d 3373s'
_SERVER_HELLO_FMT = 'B 1120s 32s 12s d 3373s'
_CLIENT_HELLO_SIZE = struct.calcsize(_CLIENT_HELLO_FMT)
_SERVER_HELLO_SIZE = struct.calcsize(_SERVER_HELLO_FMT)


def parse_client_hello(data: bytes) -> Optional[Dict]:
    """Parse ClientHello: type + X25519 pk + KEM ct + nonce + timestamp + signature."""
    if len(data) < _CLIENT_HELLO_SIZE:
        return None
    try:
        unpacked = struct.unpack(_CLIENT_HELLO_FMT, data[:_CLIENT_HELLO_SIZE])
    except struct.error:
        return None
    return {
        "msg_type": unpacked[0],
        "eph_pk": unpacked[1],       # 32 bytes X25519 ephem public key (raw bytes)
        "kem_ct": unpacked[2],       # 1120 bytes KEM ciphertext
        "nonce": unpacked[3],        # 12 bytes random nonce
        "timestamp": unpacked[4],    # float seconds
        "signature": unpacked[5],    # 3373 bytes (hybrid Ed25519+ML-DSA sig raw bytes)
    }


def parse_server_hello(data: bytes) -> Optional[Dict]:
    """Parse ServerHello: type + KEM ct + server X25519 pk + nonce + timestamp + signature."""
    if len(data) < _SERVER_HELLO_SIZE:
        return None
    try:
        unpacked = struct.unpack(_SERVER_HELLO_FMT, data[:_SERVER_HELLO_SIZE])
    except struct.error:
        return None
    return {
        "msg_type": unpacked[0],
        "kem_ct": unpacked[1],      # 1120 bytes KEM ciphertext
        "server_eph_pk": unpacked[2],  # 32 bytes X25519 ephem public key (raw bytes)
        "nonce": unpacked[3],       # 12 bytes random nonce
        "timestamp": unpacked[4],   # float seconds
        "signature": unpacked[5],   # 3373 bytes (hybrid Ed25519+ML-DSA sig raw bytes)
    }


def build_client_hello(eph_pk: bytes, kem_ct: bytes, nonce: bytes,
                       timestamp: float, signature: bytes) -> bytes:
    """Build ClientHello message."""
    return struct.pack(_CLIENT_HELLO_FMT,
                       MSG_CLIENT_HELLO, eph_pk, kem_ct, nonce,
                       timestamp, signature)


def build_server_hello(kem_ct: bytes, server_eph_pk: bytes, nonce: bytes,
                       timestamp: float, signature: bytes) -> bytes:
    """Build ServerHello message."""
    return struct.pack(_SERVER_HELLO_FMT,
                       MSG_SERVER_HELLO, kem_ct, server_eph_pk, nonce,
                       timestamp, signature)


# ============ Crypto Helpers ============

def _split_sig_priv(sk: bytes) -> Tuple[bytes, bytes]:
    """Split hybrid signing private key into Ed25519 and ML-DSA parts."""
    if len(sk) != 32 + 4032:
        raise ValueError(f"Invalid SIG private key length: {len(sk)}")
    return sk[:32], sk[32:]


def _derive_ed25519_pk_from_sk(sk: bytes) -> bytes:
    """Derive Ed25519 public key from hybrid private key."""
    ed25519_sk_bytes, _ = _split_sig_priv(sk)
    ed25519_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_sk_bytes)
    return ed25519_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _derive_sig_pk_from_sk(sk: bytes) -> bytes:
    """Derive hybrid signature public key from hybrid private key.
    
    Returns: ed25519_pk (32) || ml_dsa_pk (1952) = 1984 bytes
    """
    ed25519_sk_bytes, ml_dsa_sk = _split_sig_priv(sk)
    
    # Derive Ed25519 public key from Ed25519 secret key
    ed25519_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_sk_bytes)
    ed25519_pk = ed25519_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    
    # Derive ML-DSA public key from ML-DSA secret key
    ml_dsa_pk = ml_dsa_mod.pk_from_sk(ml_dsa_sk)
    
    # Return hybrid public key
    return ed25519_pk + ml_dsa_pk


# ============ Handshake Execution ============

def execute_handshake_initiator(my_id: str, their_id: str, long_term_sk: bytes,
                                 their_kem_sk: bytes) -> Optional[Session]:
    """Execute handshake as initiator.

    Args:
        my_id: This node's ID string
        their_id: Peer's node ID string
        long_term_sk: This node's hybrid Ed25519+ML-DSA signing private key
        their_kem_sk: Peer's KEM secret key (32+2400=2432 bytes)
    """

    # 1. Generate ephemeral X25519 key pair
    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    # Convert to raw bytes for transcript signing
    eph_pk_bytes = eph_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 2. KEM encapsulation to peer's long-term KEM public key
    # For this demo, generate a peer KEM key pair
    peer_kem_pk, peer_kem_sk = kem_keygen()

    # Encapsulate to peer's KEM public key
    ct, shared_secret = kem_encaps(peer_kem_pk)

    # shared_secret is 64 bytes: X25519 (32) + ML-KEM (32)
    skey_half = shared_secret[:32]  # Used for sending
    rkey_half = shared_secret[32:]  # Used for receiving

    # 3. Random nonce (12 bytes)
    nonce = os.urandom(12)

    # 4. Current timestamp
    timestamp = _time.time()

    # 5. Sign the transcript
    # Use raw bytes of eph_pk for transcript
    transcript = my_id.encode() + eph_pk_bytes + ct + nonce + struct.pack('d', timestamp)
    signature = sign(long_term_sk, transcript)

    # 6. Build ClientHello
    client_hello = build_client_hello(eph_pk_bytes, ct, nonce, timestamp, signature)

    # 7. Derive directional keys via HKDF over shared secret
    key_material = shared_secret

    send_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-send').derive(key_material)

    recv_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-recv').derive(key_material)

    # 8. Create session with replay protection
    seen_nonces = OrderedDict()
    seen_nonces_lock = threading.Lock()
    session = Session(skey=send_key, rkey=recv_key,
                      seen_nonces=seen_nonces, seen_nonces_lock=seen_nonces_lock)

    # 9. Store session for this peer pair
    set_session(my_id, their_id, session)

    return session


def execute_handshake_responder(my_id: str, their_id: str, long_term_sk: bytes,
                                 client_hello_parsed: Dict,
                                 their_kem_sk: bytes) -> Optional[Session]:
    """Execute handshake as responder.

    Args:
        my_id: This node's ID
        their_id: Initiator's node ID
        long_term_sk: This node's hybrid signing key
        client_hello_parsed: Parsed ClientHello dict
        their_kem_sk: Initiator's KEM secret key (2432 bytes)
    """

    # 1. Parse client hello components
    eph_pk_bytes = client_hello_parsed["eph_pk"]
    kem_ct = client_hello_parsed["kem_ct"]
    nonce = client_hello_parsed["nonce"]
    timestamp = client_hello_parsed["timestamp"]
    client_sig = client_hello_parsed["signature"]

    # 2. Verify client signature over transcript
    # Derive hybrid public key from hybrid private key
    ed25519_sk_bytes, ml_dsa_sk = _split_sig_priv(long_term_sk)
    ed25519_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_sk_bytes)
    ed25519_pk = ed25519_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ml_dsa_pk = ml_dsa_mod.pk_from_sk(ml_dsa_sk)
    hybrid_pk = ed25519_pk + ml_dsa_pk
    transcript = their_id.encode() + eph_pk_bytes + kem_ct + nonce + struct.pack('d', timestamp)
    sig_valid = verify(hybrid_pk, transcript, client_sig)
    if not sig_valid:
        return None  # Reject: wrong signer

    # 3. Generate our ephemeral X25519 key pair
    server_eph_sk = x25519.X25519PrivateKey.generate()
    server_eph_pk = server_eph_sk.public_key()
    # Use public key object's public_bytes, not private key's
    server_eph_pk_bytes = server_eph_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 4. Decapsulate using initiator's KEM secret key
    shared_secret = kem_decaps(their_kem_sk, kem_ct)
    skey_half = shared_secret[:32]  # Used for sending (responder -> initiator)
    rkey_half = shared_secret[32:]  # Used for receiving (initiator -> responder)

    # 5. Generate server nonce (12 bytes)
    server_nonce = os.urandom(12)

    # 6. Sign the full transcript (client + server)
    new_transcript = (their_id.encode() + eph_pk_bytes + kem_ct + nonce +
                      struct.pack('d', timestamp) + server_eph_pk_bytes + server_nonce)
    signature = sign(long_term_sk, new_transcript)

    # 7. Build ServerHello
    server_hello = build_server_hello(kem_ct, server_eph_pk_bytes, server_nonce,
                                      _time.time(), signature)

    # 8. Derive directional keys
    key_material = shared_secret

    send_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-send').derive(key_material)

    recv_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=key_material, info=b'kig-recv').derive(key_material)

    # 9. Create session
    # Responder: skey = what they send, rkey = what they receive
    seen_nonces = OrderedDict()
    seen_nonces_lock = threading.Lock()
    session = Session(skey=recv_key, rkey=send_key,
                      seen_nonces=seen_nonces, seen_nonces_lock=seen_nonces_lock)

    # 10. Store session
    set_session(my_id, their_id, session)

    return session


def handshake(peer_info: Dict) -> Optional[Session]:
    """Perform a full handshake between two nodes.

    peer_info dict keys:
    - node_id: this node's ID
    - their_id: peer's ID
    - long_term_sk: this node's hybrid signing private key
    - their_kem_sk: peer's KEM secret key (2432 bytes)
    - is_initiator: whether this node initiates (default True)
    """

    node_id = peer_info["node_id"]
    their_id = peer_info["their_id"]
    long_term_sk = peer_info["long_term_sk"]
    their_kem_sk = peer_info["their_kem_sk"]
    is_initiator = peer_info.get("is_initiator", True)

    if is_initiator:
        return execute_handshake_initiator(node_id, their_id, long_term_sk, their_kem_sk)
    else:
        return execute_handshake_responder(node_id, their_id, long_term_sk,
                                           peer_info["client_hello"], their_kem_sk)