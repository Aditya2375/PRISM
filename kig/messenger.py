"""End-to-end messenger with forward secrecy.

Handshake (three messages, both sides sign the transcript with long-term ML-DSA-65 keys):

  1. initiator -> responder: ids, session id, fresh hybrid KEM public key (X25519 + ML-KEM-768), signature
  2. responder -> initiator: its fresh hybrid KEM public key, secret s1 sealed to the initiator's
     ephemeral key (HPKE), signature over the transcript so far
  3. initiator -> responder: secret s2 sealed to the responder's ephemeral key, signature

Session keys = HKDF-SHA256(s1 || s2, salt = transcript hash). Ephemeral private keys are
dropped as soon as they are used. Long-term keys only sign, so leaking them later does not
open a recorded session.

Data messages are split into chunks. Each chunk is ChaCha20-Poly1305 sealed with the
direction key, the nonce comes from the strictly increasing sequence number, and the header
(sender, recipient, session, message, seq, idx, chunk count) is authenticated as AAD.
Replay state is persisted. A message is delivered only after every chunk authenticates.
"""
from __future__ import annotations

import json
import os
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto as c

CHUNK_BYTES = 1024
MAX_CHUNKS = 4096
TICKET_TTL_S = 300.0


class MessengerError(Exception):
    def __init__(self, code: str, reason: str = ""):
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code


@dataclass
class Identity:
    user: str
    pub: bytes
    sec: bytes = field(repr=False)

    @classmethod
    def generate(cls, user: str) -> "Identity":
        pub, sec = c.sig_keygen()
        return cls(user, pub, sec)


def _hkdf(secret: bytes, salt: bytes, info: bytes, n: int = 64) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(secret)


def _h(*parts: Any) -> bytes:
    return c.sha256_hex(c.canonical(list(parts))).encode()


@dataclass
class Session:
    sid: str
    me: str
    peer: str
    k_send: bytes = field(repr=False)
    k_recv: bytes = field(repr=False)
    send_seq: int = 0
    resumption_secret: bytes = field(default=b"", repr=False)


class Handshake:
    """Holds ephemeral private keys only until they are consumed."""

    def __init__(self, role: str, me: Identity, peer: str, sid: str):
        self.role, self.me, self.peer, self.sid = role, me, peer, sid
        self.eph_pub, self._eph_sec = c.kem_keygen()
        self.transcript: list[Any] = []
        self.s_mine: bytes | None = None

    def drop(self) -> None:
        self._eph_sec = None  # type: ignore[assignment]


class Endpoint:
    def __init__(self, ident: Identity, directory: dict[str, bytes], replay_path: str | Path | None = None,
                 clock: Callable[[], float] = time.time):
        self.id, self.dir, self.clock = ident, directory, clock
        self.sessions: dict[str, Session] = {}
        self.tickets: dict[str, dict[str, Any]] = {}
        self._buf: dict[tuple[str, str], dict[str, Any]] = {}
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._rp = Path(replay_path) if replay_path else None
        if self._rp and self._rp.exists():
            self._seen = {l for l in self._rp.read_text().splitlines() if l}
        self.stats: dict[str, int] = {}

    # ---------------------------------------------------------------- handshake
    def _peer_pub(self, user: str) -> bytes:
        if user not in self.dir:
            raise MessengerError("unknown_peer", user)
        return self.dir[user]

    def _sign(self, label: str, t: list[Any]) -> str:
        return c.b64e(c.sign(self.id.sec, "msg-hs-" + label, _h(*t)))

    def _check(self, user: str, label: str, t: list[Any], sig: str) -> None:
        if not c.verify(self._peer_pub(user), "msg-hs-" + label, _h(*t), c.b64d(sig)):
            raise MessengerError("bad_signature", f"handshake step {label}")

    def initiate(self, peer: str) -> tuple[Handshake, dict[str, Any]]:
        sid = os.urandom(12).hex()
        hs = Handshake("init", self.id, peer, sid)
        t = ["m1", self.id.user, peer, sid, c.b64e(hs.eph_pub)]
        hs.transcript = t
        return hs, {"t": "m1", "from": self.id.user, "to": peer, "sid": sid,
                    "epk": c.b64e(hs.eph_pub), "sig": self._sign("1", t)}

    def respond(self, m1: dict[str, Any]) -> tuple[Handshake, dict[str, Any]]:
        if m1.get("to") != self.id.user:
            raise MessengerError("wrong_recipient", "handshake not addressed to this identity")
        t1 = ["m1", m1["from"], m1["to"], m1["sid"], m1["epk"]]
        self._check(m1["from"], "1", t1, m1["sig"])
        if m1["sid"] in self.sessions:
            raise MessengerError("replay", "session id already used")
        hs = Handshake("resp", self.id, m1["from"], m1["sid"])
        ct1, s1 = c.kem_encaps(c.b64d(m1["epk"]), _h(*t1))
        hs.s_mine = s1
        t2 = t1 + ["m2", c.b64e(hs.eph_pub), c.b64e(ct1)]
        hs.transcript = t2
        return hs, {"t": "m2", "sid": m1["sid"], "epk": c.b64e(hs.eph_pub), "ct": c.b64e(ct1),
                    "sig": self._sign("2", t2)}

    def finish(self, hs: Handshake, m2: dict[str, Any]) -> tuple[Session, dict[str, Any]]:
        if m2.get("sid") != hs.sid:
            raise MessengerError("wrong_session", "reply is for a different session")
        t2 = hs.transcript + ["m2", m2["epk"], m2["ct"]]
        self._check(hs.peer, "2", t2, m2["sig"])
        try:
            s1 = c.kem_decaps(hs._eph_sec, hs.eph_pub, c.b64d(m2["ct"]), _h(*hs.transcript))
        except c.CryptoError as e:
            raise MessengerError("bad_handshake", str(e)) from None
        ct2, s2 = c.kem_encaps(c.b64d(m2["epk"]), _h(*t2))
        t3 = t2 + ["m3", c.b64e(ct2)]
        sig = self._sign("3", t3)
        sess = self._derive("init", hs.sid, hs.peer, s1, s2, t3)
        hs.drop()
        return sess, {"t": "m3", "sid": hs.sid, "ct": c.b64e(ct2), "sig": sig}

    def complete(self, hs: Handshake, m3: dict[str, Any]) -> Session:
        if m3.get("sid") != hs.sid:
            raise MessengerError("wrong_session", "confirmation is for a different session")
        t3 = hs.transcript + ["m3", m3["ct"]]
        self._check(hs.peer, "3", t3, m3["sig"])
        try:
            s2 = c.kem_decaps(hs._eph_sec, hs.eph_pub, c.b64d(m3["ct"]), _h(*hs.transcript))
        except c.CryptoError as e:
            raise MessengerError("bad_handshake", str(e)) from None
        sess = self._derive("resp", hs.sid, hs.peer, hs.s_mine, s2, t3)
        hs.drop()
        hs.s_mine = None
        return sess

    def _derive(self, role: str, sid: str, peer: str, s1: bytes, s2: bytes, transcript: list[Any]) -> Session:
        okm = _hkdf(s1 + s2, _h(*transcript), b"kig/msg/v1/keys", 96)
        k_i2r, k_r2i, rs = okm[:32], okm[32:64], okm[64:]
        s = Session(sid, self.id.user, peer, k_i2r if role == "init" else k_r2i,
                    k_r2i if role == "init" else k_i2r, resumption_secret=rs)
        self.sessions[sid] = s
        return s

    # ---------------------------------------------------------------- resumption
    def issue_ticket(self, sess: Session) -> dict[str, Any]:
        """Responder side. Single use, short lived, bound to the authenticated peer."""
        tid = os.urandom(16).hex()
        secret = _hkdf(sess.resumption_secret, tid.encode(), b"kig/msg/v1/ticket", 32)
        self.tickets[tid] = {"peer": sess.peer, "secret": secret, "exp": self.clock() + TICKET_TTL_S}
        return {"tid": tid, "secret": c.b64e(secret), "resp": self.id.user}

    def resume(self, ticket: dict[str, Any]) -> tuple[Session, dict[str, Any]]:
        sid, nonce = os.urandom(12).hex(), os.urandom(16).hex()
        t = ["resume", ticket["tid"], self.id.user, ticket["resp"], sid, nonce]
        msg = {"t": "resume", "tid": ticket["tid"], "from": self.id.user, "to": ticket["resp"],
               "sid": sid, "nonce": nonce, "sig": self._sign("r", t)}
        return self._resume_keys("init", sid, ticket["resp"], c.b64d(ticket["secret"]), nonce), msg

    def accept_resume(self, msg: dict[str, Any]) -> Session:
        tk = self.tickets.pop(msg.get("tid", ""), None)         # consumed whether or not it verifies
        if tk is None:
            raise MessengerError("ticket_invalid", "unknown or already used")
        if self.clock() > tk["exp"]:
            raise MessengerError("ticket_expired")
        if msg.get("from") != tk["peer"] or msg.get("to") != self.id.user:
            raise MessengerError("ticket_wrong_peer", "ticket is bound to a different identity")
        t = ["resume", msg["tid"], msg["from"], msg["to"], msg["sid"], msg["nonce"]]
        self._check(msg["from"], "r", t, msg["sig"])             # fresh proof of key possession
        if msg["sid"] in self.sessions:
            raise MessengerError("replay", "session id already used")
        return self._resume_keys("resp", msg["sid"], msg["from"], tk["secret"], msg["nonce"])

    def _resume_keys(self, role: str, sid: str, peer: str, secret: bytes, nonce: str) -> Session:
        okm = _hkdf(secret, (sid + nonce).encode(), b"kig/msg/v1/resume", 96)
        k_i2r, k_r2i = okm[:32], okm[32:64]
        s = Session(sid, self.id.user, peer, k_i2r if role == "init" else k_r2i,
                    k_r2i if role == "init" else k_i2r, resumption_secret=okm[64:])
        self.sessions[sid] = s
        return s

    # -------------------------------------------------------------------- data
    @staticmethod
    def _nonce(direction_peer: str, seq: int) -> bytes:
        return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")

    def seal(self, sess: Session, to: str, plaintext: bytes, chunk_bytes: int = CHUNK_BYTES) -> list[dict[str, Any]]:
        if to != sess.peer:
            raise MessengerError("wrong_recipient", "session is bound to a different peer")
        parts = [plaintext[i:i + chunk_bytes] for i in range(0, len(plaintext), chunk_bytes)] or [b""]
        if len(parts) > MAX_CHUNKS:
            raise MessengerError("too_large")
        mid, n = os.urandom(8).hex(), len(parts)
        out = []
        for idx, part in enumerate(parts):
            seq = sess.send_seq
            sess.send_seq += 1
            hdr = {"s": self.id.user, "r": to, "sid": sess.sid, "mid": mid, "seq": seq, "idx": idx, "n": n}
            ct = ChaCha20Poly1305(sess.k_send).encrypt(self._nonce(to, seq), part, c.canonical(hdr))
            out.append({"hdr": hdr, "ct": c.b64e(ct)})
        return out

    def _count(self, key: str) -> None:
        self.stats[key] = self.stats.get(key, 0) + 1

    def receive(self, wire: dict[str, Any]) -> dict[str, Any]:
        """Process one chunk. Returns {status: delivered|partial|rejected, ...}. Never raises on bad input."""
        def rej(code: str) -> dict[str, Any]:
            self._count(code)
            return {"status": "rejected", "reason": code}
        try:
            hdr, ct = wire["hdr"], c.b64d(wire["ct"])
            sid, sender, seq, idx, n, mid = hdr["sid"], hdr["s"], hdr["seq"], hdr["idx"], hdr["n"], hdr["mid"]
            if hdr["r"] != self.id.user:
                return rej("wrong_recipient")
            if not all(isinstance(x, int) and not isinstance(x, bool) for x in (seq, idx, n)) or not (0 <= idx < n <= MAX_CHUNKS) or seq < 0:
                return rej("bad_header")
            sess = self.sessions.get(sid)
            if sess is None:
                return rej("unknown_session")
            if sender != sess.peer:
                return rej("wrong_sender")
            key = f"{sid}|{sender}|{seq}"
            with self._lock:
                if key in self._seen:
                    return rej("replay")
                try:
                    pt = ChaCha20Poly1305(sess.k_recv).decrypt(self._nonce(sender, seq), ct, c.canonical(hdr))
                except InvalidTag:
                    return rej("bad_tag")
                m = self._buf.setdefault((sid, mid), {"n": n, "parts": {}})
                if m["n"] != n:
                    return rej("count_mismatch")
                if idx in m["parts"]:
                    return rej("duplicate_chunk")
                self._remember(key)
                m["parts"][idx] = pt
                if len(m["parts"]) == n:
                    del self._buf[(sid, mid)]
                    self._count("delivered")
                    return {"status": "delivered", "mid": mid, "plaintext": b"".join(m["parts"][i] for i in range(n))}
                return {"status": "partial", "mid": mid, "have": len(m["parts"]), "of": n}
        except (KeyError, TypeError, ValueError, c.CryptoError):
            return rej("malformed")

    def _remember(self, key: str) -> None:
        self._seen.add(key)
        if self._rp:
            self._rp.parent.mkdir(parents=True, exist_ok=True)
            with open(self._rp, "a") as fh:
                fh.write(key + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def missing(self, sid: str, mid: str) -> list[int]:
        m = self._buf.get((sid, mid))
        return [] if not m else [i for i in range(m["n"]) if i not in m["parts"]]


def connect(a: Endpoint, b: Endpoint) -> tuple[Session, Session]:
    """Run the full handshake between two in-process endpoints."""
    hs_a, m1 = a.initiate(b.id.user)
    hs_b, m2 = b.respond(m1)
    sa, m3 = a.finish(hs_a, m2)
    sb = b.complete(hs_b, m3)
    return sa, sb


class Net:
    """Deterministic lossy network: drop, duplicate and reorder with a fixed seed."""

    def __init__(self, loss: float = 0.0, dup: float = 0.0, reorder: bool = False, seed: int = 1):
        self.loss, self.dup, self.reorder, self.rnd = loss, dup, reorder, random.Random(seed)

    def carry(self, wires: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for w in wires:
            if self.rnd.random() < self.loss:
                continue
            out.append(w)
            if self.rnd.random() < self.dup:
                out.append(w)
        if self.reorder:
            self.rnd.shuffle(out)
        return out


def transfer(sender: Endpoint, sess: Session, receiver: Endpoint, data: bytes, net: Net,
             chunk_bytes: int = 256, rounds: int = 1) -> dict[str, Any]:
    """Send ``data``; each extra round retransmits only the chunks the receiver reports missing."""
    wires = sender.seal(sess, sess.peer, data, chunk_bytes)
    mid, sid = wires[0]["hdr"]["mid"], sess.sid
    result: dict[str, Any] = {"status": "partial", "reasons": {}, "rounds": 0, "chunks": len(wires), "sent": 0}
    pending = wires
    for r in range(rounds):
        result["rounds"] = r + 1
        result["sent"] += len(pending)
        for w in net.carry(pending):
            res = receiver.receive(w)
            if res["status"] == "rejected":
                result["reasons"][res["reason"]] = result["reasons"].get(res["reason"], 0) + 1
            elif res["status"] == "delivered":
                result.update(status="delivered", intact=res["plaintext"] == data)
        if result["status"] == "delivered":
            return result
        miss = set(receiver.missing(sid, mid))
        pending = [w for w in wires if w["hdr"]["idx"] in miss] if miss else wires
    result["missing"] = receiver.missing(sid, mid)
    return result
