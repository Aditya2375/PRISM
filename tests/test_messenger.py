import copy

import pytest

from kig import crypto as c
from kig.messenger import Endpoint, Identity, MessengerError, Net, connect, transfer, TICKET_TTL_S


@pytest.fixture
def pair(tmp_path):
    a, b, m = Identity.generate("alice"), Identity.generate("bob"), Identity.generate("mallory")
    d = {"alice": a.pub, "bob": b.pub, "mallory": m.pub}
    ea, eb, em = (Endpoint(i, d, tmp_path / f"{i.user}.replay") for i in (a, b, m))
    sa, sb = connect(ea, eb)
    return ea, eb, em, sa, sb, d


def rd(ep, wires):
    return [ep.receive(w) for w in wires]


def test_roundtrip_and_chunking(pair):
    ea, eb, _, sa, sb, _ = pair
    msg = bytes(range(256)) * 20
    res = rd(eb, ea.seal(sa, "bob", msg, 300))
    assert res[-1]["status"] == "delivered" and res[-1]["plaintext"] == msg
    assert all(r["status"] == "partial" for r in res[:-1])
    back = rd(ea, eb.seal(sb, "alice", b"pong"))
    assert back[0]["plaintext"] == b"pong"


def test_duplicate_is_rejected(pair):
    ea, eb, _, sa, sb, _ = pair
    w = ea.seal(sa, "bob", b"once")[0]
    assert eb.receive(w)["status"] == "delivered"
    assert eb.receive(copy.deepcopy(w)) == {"status": "rejected", "reason": "replay"}


def test_replay_cache_survives_restart(pair, tmp_path):
    ea, eb, _, sa, sb, d = pair
    w = ea.seal(sa, "bob", b"once")[0]
    eb.receive(w)
    eb2 = Endpoint(Identity("bob", d["bob"], b""), d, tmp_path / "bob.replay")
    eb2.sessions = eb.sessions
    assert eb2.receive(copy.deepcopy(w))["reason"] == "replay"


def test_swapped_recipient_and_wrong_recipient_decrypt(pair):
    ea, eb, em, sa, sb, d = pair
    w = ea.seal(sa, "bob", b"for bob")[0]
    # attacker rewrites the recipient to mallory: header is authenticated
    w2 = copy.deepcopy(w); w2["hdr"]["r"] = "mallory"
    assert em.receive(w2)["reason"] == "unknown_session"
    # mallory (who has her own session with bob) cannot read a chunk meant for bob
    sm, _ = connect(em, eb)
    assert em.receive(copy.deepcopy(w))["reason"] == "wrong_recipient"
    # bob receiving the rewritten chunk fails the tag
    w3 = copy.deepcopy(w); w3["hdr"]["r"] = "bob"; w3["hdr"]["s"] = "alice"; w3["hdr"]["seq"] = 99
    assert eb.receive(w3)["reason"] == "bad_tag"
    with pytest.raises(MessengerError):
        ea.seal(sa, "mallory", b"x")                   # session is bound to bob


@pytest.mark.parametrize("field,val", [("mid", "ffff"), ("idx", 0), ("n", 2), ("seq", 7), ("sid", "00"), ("s", "mallory")])
def test_modified_header_rejected(pair, field, val):
    ea, eb, _, sa, sb, _ = pair
    w = ea.seal(sa, "bob", b"x" * 700, 256)[1]
    w["hdr"][field] = val
    assert eb.receive(w)["status"] == "rejected"


def test_cross_session_replay(pair):
    ea, eb, _, sa, sb, d = pair
    sa2, sb2 = connect(ea, eb)
    w = ea.seal(sa, "bob", b"s1")[0]
    w["hdr"]["sid"] = sa2.sid
    assert eb.receive(w)["reason"] == "bad_tag"


def test_partial_is_reported_not_delivered(pair):
    ea, eb, _, sa, sb, _ = pair
    wires = ea.seal(sa, "bob", b"y" * 1000, 256)
    res = rd(eb, wires[:-1])
    assert all(r["status"] == "partial" for r in res)
    assert eb.missing(sa.sid, wires[0]["hdr"]["mid"]) == [len(wires) - 1]
    bad = copy.deepcopy(wires[-1]); bad["ct"] = c.b64e(b"\x00" * 40)
    assert eb.receive(bad)["reason"] == "bad_tag"
    assert eb.receive(wires[-1])["status"] == "delivered"


def test_forward_secrecy_long_term_key_leak_does_not_open_recorded_session(tmp_path):
    ia, ib = Identity.generate("alice"), Identity.generate("bob")
    d = {"alice": ia.pub, "bob": ib.pub}
    ea, eb = Endpoint(ia, d), Endpoint(ib, d)
    # attacker records the whole wire exchange
    hs_a, m1 = ea.initiate("bob"); hs_b, m2 = eb.respond(m1)
    sa, m3 = ea.finish(hs_a, m2); sb = eb.complete(hs_b, m3)
    wire = ea.seal(sa, "bob", b"top secret message")
    assert hs_a._eph_sec is None and hs_b._eph_sec is None and hs_b.s_mine is None   # ephemerals dropped
    # session 1 over; the attacker later obtains EVERY long-term key
    leaked_sig = [ia.sec, ib.sec]
    long_term_kem = [c.kem_keygen() for _ in range(3)]       # whatever KEM keys the devices hold
    for pub, sec in long_term_kem:
        for ct in (m2["ct"], m3["ct"]):
            with pytest.raises(c.CryptoError):
                c.kem_decaps(sec, pub, c.b64d(ct), b"")
    # signatures prove identity but derive nothing: re-deriving from signatures yields the wrong key
    from kig.messenger import _hkdf, _h
    guess = _hkdf(b"".join(leaked_sig), b"x", b"kig/msg/v1/keys", 96)[:32]
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    with pytest.raises(InvalidTag):
        ChaCha20Poly1305(guess).decrypt(b"\0" * 4 + (0).to_bytes(8, "big"), c.b64d(wire[0]["ct"]), c.canonical(wire[0]["hdr"]))
    # the endpoints' own state for this session holds no ephemeral private key
    assert not any(isinstance(v, (bytes, bytearray)) and len(v) in (c.KEM_PQ_SEED + c.X_LEN,)
                   for v in vars(hs_a).values())


def test_handshake_rejects_impostor_and_unknown_peer(pair):
    ea, eb, em, sa, sb, d = pair
    hs, m1 = em.initiate("bob")
    m1["from"] = "alice"                                 # mallory claims to be alice
    with pytest.raises(MessengerError) as e:
        eb.respond(m1)
    assert e.value.code == "bad_signature"
    ghost = Endpoint(Identity.generate("ghost"), {"bob": d["bob"], "ghost": b""})
    _, m1 = ghost.initiate("bob")
    with pytest.raises(MessengerError):
        eb.respond(m1)


def test_handshake_tamper_in_transit(pair):
    ea, eb, _, _, _, _ = pair
    hs_a, m1 = ea.initiate("bob")
    hs_b, m2 = eb.respond(m1)
    m2["ct"] = m2["ct"][:-4] + "AAAA"
    with pytest.raises(MessengerError):
        ea.finish(hs_a, m2)


@pytest.mark.parametrize("loss", [0.10, 0.30])
def test_lossy_network_never_delivers_wrong_bytes(pair, loss):
    ea, eb, _, sa, sb, _ = pair
    data = bytes(range(256)) * 16
    for seed in range(20):
        r = transfer(ea, sa, eb, data, Net(loss=loss, dup=0.1, reorder=True, seed=seed), 256, rounds=1)
        assert r["status"] in ("delivered", "partial")
        if r["status"] == "delivered":
            assert r["intact"]
    # with retransmission of missing chunks it completes
    ok = 0
    for seed in range(20):
        r = transfer(ea, sa, eb, data, Net(loss=loss, dup=0.1, reorder=True, seed=100 + seed), 256, rounds=12)
        ok += r["status"] == "delivered"
    assert ok == 20


def test_resumption_single_use_bound_and_expiring(pair):
    ea, eb, em, sa, sb, d = pair
    tk = eb.issue_ticket(sb)
    s2a, msg = ea.resume(tk)
    s2b = eb.accept_resume(msg)
    assert eb.receive(ea.seal(s2a, "bob", b"resumed")[0])["plaintext"] == b"resumed"
    with pytest.raises(MessengerError) as e:
        eb.accept_resume(msg)                            # single use
    assert e.value.code == "ticket_invalid"
    tk = eb.issue_ticket(sb)
    _, mm = em.resume(tk)                                # mallory steals the ticket
    with pytest.raises(MessengerError) as e:
        eb.accept_resume(mm)
    assert e.value.code == "ticket_wrong_peer"
    tk = eb.issue_ticket(sb)
    _, m_ok = ea.resume(tk)
    m_bad = dict(m_ok); m_bad["sig"] = c.b64e(b"\0" * 3309)   # no fresh proof
    with pytest.raises(MessengerError):
        eb.accept_resume(m_bad)
    tk = eb.issue_ticket(sb)
    _, m3 = ea.resume(tk)
    eb.clock = lambda: 9e12
    with pytest.raises(MessengerError) as e:
        eb.accept_resume(m3)
    assert e.value.code == "ticket_expired"


def test_malformed_input_never_crashes(pair):
    ea, eb, *_ = pair
    for junk in [{}, {"hdr": 1, "ct": "x"}, {"hdr": {"s": "alice"}, "ct": "!!"}, {"hdr": {"s": "a", "r": "bob", "sid": "x", "mid": "m", "seq": -1, "idx": 0, "n": 1}, "ct": "AA=="},
                 {"hdr": {"s": "a", "r": "bob", "sid": "x", "mid": "m", "seq": 1, "idx": 5, "n": 1}, "ct": "AA=="}]:
        assert eb.receive(junk)["status"] == "rejected"
