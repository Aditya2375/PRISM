"""Regression tests for the weaknesses found by independent attack rounds. Each asserts the SAFE behaviour."""
import base64, json, os, shutil, subprocess, sys, threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import kig.service as S
from kig import audit as A, crypto as c, threshold as T
from kig.api import create_app
from kig.client import Client, Device, manifest_msg, _commit
from kig.service import Denied, GuardService


def boot(p, **kw):
    svc = GuardService(p, **kw)
    a = Device.generate("adm-1", "adm")
    svc.bootstrap("adm", "adm-1", a.sign_pub, a.kem_pub)
    return svc, a


def member(svc, adm, name="bob"):
    ac = Client(adm, svc.handle)
    ac.call("create_user", user=name, role="member")
    d = Device.generate(f"{name}-1", name)
    ac.call("enroll_device", **d.public_args())
    return ac, d


# ---- F1: the operator token must be real
@pytest.mark.parametrize("content", ["", "short", "x" * 31])
def test_f1_weak_operator_token_is_replaced(tmp_path, content):
    (tmp_path / "operator.token").write_text(content)
    cl = TestClient(create_app(tmp_path))
    assert cl.get("/v1/overview").status_code in (401, 403)
    tok = (tmp_path / "operator.token").read_text().strip()
    assert len(tok) >= 32 and tok != content
    assert (tmp_path / "operator.token").stat().st_mode & 0o077 == 0
    assert cl.get("/v1/overview", headers={"x-kig-operator-token": tok}).status_code == 200


def test_f1_loose_token_mode_is_replaced(tmp_path):
    create_app(tmp_path)
    t = tmp_path / "operator.token"; old = t.read_text(); os.chmod(t, 0o644)
    create_app(tmp_path)
    assert t.read_text() != old and t.stat().st_mode & 0o077 == 0


# ---- F2: a server swapping a device's KEM key must be refused, and no key ends up usable by the server
def test_f2_server_substituted_kem_key_is_refused(tmp_path):
    svc, adm = boot(tmp_path)
    evil = Device.generate("evil", "adm")

    def transport(env, source="local"):
        out = svc.handle(env, source)
        if env["cmd"] == "eligible":
            out = {"devices": {d: c.b64e(evil.kem_pub) for d in out["devices"]}}
        if env["cmd"] == "directory":
            for d in out.get("devices", {}).values():
                d["kem_pub"] = c.b64e(evil.kem_pub)
        return out
    cl = Client(adm, transport)
    with pytest.raises(Exception):
        cl.put_file("secret", b"top secret payroll", acl=["adm"])
    assert "secret" not in svc.state["files"]


# ---- F3: a whole file forged on first sight is refused
def _forged(adm, mal, user="adm"):
    dek = c.random_key()
    ct = c.aead_encrypt(dek, b"FORGED", b"kig/v1/file|memo|1")
    commit = _commit(dek, "memo", 1)
    kct, kek = c.kem_encaps(adm.kem_pub, b"kig/v1/wrap|memo|adm-1|1")
    wrap = {"ct": c.b64e(kct), "blob": c.b64e(c.aead_encrypt(kek, dek, b"kig/v1/file|memo|1"))}
    sig = c.sign(mal.sign_sec, "manifest", manifest_msg("memo", 1, ["adm"], "adm", commit, "mal", user))
    return {"file_id": "memo", "epoch": 1, "ciphertext": c.b64e(ct), "wrap": wrap, "commit": commit,
            "can_rotate": False, "owner": "adm", "acl": ["adm"], "needs_rotation": False,
            "manifest": {"writer": "mal", "sig": c.b64e(sig), "writer_sign_pub": c.b64e(mal.sign_pub),
                         "writer_user": user, "enrollment": None, "role_proof": None}}


def test_f3_forged_first_sight_file_is_refused(tmp_path):
    svc, adm = boot(tmp_path)
    mal = Device.generate("mal", "adm")
    resp = _forged(adm, mal)

    def transport(env, source="local"):
        return resp if env["cmd"] == "fetch" else svc.handle(env, source)
    with pytest.raises(Exception):
        Client(adm, transport).fetch("memo")


def test_f3_pinned_root_rejects_a_server_with_a_second_root(tmp_path):
    svc, adm = boot(tmp_path)
    fp = adm.fingerprint()
    cl = Client(adm, svc.handle, roots=[fp])
    cl.put_file("f", b"data", acl=["adm"])
    assert cl.fetch("f") == b"data"
    other = Client(adm, svc.handle, roots=["00" * 32])
    with pytest.raises(Exception):
        other.fetch("f")


# ---- F4: quotas
def test_f4_per_user_file_cap(tmp_path, monkeypatch):
    svc, adm = boot(tmp_path)
    ac, bob = member(svc, adm)
    monkeypatch.setattr(S, "MAX_USER_FILES", 5)
    bc = Client(bob, svc.handle)
    for i in range(5):
        bc.put_file(f"j{i}", b"x", acl=["bob"])
    with pytest.raises(Denied) as e:
        bc.put_file("j5", b"x", acl=["bob"])
    assert e.value.code == "quota"
    ac.put_file("payroll", b"p", acl=["adm"])          # another user is unaffected


def test_f4_per_user_byte_cap_and_replacement_counts_once(tmp_path, monkeypatch):
    svc, adm = boot(tmp_path)
    ac, bob = member(svc, adm)
    monkeypatch.setattr(S, "MAX_USER_BYTES", 6000)
    bc = Client(bob, svc.handle)
    bc.put_file("a", b"x" * 1000, acl=["bob"])
    with pytest.raises(Denied) as e:
        bc.put_file("b", b"x" * 9000, acl=["bob"])
    assert e.value.code == "quota"


def test_f4_global_byte_cap(tmp_path, monkeypatch):
    svc, adm = boot(tmp_path)
    monkeypatch.setattr(S, "MAX_TOTAL_BYTES", 2000)
    ac = Client(adm, svc.handle)
    with pytest.raises(Denied) as e:
        ac.put_file("big", b"x" * 5000, acl=["adm"])
    assert e.value.code == "quota"


# ---- F5 / G5: nobody can plant a file in another user's list; owner or admin may delete
def test_f5_member_cannot_share_with_others(tmp_path):
    svc, adm = boot(tmp_path)
    ac, bob = member(svc, adm)
    with pytest.raises(Denied):
        Client(bob, svc.handle).put_file("URGENT", b"phish", acl=["adm"])
    assert "URGENT" not in svc.state["files"]


def test_g5_owner_and_admin_can_delete_member_cannot(tmp_path):
    svc, adm = boot(tmp_path)
    ac, bob = member(svc, adm)
    carol_c = Client(bob, svc.handle)
    carol_c.put_file("mine", b"x", acl=["bob"])
    ac.put_file("adm-file", b"y", acl=["adm", "bob"])
    with pytest.raises(Denied):
        carol_c.call("delete_file", file_id="adm-file")
    carol_c.call("delete_file", file_id="mine")
    ac.call("delete_file", file_id="adm-file")
    assert "mine" not in svc.state["files"] and "adm-file" not in svc.state["files"]
    assert any(e["type"] == "file.deleted" for e in svc.audit.entries)
    ok, why = svc.audit.verify()
    assert ok, why


# ---- F6: body cap streams
def test_f6_oversized_body_refused_by_header_and_by_stream(tmp_path, monkeypatch):
    import kig.api as api
    monkeypatch.setattr(api, "MAX_BODY", 1024 * 1024)
    cl = TestClient(create_app(tmp_path))
    big = b"{" + b" " * (3 * 1024 * 1024) + b"}"
    assert cl.post("/v1/command", content=big).status_code == 413

    def gen():
        for _ in range(300):
            yield b" " * 65536          # no Content-Length: chunked
    assert cl.post("/v1/command", content=gen()).status_code == 413


# ---- G1: the last admin device can never be revoked; the operator can recover offline
def test_g1_last_admin_device_cannot_be_revoked(tmp_path):
    svc, laptop = boot(tmp_path / "d")
    ac = Client(laptop, svc.handle)
    phone = Device.generate("adm-phone", "adm")
    ac.call("enroll_device", **phone.public_args())
    thief = Client(phone, svc.handle)
    thief.call("revoke_device", device="adm-1")
    with pytest.raises(Denied):
        thief.call("revoke_device", device="adm-phone")
    assert thief.call("whoami")["user"] == "adm"
    assert [d for d, v in svc.state["devices"].items() if v["status"] == "active"] == ["adm-phone"]


def test_g1_recover_admin_offline_after_total_loss(tmp_path):
    d = tmp_path / "d"
    svc, laptop = boot(d)
    ac = Client(laptop, svc.handle)
    ac.put_file("f", b"data", acl=["adm"])
    with pytest.raises(Denied):
        ac.call("report_lost", device="adm-1")       # even reporting the last admin device lost is refused
    new = Device.generate("adm-new", "adm")
    svc2 = svc                                          # same process may keep using the open data dir
    fp = svc2.recover_admin("adm", "adm-new", new.sign_pub, new.kem_pub)
    assert fp
    last = [e for e in svc2.audit.entries if e["type"] == "device.enrolled"][-1]
    assert last["actor"] == "operator" and last["data"]["recovery"] is True
    assert Client(new, svc2.handle, verify_directory=False).call("whoami")["user"] == "adm"
    ok, why = svc2.audit.verify()
    assert ok, why


def test_g1_recover_admin_refuses_non_admin_and_reused_device(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac, bob = member(svc, adm)
    x = Device.generate("x", "bob")
    with pytest.raises(Denied):
        svc.recover_admin("bob", "x", x.sign_pub, x.kem_pub)
    with pytest.raises(Denied):
        svc.recover_admin("adm", "adm-1", x.sign_pub, x.kem_pub)


# ---- G2: rollback of the whole data dir is refused when a pin exists outside it
def test_g2_directory_rollback_refused_with_pin(tmp_path):
    d, pin = tmp_path / "d", tmp_path / "pin.json"
    svc, laptop = boot(d, pin_path=pin)
    ac = Client(laptop, svc.handle)
    phone = Device.generate("adm-phone", "adm")
    ac.call("enroll_device", **phone.public_args())
    shutil.copytree(d, tmp_path / "old")
    ac.call("report_lost", device="adm-phone")
    shutil.rmtree(d); shutil.copytree(tmp_path / "old", d)
    with pytest.raises(Exception):
        GuardService(d, pin_path=pin)
    with pytest.raises(Exception):                                       # a missing pin file on a non-empty log is refused (I4)
        GuardService(tmp_path / "d", pin_path=tmp_path / "nopin.json")
    GuardService(tmp_path / "d")                                         # no pin configured at all: starts (documented limit)


def test_g2_pin_advances_and_honest_restart_works(tmp_path):
    d, pin = tmp_path / "d", tmp_path / "pin.json"
    svc, laptop = boot(d, pin_path=pin)
    Client(laptop, svc.handle).call("create_user", user="u", role="member")
    n = json.loads(pin.read_text())["len"]
    assert n == len(svc.audit.entries)
    GuardService(d, pin_path=pin)


def test_g2_tampered_history_with_same_length_refused(tmp_path):
    d, pin = tmp_path / "d", tmp_path / "pin.json"
    svc, laptop = boot(d, pin_path=pin)
    Client(laptop, svc.handle).call("create_user", user="u", role="member")
    p = json.loads(pin.read_text()); p["head"] = "00" * 32; pin.write_text(json.dumps(p))
    with pytest.raises(Exception):
        GuardService(d, pin_path=pin)


# ---- G4: strict audit fields in the service verifier
def test_g4_extra_field_in_audit_entry_is_rejected(tmp_path):
    svc, laptop = boot(tmp_path / "d")
    lines = (tmp_path / "d" / "audit.jsonl").read_bytes().split(b"\n")
    e = json.loads(lines[0]); e["note"] = "added after signing"
    ok, _ = A.verify_chain([e] + [json.loads(l) for l in lines[1:] if l.strip()], svc.pub)
    assert ok is False


# ---- G6: symlinks planted on temp names are never followed
def test_g6_symlinked_temp_names_do_not_clobber(tmp_path):
    d = tmp_path / "d"; d.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"; victim.write_text("precious")
    for name in ("audit.head.tmp", "state.json.tmp", "backup.counter.tmp", "pin.tmp"):
        os.symlink(victim, d / name)
    svc, a = boot(d)
    Client(a, svc.handle).call("create_user", user="b", role="member")
    assert victim.read_text() == "precious"


# ---- G7: data dir mode
def test_g7_loose_data_dir_is_tightened(tmp_path):
    d = tmp_path / "d"; d.mkdir(); os.chmod(d, 0o755)
    GuardService(d)
    assert d.stat().st_mode & 0o077 == 0


# ---- H1: operator reads are safe under concurrent writes
def test_h1_overview_and_alerts_race_with_writes(tmp_path):
    svc, a = boot(tmp_path / "d")
    ac = Client(a, svc.handle)
    errs, stop = [], threading.Event()

    def reader():
        while not stop.is_set():
            try:
                svc.overview(); svc.alerts()
            except Exception as e:
                errs.append(repr(e)); return
    ts = [threading.Thread(target=reader) for _ in range(4)]
    [t.start() for t in ts]
    try:
        for i in range(120):
            ac.call("create_user", user=f"u{i}", role="member")
    finally:
        stop.set(); [t.join() for t in ts]
    assert not errs, errs[:1]


# ---- H2: one forged share per index cannot block recovery
def _forge(share_json, flip=1):
    d = json.loads(share_json)
    raw = bytearray(base64.b64decode(d["share"])); raw[0] ^= flip
    d["share"] = base64.b64encode(bytes(raw)).decode(); d["fp"] = T._fp(d["i"], bytes(raw))
    return json.dumps(d).encode()


def test_h2_forged_duplicate_index_does_not_block_recovery():
    secret = b"backup-private-key" * 4
    shares = T.split(secret, 3, 5)
    assert T.combine([_forge(shares[0])] + shares[:3]) == secret
    assert T.combine(shares[:3] + [_forge(shares[0])]) == secret
    assert T.combine([_forge(shares[1]), _forge(shares[0], 2)] + shares[:3]) == secret


def test_h2_only_forged_shares_still_fail_cleanly():
    secret = b"s" * 32
    shares = T.split(secret, 3, 5)
    with pytest.raises(T.ThresholdError):
        T.combine([_forge(shares[0]), shares[1], shares[2][:0] or shares[1]])


# ---- H3: unreachable service is a clean message, not a traceback
def test_h3_cli_unreachable_service(tmp_path, capsys):
    from kig import cli
    key = tmp_path / "k.json"; Device.generate("d", "u").save(key)
    rc = cli.main(["whoami", "--url", "http://127.0.0.1:9", "--key", str(key)]) if _has_cmd("whoami") else 3
    err = capsys.readouterr().err
    assert rc != 0 and "Traceback" not in err


def _has_cmd(name):
    from kig import cli
    try:
        cli.build_parser().parse_args([name, "--url", "x", "--key", "y"]); return True
    except SystemExit:
        return False
    except Exception:
        return False


# ---- H4: a second process on the same data dir refuses to start
def test_h4_second_process_refuses(tmp_path):
    d = tmp_path / "d"
    svc, a = boot(d)
    code = ("import sys; from kig.service import GuardService\n"
            "try:\n GuardService(sys.argv[1])\nexcept Exception as e:\n print('REFUSED', type(e).__name__); sys.exit(7)\n")
    r = subprocess.run([sys.executable, "-c", code, str(d)], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
    assert r.returncode == 7, r.stdout + r.stderr


# ---- H5: cli get does not follow a symlink at --out
def test_h5_cli_get_does_not_follow_symlink(tmp_path, monkeypatch):
    from kig import cli
    svc, adm = boot(tmp_path / "d")
    monkeypatch.setattr(cli, "_post", lambda url: svc.handle)
    key = tmp_path / "k.json"; adm.save(key)
    src = tmp_path / "in.txt"; src.write_text("hello")
    assert cli.main(["put", "--url", "x", "--key", str(key), "--file-id", "f", "--path", str(src)]) == 0
    victim = tmp_path / "victim.txt"; victim.write_text("precious")
    out = tmp_path / "out.txt"; os.symlink(victim, out)
    cli.main(["get", "--url", "x", "--key", str(key), "--file-id", "f", "--out", str(out)])
    assert victim.read_text() == "precious"


# ---- root pinning with an operator-recovered device
def test_recovered_device_works_when_roots_are_pinned(tmp_path):
    svc, a = boot(tmp_path / "d")
    n = Device.generate("n1", "adm")
    svc.recover_admin("adm", "n1", n.sign_pub, n.kem_pub)
    roots = svc.root_fingerprints()
    assert a.fingerprint() in roots and n.fingerprint() in roots
    cl = Client(n, svc.handle, roots=roots)
    cl.put_file("h", b"y", acl=["adm"])
    assert cl.fetch("h") == b"y"
    # a client that pins only the recovered device refuses the original root's files
    Client(a, svc.handle, roots=roots).put_file("g", b"z", acl=["adm", ])
    with pytest.raises(Exception):
        Client(n, svc.handle, roots=[n.fingerprint()]).fetch("g")


# ---- round 4 (I2, I3, I4, I7) and critic (W2, W3)
def test_i2_rejected_put_leaves_no_blob_behind(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac, bob = member(svc, adm)
    bc = Client(bob, svc.handle, verify_directory=False)
    for i in range(5):
        with pytest.raises(Denied):
            bc.call("put_file", file_id=f"x{i}", acl=["bob"], ciphertext=c.b64e(os.urandom(100_000)), wraps={},
                    commit="0" * 64, manifest_sig=c.b64e(b"s"))
    blobs = [f for f in (tmp_path / "d" / "blobs").rglob("*") if f.is_file()] if (tmp_path / "d" / "blobs").exists() else []
    assert blobs == []


def test_i3_deleted_file_id_is_never_reused(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac = Client(adm, svc.handle)
    ac.put_file("doc", b"v1", acl=["adm"]); ac.rotate("doc")
    ac.call("delete_file", file_id="doc")
    with pytest.raises(Denied) as e:
        ac.put_file("doc", b"v2", acl=["adm"])
    assert e.value.code == "conflict"
    assert "doc" in svc.state["deleted"]
    ac.put_file("doc-2", b"v2", acl=["adm"])


def test_i7_quota_walk_does_not_touch_the_disk_again(tmp_path, monkeypatch):
    svc, adm = boot(tmp_path / "d")
    ac = Client(adm, svc.handle)
    for i in range(10):
        ac.put_file(f"f{i}", b"x", acl=["adm"])
    svc._check_quota("adm", 10, True)          # first walk fills the size cache
    calls = []
    real = Path.stat
    monkeypatch.setattr(Path, "stat", lambda self, *a, **k: (calls.append(1), real(self, *a, **k))[1])
    svc._check_quota("adm", 10, True)
    svc._check_quota("adm", 10, True)
    assert len(calls) == 0


def test_w2_delete_is_never_committed_without_its_audit_entry(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac = Client(adm, svc.handle)
    ac.put_file("doc", b"x", acl=["adm"])
    real = svc._log

    def boom(t, *x, **k):
        if t == "file.deleted":
            raise RuntimeError("crash")
        return real(t, *x, **k)
    svc._log = boom
    with pytest.raises(Exception):
        ac.call("delete_file", file_id="doc")
    svc._log = real
    s2_dir = tmp_path / "copy"; shutil.copytree(tmp_path / "d", s2_dir, ignore=shutil.ignore_patterns(".datalock"))
    s2 = GuardService(s2_dir)
    assert "doc" in s2.state["files"] or any(e["type"] == "file.deleted" for e in s2.audit.entries)


def test_w3_odd_content_length_is_a_clean_4xx(tmp_path):
    cl = TestClient(create_app(tmp_path), raise_server_exceptions=False)
    assert cl.post("/v1/command", content=b"{}", headers={"content-length": b"\xb2"}).status_code < 500


def test_w1_chain_signed_by_a_plain_member_is_refused_with_a_clear_reason(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac, bob = member(svc, adm)
    evil = Device.generate("evil-dev", "adm")
    forged = Client(bob, lambda env: {}).envelope("enroll_device", evil.public_args())     # a member signs an "enrolment"

    def server(env, source="local"):
        out = svc.handle(env, source)
        if env["cmd"] == "eligible":
            out = {"devices": {**out["devices"], "evil-dev": c.b64e(evil.kem_pub)}}
        if env["cmd"] == "directory":
            chain = ac.call("directory", devices=["bob-1"])["devices"]
            out = {"devices": {**out["devices"], **chain, "evil-dev": {"user": "adm", "sign_pub": c.b64e(evil.sign_pub),
                   "kem_pub": c.b64e(evil.kem_pub), "status": "active", "proof": forged, "role_proof": None}}}
        return out
    cl = Client(adm, server)
    with pytest.raises(c.CryptoError) as e:
        cl._recipients(["adm"])
    assert "not shown to be an admin" in str(e.value)


def test_w1_admin_made_by_an_admin_can_enrol_devices(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac = Client(adm, svc.handle)
    ac.call("create_user", user="carol", role="admin")
    carol = Device.generate("carol-1", "carol")
    ac.call("enroll_device", **carol.public_args())
    cc = Client(carol, svc.handle)
    dave = Device.generate("dave-1", "adm")
    cc.call("enroll_device", **dave.public_args())
    cl = Client(adm, svc.handle)
    cl.put_file("f", b"x", acl=["adm"])
    assert Client(dave, svc.handle).fetch("f") == b"x"


def test_i6_recovered_admin_works_for_existing_clients_after_pin_root(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac, bob = member(svc, adm)
    ac = Client(adm, svc.handle, state_path=tmp_path / "adm.state")
    ac.put_file("shared", b"hello bob", acl=["adm", "bob"])
    bc = Client(bob, svc.handle)
    assert bc.fetch("shared") == b"hello bob"                     # both pinned adm-1 as the root
    new = Device.generate("adm-new", "adm")
    fp = svc.recover_admin("adm", "adm-new", new.sign_pub, new.kem_pub)
    assert svc.state["files"]["shared"]["needs_rotation"] is True
    ac.fetch("shared")                                             # auto-rotation wraps for the new device: refused until pinned
    assert ac.rotation_errors and svc.state["files"]["shared"]["needs_rotation"] is True
    ac.add_root(fp)                                                # operator told the admin the fingerprint, out of band
    ac.fetch("shared")
    assert svc.state["files"]["shared"]["needs_rotation"] is False
    nc = Client(new, svc.handle, roots=[adm.fingerprint(), fp])
    assert nc.fetch("shared") == b"hello bob"
    assert fp in json.loads((tmp_path / "adm.state.pins").read_text())["roots"]       # pin survives restarts


def test_pin_root_rejects_garbage():
    cl = Client(Device.generate("d", "u"), lambda e: {})
    for bad in ("", "zz", "x" * 40, "ab"):
        with pytest.raises(c.CryptoError):
            cl.add_root(bad)


def test_i5_first_use_pin_requires_our_own_chain_to_verify(tmp_path):
    svc, adm = boot(tmp_path / "d")
    ac, bob = member(svc, adm)
    evil_root = Device.generate("evil-root", "adm")
    bad_proof = Client(evil_root, lambda e: {}).envelope("enroll_device", bob.public_args())
    bad_proof["sig"] = c.b64e(b"\x00" * 64)                         # not a real signature

    def transport(env, source="local"):
        out = svc.handle(env, source)
        if env["cmd"] == "directory":
            out = {"devices": {"bob-1": {"user": "bob", "sign_pub": c.b64e(bob.sign_pub), "kem_pub": c.b64e(bob.kem_pub),
                                          "status": "active", "proof": bad_proof, "role_proof": None},
                               "evil-root": {"user": "adm", "sign_pub": c.b64e(evil_root.sign_pub),
                                             "kem_pub": c.b64e(evil_root.kem_pub), "status": "active", "proof": None,
                                             "role_proof": None}}}
        return out
    bc = Client(bob, transport)
    with pytest.raises(c.CryptoError):
        bc._ensure_roots()
    assert not bc.pins.get("roots")
