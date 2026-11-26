import json

import pytest
from fastapi.testclient import TestClient

from kig import crypto as c
from kig.api import create_app
from kig.client import Client, Device
from kig.service import GuardService
from kig.webapi import HEADER, create_web_app
from conftest import Clock

TOKEN = "t" * 40
H = {HEADER: TOKEN}


def world(tmp_path):
    clock = Clock()
    svc = GuardService(tmp_path / "d", clock=clock)
    clock.tick(1)
    adm = Device.generate("asha-laptop", "asha")
    svc.bootstrap("asha", "asha-laptop", adm.sign_pub, adm.kem_pub)
    tc = TestClient(create_app(tmp_path / "d", svc))

    def transport(env):
        r = tc.post("/v1/command", content=json.dumps(env))
        if r.status_code != 200:
            from kig.service import Denied
            raise Denied(r.json().get("error", "error"), r.json().get("reason", ""), r.status_code)
        return r.json()

    a = Client(adm, transport, clock)
    a.call("create_user", user="ravi", role="member")
    phone, rav = Device.generate("asha-phone", "asha"), Device.generate("ravi-laptop", "ravi")
    a.call("enroll_device", **phone.public_args())
    a.call("enroll_device", **rav.public_args())
    return svc, clock, transport, a, Client(rav, transport, clock), Client(phone, transport, clock), adm, rav, phone


def web(client, **kw):
    return TestClient(create_web_app(client, TOKEN, cors_origins=kw.get("cors", [])), base_url="http://127.0.0.1")


def test_every_request_needs_the_session_token_and_a_local_host(tmp_path):
    _, _, _, a, r, _, *_ = world(tmp_path)
    w = web(a)
    assert w.get("/me").status_code == 401
    assert w.get("/me", headers={HEADER: "x" * 40}).status_code == 401
    assert w.get("/me", headers={HEADER: TOKEN[:-1]}).status_code == 401
    assert w.get("/me", headers=H).json()["user"] == "asha"
    for host in ("evil.example", "127.0.0.1.evil.example", "localhost.evil.example"):
        assert w.get("/me", headers={**H, "Host": host}).status_code == 400
    assert w.get("/me", headers={**H, "Host": "localhost:8788"}).status_code == 200
    with pytest.raises(ValueError):
        create_web_app(a, "short")


def test_upload_list_download_roundtrip_and_acl(tmp_path):
    _, _, _, a, r, *_ = world(tmp_path)
    wa, wr = web(a), web(r)
    body = {"file_id": "salary", "acl": ["ravi"], "content_b64": c.b64e(b"top secret numbers")}
    assert wa.post("/files", json=body, headers=H).status_code == 200
    assert [f["file_id"] for f in wa.get("/files", headers=H).json()["files"]] == ["salary"]
    dl = wa.get("/files/salary", headers=H)
    assert dl.content == b"top secret numbers" and dl.headers["content-type"] == "application/octet-stream"
    assert dl.headers["cache-control"] == "no-store" and dl.headers["x-content-type-options"] == "nosniff"
    assert wr.get("/files", headers=H).json()["files"][0]["file_id"] == "salary"
    # a file ravi is not on the ACL of
    wa.post("/files", json={"file_id": "board", "acl": [], "content_b64": c.b64e(b"x")}, headers=H)
    assert [f["file_id"] for f in wr.get("/files", headers=H).json()["files"]] == ["salary"]
    g = wr.get("/files/board", headers=H)
    assert g.status_code >= 400 and b"x" != g.content and "error" in g.json()


@pytest.mark.parametrize("payload", [
    {}, {"file_id": 1, "content_b64": "AA"}, {"file_id": "f", "content_b64": 5}, {"file_id": "f", "content_b64": "%%%"},
    {"file_id": "f", "acl": "ravi", "content_b64": "AA"}, {"file_id": "f", "acl": [1], "content_b64": "AA"},
    {"file_id": "../x", "content_b64": "AA"}, {"file_id": "f", "acl": ["nobody"], "content_b64": "AA"},
])
def test_bad_uploads_are_refused_without_a_crash(tmp_path, payload):
    _, _, _, a, *_ = world(tmp_path)
    r = web(a).post("/files", json=payload, headers=H)
    assert 400 <= r.status_code < 500 and "error" in r.json()


def test_body_that_is_not_json_or_not_an_object_or_too_big(tmp_path):
    _, _, _, a, *_ = world(tmp_path)
    w = web(a)
    assert w.post("/files", content=b"{not json", headers=H).status_code == 400
    assert w.post("/files", content=b"[1]", headers=H).status_code == 400
    assert w.post("/files", content=b"{" + b" " * (11 * 1024 * 1024) + b"}", headers=H).status_code == 413


def test_my_devices_shows_only_my_own_and_no_keys(tmp_path):
    *_, a, r, p, adm, rav, phone = (None,) * 0 or world(tmp_path)[3:]
    out = web(a).get("/devices", headers=H).json()
    assert {d["device"] for d in out["devices"]} == {"asha-laptop", "asha-phone"}
    assert [d["this"] for d in out["devices"]] == [True, False]
    assert "ravi-laptop" not in json.dumps(out)
    assert all(set(d) == {"device", "status", "enrolled_at", "this"} for d in out["devices"])
    assert [d["device"] for d in web(r).get("/devices", headers=H).json()["devices"]] == ["ravi-laptop"]


def test_report_lost_then_the_lost_device_is_locked_out_and_activity_shows_it(tmp_path):
    svc, _, _, a, r, p, *_ = world(tmp_path)
    wa, wp = web(a), web(p)
    a.put_file("salary", b"n", acl=["ravi"])
    assert wa.post("/devices/lost", json={"device": "asha-phone", "reason": "stolen"}, headers=H).status_code == 200
    assert wp.get("/files", headers=H).status_code >= 400          # the lost phone is refused by the service
    states = {d["device"]: d["status"] for d in wa.get("/devices", headers=H).json()["devices"]}
    assert states == {"asha-laptop": "active", "asha-phone": "lost"}
    types = [e["type"] for e in wa.get("/activity", headers=H).json()["entries"]]
    assert "device.lost" in types and "auth.revoked_device_use" in types
    # a member cannot report someone else's device lost
    assert web(r).post("/devices/lost", json={"device": "asha-laptop"}, headers=H).status_code == 403
    assert web(a).post("/devices/lost", json={"device": 5}, headers=H).status_code == 400


def test_activity_is_scoped_and_leaks_nothing_about_others(tmp_path):
    _, _, _, a, r, *_ = world(tmp_path)
    a.put_file("salary", b"n", acl=["ravi"])
    r.fetch("salary")
    mine = web(a).get("/activity", headers=H).json()["entries"]
    theirs = web(r).get("/activity", headers=H).json()["entries"]
    assert all(e["actor"].startswith("asha") or e["data"].get("device", "").startswith("asha") for e in mine)
    assert all(e["actor"] in ("ravi-laptop", "another user", "operator") or e["data"].get("device") == "ravi-laptop" for e in theirs)
    blob = json.dumps(mine) + json.dumps(theirs)
    assert "fingerprint" not in blob and "sign_pub" not in blob and "proof" not in blob
    assert "ravi-laptop" not in json.dumps([e for e in mine if e["type"] == "access.granted"])
    assert "asha-laptop" not in json.dumps(theirs) and "asha-phone" not in json.dumps(theirs)
    assert [e["seq"] for e in mine] == sorted((e["seq"] for e in mine), reverse=True)
    assert len(web(a).get("/activity?limit=2", headers=H).json()["entries"]) == 2
    assert len(web(a).get("/activity?limit=100000", headers=H).json()["entries"]) <= 100


@pytest.mark.parametrize("bad", [0, -1, 101, "5", True, 2.5, None])
def test_activity_limit_is_validated_by_the_service(tmp_path, bad):
    _, _, _, a, *_ = world(tmp_path)
    from kig.service import Denied
    with pytest.raises(Denied):
        a.call("my_activity", limit=bad)


def test_enrol_requires_a_fingerprint_and_a_mismatch_is_a_hard_error(tmp_path):
    svc, _, _, a, r, *_ = world(tmp_path)
    new = Device.generate("asha-tablet", "asha")
    wa = web(a)
    pv = wa.post("/devices/preview", json={"pub": new.public_args()}, headers=H).json()
    assert pv["fingerprint"] == new.fingerprint()
    assert wa.post("/devices/enroll", json={"pub": new.public_args()}, headers=H).status_code == 400
    assert wa.post("/devices/enroll", json={"pub": new.public_args(), "expect_fingerprint": " "}, headers=H).status_code == 400
    assert wa.post("/devices/enroll", json={"pub": new.public_args(), "expect_fingerprint": "0" * 8}, headers=H).status_code == 409
    both = {"pub": new.public_args(), "expect_fingerprint": new.fingerprint(), "unverified": True}
    assert wa.post("/devices/enroll", json=both, headers=H).status_code == 400
    ok = wa.post("/devices/enroll", json={"pub": new.public_args(), "expect_fingerprint": new.fingerprint()}, headers=H)
    assert ok.status_code == 200 and ok.json()["verified"] is True
    other = Device.generate("asha-watch", "asha")
    un = wa.post("/devices/enroll", json={"pub": other.public_args(), "unverified": True}, headers=H).json()
    assert un["verified"] is False


def test_enrol_by_a_non_admin_is_refused_by_the_service(tmp_path):
    _, _, _, a, r, *_ = world(tmp_path)
    new = Device.generate("ravi-phone", "ravi")
    out = web(r).post("/devices/enroll", json={"pub": new.public_args(), "expect_fingerprint": new.fingerprint()}, headers=H)
    assert out.status_code == 403


@pytest.mark.parametrize("pub", [{}, {"device": "x"}, "str", {"device": "a", "user": "b", "sign_pub": "x", "kem_pub": "y", "extra": "z"},
                                 {"device": 1, "user": "b", "sign_pub": "x", "kem_pub": "y"}])
def test_malformed_public_data_is_refused(tmp_path, pub):
    _, _, _, a, *_ = world(tmp_path)
    for path in ("/devices/preview", "/devices/enroll"):
        r = web(a).post(path, json={"pub": pub, "expect_fingerprint": "x"}, headers=H)
        assert r.status_code == 400


def test_no_response_ever_carries_a_secret(tmp_path):
    svc, _, _, a, r, *_ = world(tmp_path)
    w = web(a)
    w.post("/files", json={"file_id": "f", "acl": ["ravi"], "content_b64": c.b64e(b"abc")}, headers=H)
    outs = [w.get(p, headers=H).text for p in ("/me", "/files", "/devices", "/activity")]
    outs.append(w.get("/files/f", headers=H).text)
    secrets_ = [c.b64e(a.dev.sign_sec), c.b64e(a.dev.kem_sec), c.b64e(a.dev.sign_sec)[:40], c.b64e(a.dev.kem_sec)[:40],
                (tmp_path / "d" / "operator.token").read_text().strip()]
    for o in outs:
        for s in secrets_:
            assert s not in o
    assert "sign_sec" not in "".join(outs) and "kem_sec" not in "".join(outs)


def test_openapi_and_docs_are_not_served(tmp_path):
    _, _, _, a, *_ = world(tmp_path)
    w = web(a)
    for p in ("/docs", "/openapi.json", "/redoc"):
        assert w.get(p, headers=H).status_code == 404


def test_service_down_is_a_clean_502(tmp_path):
    _, _, _, a, *_ = world(tmp_path)
    def dead(env):
        raise ConnectionRefusedError("no")
    a.send = dead
    r = web(a).get("/files", headers=H)
    assert r.status_code == 502 and r.json()["error"] == "service_unreachable"


def test_cors_is_off_by_default_and_exact_when_on(tmp_path, monkeypatch):
    _, _, _, a, *_ = world(tmp_path)
    w = web(a)
    assert "access-control-allow-origin" not in w.get("/me", headers={**H, "Origin": "http://localhost:5173"}).headers
    ok = TestClient(create_web_app(a, TOKEN, cors_origins=["http://localhost:5173"]), base_url="http://127.0.0.1")
    pre = ok.options("/files", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
                                        "Access-Control-Request-Headers": HEADER})
    assert pre.status_code == 200 and HEADER in pre.headers["access-control-allow-headers"].lower()
    assert ok.get("/me", headers={"Origin": "http://localhost:5173"}).status_code == 401   # CORS is not auth
    for bad in ("*", "http://localhost:5173/"):
        with pytest.raises(ValueError):
            create_web_app(a, TOKEN, cors_origins=[bad])
    monkeypatch.setenv("KIG_CORS_ORIGINS", ",")
    with pytest.raises(ValueError):
        create_web_app(a, TOKEN)


def test_a_server_that_lies_about_a_file_is_refused_not_passed_on(tmp_path):
    svc, _, transport, a, r, *_ = world(tmp_path)
    a.put_file("f", b"real", acl=["ravi"])
    w = web(a)
    real = a.send
    def tampered(env):
        out = real(env)
        if env["cmd"] == "fetch":
            ct = bytearray(c.b64d(out["ciphertext"])); ct[0] ^= 1; out = dict(out, ciphertext=c.b64e(bytes(ct)))
        return out
    a.send = tampered
    g = w.get("/files/f", headers=H)
    assert g.status_code == 422 and g.json()["error"] == "refused" and b"real" not in g.content


def test_cli_entry_refuses_a_missing_key_file(tmp_path, capsys):
    from kig.webapi import main
    assert main(["--key", str(tmp_path / "nope.json"), "--url", "http://127.0.0.1:1"]) == 2
    assert main(["--key", "x", "--url", "u", "--port", "0"]) == 2


def test_cors_headers_ride_on_401_and_bad_host_answers_too(tmp_path):
    _, _, _, a, *_ = world(tmp_path)
    ok = TestClient(create_web_app(a, TOKEN, cors_origins=["http://localhost:5173"]), base_url="http://127.0.0.1")
    o = {"Origin": "http://localhost:5173"}
    r = ok.get("/me", headers=o)
    assert r.status_code == 401 and r.headers["access-control-allow-origin"] == "http://localhost:5173"
    r = ok.get("/me", headers={**o, **H, "Host": "evil.example"})
    assert r.status_code == 400 and r.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in ok.get("/me", headers={"Origin": "http://evil.example"}).headers


def test_ipv6_loopback_host_with_and_without_port(tmp_path):
    _, _, _, a, *_ = world(tmp_path)
    w = TestClient(create_web_app(a, TOKEN, cors_origins=[], port=8788), base_url="http://127.0.0.1")
    for host, code in (("[::1]", 200), ("[::1]:8788", 200), ("[::1]:9999", 400), ("127.0.0.1:8788", 200), ("127.0.0.1", 200),
                       ("localhost:8788", 200), ("127.0.0.1:1", 400), ("[::2]", 400), ("[::1]x", 400)):
        assert w.get("/me", headers={**H, "Host": host}).status_code == code, host


def test_command_names_are_short_lowercase_words_before_anything_is_logged(tmp_path):
    svc, _, _, a, r, p, *_ = world(tmp_path)
    n = len(svc.audit.entries)
    from kig.service import Denied
    for bad in ("<b>x", "A" * 65, "who ami", "", "whoami\n", "x" * 100000):
        with pytest.raises(Denied) as e:
            a.call(bad)
        assert e.value.status == 400
    assert len(svc.audit.entries) == n


def test_every_string_in_activity_is_capped(tmp_path):
    svc, _, _, a, *_ = world(tmp_path)
    a.call("report_lost", device="asha-phone", reason="r" * 5000)
    ents = web(a).get("/activity", headers=H).json()["entries"]
    lost = [e for e in ents if e["type"] == "device.lost"][0]
    assert len(lost["data"]["reason"]) <= 200
    assert all(len(v) <= 200 for e in ents for v in e["data"].values() if isinstance(v, str))
