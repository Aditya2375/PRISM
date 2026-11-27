"""Alerts carry structured identity: device, user, service, event, source (and the acting device)."""
from kig.client import Client, Device
from kig.service import Denied

from conftest import code

FIELDS = ("device", "user", "service", "event", "source", "actor")


def _alerts(w, rule):
    return [a for a in w.svc.alerts() if a["rule"] == rule]


def test_every_alert_has_all_identity_fields_as_strings(w):
    stolen = Client(w.alice_phone, w.svc.handle, w.clock)
    w.ops.call("report_lost", device="alice-phone", reason="stolen")
    w.clock.tick(5)
    assert code(stolen.fetch, "report") == "revoked"
    assert w.svc.alerts()
    for a in w.svc.alerts():
        for f in FIELDS:
            assert isinstance(a[f], str) and a[f], (a["rule"], f)


def test_revoked_device_use_names_device_user_node_event_and_source(w):
    stolen = Client(w.alice_phone, w.svc.handle, w.clock)
    w.ops.call("report_lost", device="alice-phone", reason="stolen")
    w.clock.tick(5)
    env = stolen.envelope("whoami")
    try:
        w.svc.handle(env, source="10.7.7.7")
    except Denied as e:
        assert e.code == "revoked"
    a = _alerts(w, "R1-REVOKED-DEVICE-USE")[0]
    assert a["device"] == "alice-phone"
    assert a["user"] == "alice"
    assert a["service"] == w.svc.name
    assert a["event"] == "auth.revoked_device_use"
    assert a["source"] == "10.7.7.7"


def test_privilege_escalation_names_the_promoted_user_and_the_actor(w):
    w.admin.call("create_user", user="mallory")
    cd = Device.generate("mallory-pc", "mallory")
    w.admin.call("enroll_device", **cd.public_args())
    w.clock.tick(30)
    w.admin.call("set_role", user="mallory", role="admin")
    a = _alerts(w, "R4-PRIVILEGE-ESCALATION")[0]
    assert a["user"] == "mallory" and a["event"] == "role.changed" and a["service"] == w.svc.name
    assert a["actor"] != "unknown"


def test_suppressed_burst_says_unknown_instead_of_guessing(w):
    for i in range(40):
        env = w.bob.envelope("whoami")
        env["device"] = f"ghost-{i}"
        try:
            w.svc.handle(env, source="10.2.2.2")
        except Denied:
            pass
    w.clock.tick(61)
    w.svc.handle(w.admin.envelope("whoami"), source="10.3.3.3")
    a = [x for x in _alerts(w, "R3-AUTH-FAILURE-BURST") if x["event"] == "auth.failures_suppressed"][0]
    assert a["device"] == "unknown" and a["user"] == "unknown" and a["source"] == "unknown"
    assert a["service"] == w.svc.name


def test_limited_device_removal_alert_names_device_and_user(w):
    # R5 data comes from the audit entry itself
    from kig.detect import Detector
    d = Detector(service="node-x")
    d.observe({"type": "device.enrolled", "seq": 1, "ts": 1.0, "actor": "operator", "data": {"user": "asha", "device": "asha-phone"}})
    out = d.observe({"type": "device.lost", "seq": 2, "ts": 2.0, "actor": "asha-laptop",
                     "data": {"device": "asha-phone", "user": "asha", "admin_limited_removed": True}})
    assert len(out) == 1
    a = out[0].as_data()
    assert (a["device"], a["user"], a["service"], a["event"], a["actor"]) == (
        "asha-phone", "asha", "node-x", "device.lost", "asha-laptop")


def test_replayed_log_rebuilds_device_owner_so_old_alerts_still_name_the_user():
    from kig.detect import Detector
    d = Detector(service="n")
    d.observe({"type": "device.enrolled", "seq": 1, "ts": 1.0, "actor": "operator", "data": {"user": "u1", "device": "dev1"}})
    out = d.observe({"type": "auth.replay", "seq": 2, "ts": 2.0, "actor": "dev1", "data": {"device": "dev1", "source": "1.2.3.4"}})
    a = out[0].as_data()
    assert a["user"] == "u1" and a["source"] == "1.2.3.4" and a["device"] == "dev1"


# ---- round 14 (attacker Q1): an unauthenticated device id is a claim, not an identity

import time
import pytest
from kig import crypto as c
from kig.service import GuardService


def _junk(dev_id, i):
    return {"cmd": "whoami", "device": dev_id, "ts": time.time(), "nonce": f"n{i}", "args": {}, "sig": c.b64e(b"\0" * 3309)}


def _boot(p):
    svc = GuardService(p, name="node-a")
    a = Device.generate("alice-laptop", "alice")
    svc.bootstrap("alice", "alice-laptop", a.sign_pub, a.kem_pub)
    return svc


def test_q1_id_with_at_sign_does_not_frame_a_real_device(tmp_path):
    svc = _boot(tmp_path / "d"); time.sleep(0.05)
    for i in range(3):
        with pytest.raises(Denied):
            svc.handle(_junk("alice-laptop@evil", i), source="203.0.113.9")
    a = [x for x in svc.alerts() if x["rule"] == "R3-AUTH-FAILURE-BURST"][-1]
    assert a["device"] == "unknown" and a["user"] == "unknown" and a["subject"] == "unauthenticated"
    assert a["source"] == "203.0.113.9"


def test_q1_unknown_device_burst_never_resolves_a_user(tmp_path):
    svc = _boot(tmp_path / "d"); time.sleep(0.05)
    for i in range(3):
        with pytest.raises(Denied):
            svc.handle(_junk("ghost", i), source="203.0.113.9")
    a = [x for x in svc.alerts() if x["rule"] == "R3-AUTH-FAILURE-BURST"][-1]
    assert (a["device"], a["user"]) == ("unknown", "unknown")


def test_q1_bad_signature_on_an_enrolled_device_names_it_and_says_the_sender_may_be_someone_else(tmp_path):
    svc = _boot(tmp_path / "d"); time.sleep(0.05)
    for i in range(3):
        with pytest.raises(Denied):
            svc.handle(_junk("alice-laptop", i), source="203.0.113.9")
    a = [x for x in svc.alerts() if x["rule"] == "R3-AUTH-FAILURE-BURST"][-1]
    assert a["device"] == "alice-laptop" and a["user"] == "alice"
    assert "may not be that device" in a["explanation"]
