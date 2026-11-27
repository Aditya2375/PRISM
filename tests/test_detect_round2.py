"""Alerts name identity and services; outside logs feed the detector; cross-service movement; uncertain ordering; R4."""
import json
import subprocess
import sys

from kig import ingest
from kig.client import Device
from kig.detect import Detector
from kig.service import Denied

from conftest import code  # noqa: F401


def _all(w, rule):
    return [a for a in w.svc.alerts() if a["rule"] == rule]


def _jl(rows):
    return [json.dumps(r) for r in rows]


def _feed(rows, **cfg):
    c = ingest.load_config(None)
    c.update(cfg)
    alerts, st = ingest.run(_jl(rows), c)
    return [a.as_data() for a in alerts], st


# ---- 3. identity and services on every alert

def test_suppressed_burst_names_the_claimed_identities_and_sources(w):
    for i in range(40):
        env = w.bob.envelope("whoami")
        env["device"] = "ghost-x"
        env["nonce"] = f"n{i}"
        try:
            w.svc.handle(env, source="10.2.2.2")
        except Denied:
            pass
    w.clock.tick(61)
    w.svc.handle(w.admin.envelope("whoami"), source="10.3.3.3")
    a = [x for x in _all(w, "R3-AUTH-FAILURE-BURST") if x["event"] == "auth.failures_suppressed"][0]
    assert "ghost-x@10.2.2.2" in a["identity"] and a["identity_verified"] is False
    assert "ghost-x" in a["explanation"]
    assert a["device"] == "unknown" and a["user"] == "unknown"     # a claim is never put in the proven fields


def test_every_alert_names_an_identity_and_services(w):
    for i in range(3):
        env = w.bob.envelope("whoami"); env["device"] = "nobody"
        try:
            w.svc.handle(env, source="10.9.9.9")
        except Denied:
            pass
    w.admin.call("create_user", user="eve", role="admin")
    assert w.svc.alerts()
    for a in w.svc.alerts():
        assert a["identity"] not in ("", "unknown"), a
        assert w.svc.name in a["services"] and a["services"] == sorted(a["services"])


def test_alert_services_list_every_service_in_the_evidence():
    rows = [{"ts": 1000 + i, "user": "mallory", "service": s, "event": "login", "status": "401", "ip": "6.6.6.6"}
            for i, s in enumerate(["web", "vpn", "mail"])]
    alerts, _ = _feed(rows)
    r3 = [a for a in alerts if a["rule"] == "R3-AUTH-FAILURE-BURST"][0]
    assert r3["identity"] == "mallory" and r3["identity_verified"] is False
    assert {"web", "vpn", "mail"} <= set(r3["services"])


# ---- 4. adapter

def test_jsonl_adapter_default_names():
    rows = [{"timestamp": "2026-01-01T00:00:00Z", "user": "dana", "service": "web", "event": "login_failed", "ip": "1.1.1.1"}] * 3
    alerts, st = _feed(rows)
    assert st["fed"] == 3 and st["skipped"] == 0
    a = [x for x in alerts if x["rule"] == "R3-AUTH-FAILURE-BURST"][0]
    assert a["identity"] == "dana" and a["source"] == "1.1.1.1" and "web" in a["services"]


def test_csv_adapter_with_renamed_fields_and_strptime(tmp_path):
    cfg = tmp_path / "map.json"
    cfg.write_text(json.dumps({"fields": {"ts": "when", "identity": "who", "service": "app", "event": "verb"},
                               "ts_format": "%d/%m/%Y %H:%M:%S", "events": {"logon_bad": "auth_failure"}}))
    log = tmp_path / "a.csv"
    log.write_text("when,who,app,verb,src\n" + "".join(f"01/02/2026 10:00:0{i},omar,erp,logon_bad,9.9.9.9\n" for i in range(3))
                   + "garbage,,,\n")
    out = subprocess.run([sys.executable, "-m", "kig.ingest", str(log), "--config", str(cfg)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    alerts = [json.loads(x) for x in out.stdout.splitlines()]
    assert any(a["rule"] == "R3-AUTH-FAILURE-BURST" and a["identity"] == "omar" and "erp" in a["services"] for a in alerts)
    summary = json.loads(out.stderr.strip().splitlines()[-1])["summary"]
    assert summary["fed"] == 3 and summary["skipped"] == 1


def test_bad_config_is_refused(tmp_path):
    cfg = tmp_path / "bad.json"
    cfg.write_text(json.dumps({"events": {"x": "not-a-kind"}}))
    out = subprocess.run([sys.executable, "-m", "kig.ingest", "-", "--config", str(cfg)], input="", capture_output=True, text=True)
    assert out.returncode == 2 and "unknown kind" in out.stderr


def test_revoked_credential_use_from_outside_log_is_critical_and_named():
    rows = [{"ts": 10, "user": "lee", "service": "idp", "event": "revoke", "device": "lee-token"},
            {"ts": 20, "user": "lee", "service": "api", "event": "revoked_use", "device": "lee-token", "ip": "5.5.5.5"}]
    alerts, _ = _feed(rows)
    a = [x for x in alerts if x["rule"] == "R1-REVOKED-DEVICE-USE"][0]
    assert a["severity"] == "critical" and a["identity"] == "lee" and {"idp", "api"} <= set(a["services"])


# ---- 5. cross-service lateral movement

def _access(ts, who, svc):
    return {"ts": ts, "user": who, "service": svc, "event": "read", "path": "/x"}


def test_established_identity_reaching_a_new_service_alerts_with_the_path():
    rows = [_access(0, "ravi", "web"), _access(100, "ravi", "web"), _access(4000, "ravi", "db")]
    alerts, _ = _feed(rows)
    a = [x for x in alerts if x["rule"] == "R6-LATERAL-SERVICE"]
    assert len(a) == 1 and a[0]["path"] == ["web", "db"] and a[0]["identity"] == "ravi"
    assert "web -> db" in a[0]["explanation"] and {"db"} <= set(a[0]["services"])


def test_fast_hop_chain_without_history_alerts_high():
    rows = [_access(0, "x", "web"), _access(5, "x", "files"), _access(9, "x", "payroll")]
    a = [x for x in _feed(rows)[0] if x["rule"] == "R6-LATERAL-SERVICE"]
    assert a and a[0]["severity"] == "high" and a[0]["path"] == ["web", "files", "payroll"]


def test_identity_still_learning_its_services_does_not_alert():
    rows = [_access(0, "new", "web"), _access(900, "new", "mail")]          # second usual service, first hour
    assert not [x for x in _feed(rows)[0] if x["rule"].startswith("R6")]


def test_benign_reuse_of_known_services_never_alerts():
    rows = [_access(t, "kim", s) for t in range(0, 4000, 50) for s in ("web",)] + [_access(4001, "kim", "web")]
    assert not [x for x in _feed(rows)[0] if x["rule"].startswith("R6")]


# ---- 6. uncertain ordering

def test_events_from_different_services_within_skew_are_flagged_uncertain():
    rows = [_access(0, "nia", "web"), _access(400, "nia", "web"), _access(4000, "nia", "db")]
    rows.insert(2, _access(3990, "nia", "vpn"))     # vpn 10 s before db: inside +/-30 s, order unknown
    a = [x for x in _feed(rows)[0] if x["rule"] == "R6-LATERAL-SERVICE"][-1]
    assert a["ordering"] == "uncertain" and "30s" in a["ordering_note"]


def test_far_apart_events_are_certain():
    rows = [_access(0, "nia", "web"), _access(400, "nia", "web"), _access(4000, "nia", "db")]
    a = [x for x in _feed(rows)[0] if x["rule"] == "R6-LATERAL-SERVICE"][0]
    assert a["ordering"] == "certain"


def test_out_of_order_beyond_skew_raises_r10():
    rows = [_access(1000, "ola", "web"), _access(900, "ola", "db")]
    a = [x for x in _feed(rows)[0] if x["rule"] == "R10-OUT-OF-ORDER"]
    assert len(a) == 1 and a[0]["identity"] == "ola" and {"web", "db"} <= set(a[0]["services"])


def test_reorder_inside_skew_is_not_an_alert_only_a_flag():
    rows = [_access(1000, "ola", "web"), _access(985, "ola", "db")]
    assert not [x for x in _feed(rows)[0] if x["rule"] == "R10-OUT-OF-ORDER"]


# ---- 7. R4: admin created, then its first device: critical, once, time-bound

def test_admin_created_then_first_device_is_critical_once(w):
    w.admin.call("create_user", user="mallory", role="admin")
    w.clock.tick(20)
    w.admin.call("enroll_device", **Device.generate("mallory-pc", "mallory").public_args())
    w.clock.tick(20)
    w.admin.call("enroll_device", **Device.generate("mallory-phone", "mallory").public_args())
    r4 = _all(w, "R4-PRIVILEGE-ESCALATION")
    assert [a["severity"] for a in r4] == ["high", "critical"]      # creation, then first device; the second device adds nothing
    assert r4[1]["user"] == "mallory" and r4[1]["device"] == "mallory-pc"


def test_admin_first_device_after_window_is_not_critical(w):
    from kig import detect
    w.admin.call("create_user", user="later", role="admin")
    w.clock.tick(detect.ADMIN_FIRST_DEVICE_S + 1)
    w.admin.call("enroll_device", **Device.generate("later-pc", "later").public_args())
    assert [a["severity"] for a in _all(w, "R4-PRIVILEGE-ESCALATION")] == ["high"]


def test_bootstrap_admin_and_member_devices_never_raise_r4(w):
    assert _all(w, "R4-PRIVILEGE-ESCALATION") == []


def test_r4_survives_restart_without_repeating(w, tmp_path):
    from kig.service import GuardService
    w.admin.call("create_user", user="m2", role="admin")
    w.admin.call("enroll_device", **Device.generate("m2-pc", "m2").public_args())
    n = len(_all(w, "R4-PRIVILEGE-ESCALATION"))
    svc = GuardService(w.svc.dir, clock=w.clock)         # restart: detector memory is replayed, alerts are not re-raised
    assert len([a for a in svc.alerts() if a["rule"] == "R4-PRIVILEGE-ESCALATION"]) == n
