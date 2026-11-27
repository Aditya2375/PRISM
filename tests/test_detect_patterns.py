"""Access-pattern rules: bulk reads, lateral movement, slow guessing, clock skew. Rules fire from audit entries only."""
from kig import detect as D
from kig.detect import Detector


def _e(seq, ts, typ, data, actor="dev1"):
    return {"seq": seq, "ts": ts, "type": typ, "actor": actor, "data": data}


def _feed(det, entries):
    out = []
    for e in entries:
        out += det.observe(e)
    return out


def _reads(dev, user, files, t0=1000.0, step=1.0, seq0=0):
    return [_e(seq0 + i, t0 + i * step, "access.granted", {"device": dev, "user": user, "file": f, "epoch": 1}, dev)
            for i, f in enumerate(files)]


def test_bulk_read_by_admin_is_critical_and_names_the_files():
    det = Detector(service="n1")
    det.observe(_e(0, 1.0, "service.bootstrapped", {"user": "root", "device": "root-pc"}, "operator"))
    out = _feed(det, _reads("root-pc", "root", [f"f{i}" for i in range(D.BULK_READ_FILES)], seq0=1))
    a = [x for x in out if x.rule == "R7-BULK-READ"]
    assert len(a) == 1 and a[0].severity == "critical" and a[0].user == "root" and a[0].device == "root-pc"
    assert len(a[0].files) == D.BULK_READ_FILES and a[0].services == ["n1"]


def test_bulk_read_by_a_member_is_high_and_slow_reads_do_not_fire():
    det = Detector(service="n1")
    out = _feed(det, _reads("bob-pc", "bob", [f"f{i}" for i in range(D.BULK_READ_FILES)]))
    assert [x.severity for x in out if x.rule == "R7-BULK-READ"] == ["high"]
    det2 = Detector(service="n1")
    slow = _feed(det2, _reads("bob-pc", "bob", [f"f{i}" for i in range(D.BULK_READ_FILES * 2)], step=30.0))
    assert not [x for x in slow if x.rule == "R7-BULK-READ"]


def test_lateral_movement_needs_a_baseline_and_new_files():
    det = Detector(service="n1")
    base = _feed(det, _reads("bob-pc", "bob", ["a", "b", "a", "b", "a"], t0=1000.0, step=60.0))
    assert not base
    out = _feed(det, _reads("bob-pc", "bob", ["x1", "x2", "x3", "x4"], t0=5000.0, step=2.0, seq0=10))
    a = [x for x in out if x.rule == "R6-LATERAL-MOVEMENT"]
    assert len(a) == 1 and a[0].files == ["x1", "x2", "x3", "x4"] and a[0].user == "bob"
    # a brand-new device that simply starts reading its files is not flagged
    det2 = Detector(service="n1")
    assert not [x for x in _feed(det2, _reads("new-pc", "carol", ["p", "q", "r", "s"], step=2.0)) if x.rule == "R6-LATERAL-MOVEMENT"]


def test_rereading_known_files_is_not_lateral():
    det = Detector(service="n1")
    _feed(det, _reads("bob-pc", "bob", ["a", "b", "c", "d", "e"], step=60.0))
    out = _feed(det, _reads("bob-pc", "bob", ["a", "b", "c", "d", "e"], t0=9000.0, step=2.0, seq0=10))
    assert not out


def test_slow_guessing_below_the_burst_rule_still_alerts():
    det = Detector(service="n1")
    es = [_e(i, 1000.0 + i * 200.0, "auth.bad_signature", {"device": "ghost", "source": "10.1.1.1"}) for i in range(D.SLOW_FAILURES)]
    out = _feed(det, es)
    assert [x.rule for x in out] == ["R8-SLOW-GUESSING"] and out[0].source == "10.1.1.1"
    assert not [x for x in out if x.rule == "R3-AUTH-FAILURE-BURST"]


def test_clock_skew_alert_states_the_tolerance_and_offsets():
    det = Detector(service="n1")
    es = [_e(i, 1000.0 + i, "auth.stale", {"device": "bob-pc", "cmd": "fetch", "skew": 95.0 + i, "source": "10.2.2.2"}) for i in range(3)]
    out = _feed(det, es)
    a = [x for x in out if x.rule == "R9-CLOCK-SKEW"]
    assert len(a) == 1 and "+/-30s" in a[0].explanation and a[0].severity == "low"


def test_every_alert_carries_services_and_files_lists():
    det = Detector(service="n1")
    out = _feed(det, [_e(0, 1.0, "auth.replay", {"device": "x", "source": "s"})])
    d = out[0].as_data()
    assert d["services"] == ["n1"] and d["files"] == []
