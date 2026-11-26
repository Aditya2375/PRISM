import copy
import random
import time

import pytest

from kig.client import Client, Device
from kig.cluster import Bus, Cluster
from kig.service import GRACE_S, Denied


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except Denied as e:
        return e.code
    return None


def build(tmp_path, delay=lambda n: 0.0):
    cl = Cluster(tmp_path, bus=Bus(delay))
    time.sleep(0.01)
    alice = Device.generate("alice-laptop", "alice")
    cl.primary.bootstrap("alice", "alice-laptop", alice.sign_pub, alice.kem_pub)
    admin = cl.writer(alice)
    admin.call("create_user", user="bob")
    phone, bob = Device.generate("alice-phone", "alice"), Device.generate("bob-laptop", "bob")
    for d in (phone, bob):
        admin.call("enroll_device", **d.public_args())
    admin.put_file("report", b"payroll", acl=["alice", "bob"])
    cl.bus.drain()
    cl.sync_all()
    return cl, admin, alice, phone, bob


def test_replicas_serve_reads_and_refuse_writes(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    for node in ("node-a", "node-b", "node-c"):
        assert cl.client(bob, node).fetch("report", auto_rotate=False) == b"payroll"
    assert code(cl.client(alice, "node-b").call, "revoke_device", device="bob-laptop") == "read_only"


def test_revocation_enforced_on_every_node_and_timed(tmp_path):
    rnd = random.Random(1)
    cl, admin, alice, phone, bob = build(tmp_path, delay=lambda n: rnd.uniform(0.01, 0.06))
    time.sleep(0.02)
    admin.call("report_lost", device="alice-phone", reason="lost")
    t = cl.measure_revocation(phone)
    assert set(t) == {"node-a", "node-b", "node-c"}
    assert max(t.values()) < 1.0, t                       # last node enforced well inside a second
    for node in ("node-a", "node-b", "node-c"):
        assert code(cl.client(phone, node).fetch, "report") == "revoked"
    # other users and the owner's other device keep access on every node
    for node in ("node-a", "node-b", "node-c"):
        assert cl.client(bob, node).fetch("report", auto_rotate=False) == b"payroll"
        assert cl.client(alice, node).fetch("report", auto_rotate=False) == b"payroll"


def test_owner_can_reenrol_after_loss_and_others_keep_access(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    admin.call("report_lost", device="alice-phone")
    cl.bus.drain()
    new_phone = Device.generate("alice-phone-2", "alice")
    admin.call("enroll_device", **new_phone.public_args())
    admin.rotate("report")                                  # re-key so the new device gets a wrap
    cl.bus.drain()
    time.sleep(0.02)
    for node in ("node-a", "node-b", "node-c"):
        assert cl.client(new_phone, node).fetch("report", auto_rotate=False) == b"payroll"
        assert cl.client(bob, node).fetch("report", auto_rotate=False) == b"payroll"
        assert code(cl.client(phone, node).fetch, "report") == "revoked"


def test_partitioned_node_enforces_after_pull_and_never_unrevokes(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    cl.bus.partitioned.add("node-c")
    admin.call("report_lost", device="alice-phone")
    cl.bus.drain()
    assert code(cl.client(phone, "node-b").fetch, "report") == "revoked"
    # the partitioned node has not heard yet: this is the documented exposure window
    assert code(cl.client(phone, "node-c").fetch, "report", False) is None
    cl.bus.partitioned.clear()
    cl.pull("node-c")
    assert code(cl.client(phone, "node-c").fetch, "report") == "revoked"
    # installing an OLD snapshot later must not resurrect the device
    old = cl.primary.export_snapshot()
    old["body"]["state"]["devices"]["alice-phone"]["status"] = "active"
    with pytest.raises(Denied):
        cl.nodes["node-c"].install_snapshot(old, cl.primary.pub)   # signature no longer matches
    assert code(cl.client(phone, "node-c").fetch, "report") == "revoked"


def test_forged_certificate_rejected(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    other = Cluster(tmp_path / "evil")
    evil_cert = other.primary._cert({"kind": "revoke", "device": "bob-laptop", "seq": 1, "ts": 1})
    with pytest.raises(Denied):
        cl.nodes["node-b"].apply_cert(evil_cert, cl.primary.pub)
    assert cl.client(bob, "node-b").fetch("report", auto_rotate=False) == b"payroll"


def test_rotation_cutoff_enforced_by_every_node(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    cl.bus.partitioned.add("node-c")                      # node-c will not get the new key version
    admin.rotate("report")
    cl.bus.drain()
    # inside the grace window every node can still serve what it has
    assert cl.client(bob, "node-c").fetch("report", auto_rotate=False) == b"payroll"
    # inside grace, node-b serves the previous epoch to an in-flight transfer
    assert cl.client(bob, "node-b").fetch("report", auto_rotate=False, epoch=1) == b"payroll"
    # a node that learned about the new epoch through a signed certificate (pull) refuses to
    # serve the stale one after the cutoff
    cl.bus.partitioned.clear()
    for cert in cl.primary.all_certs():
        cl.nodes["node-c"].apply_cert(cert, cl.primary.pub)
    cl.nodes["node-c"].clock = lambda t0=time.time(): t0 + GRACE_S + 5
    cl.nodes["node-c"].last_sync = cl.nodes["node-c"].clock()      # this test is about the epoch floor, not the lease
    cl.nodes["node-c"].epoch_floor["report"] = (2, time.time() - GRACE_S - 10)
    assert code(Client(bob, cl.nodes["node-c"].handle, lambda: time.time() + GRACE_S + 5, "node-c").fetch,
                "report", False) == "stale_replica"


def test_request_cannot_be_replayed_on_another_node(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    env = cl.client(bob, "node-b").envelope("fetch", {"file_id": "report"})
    cl.nodes["node-b"].handle(copy.deepcopy(env))
    assert code(cl.nodes["node-c"].handle, copy.deepcopy(env)) == "wrong_audience"
    assert code(cl.primary.handle, copy.deepcopy(env)) == "wrong_audience"
    forged = copy.deepcopy(env)
    forged["aud"] = "node-c"
    assert code(cl.nodes["node-c"].handle, forged) == "unauthorized"   # changing aud breaks the signature


def test_partitioned_replica_fails_closed_after_lease(tmp_path):
    from kig.cluster import LEASE_S
    now = [1_800_000_000.0]
    cl = Cluster(tmp_path, clock=lambda: now[0])
    alice = Device.generate("a-laptop", "alice")
    cl.primary.bootstrap("alice", "a-laptop", alice.sign_pub, alice.kem_pub)
    cl.writer(alice).put_file("f", b"x", acl=["alice"])
    cl.sync_all()
    now[0] += 1
    cl.bus.partitioned.add("node-b")
    assert cl.client(alice, "node-b").fetch("f", auto_rotate=False) == b"x"        # inside lease
    now[0] += LEASE_S + 1
    assert code(cl.client(alice, "node-b").fetch, "f", False) == "node_stale"      # outside lease


def test_benchmark_reports_min_median_max(tmp_path):
    r = Cluster(tmp_path).benchmark_revocation(runs=5)
    assert r["runs"] == 5 and 0 <= r["min_s"] <= r["median_s"] <= r["max_s"] < 1.0
