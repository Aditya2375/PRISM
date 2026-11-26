"""Adversarial tests for revocation across the three nodes: restarts, rollback, replay, lag, forged input."""
import copy
import json
import shutil
import time

import pytest

from kig import crypto as c
from kig.client import Client, Device
from kig.cluster import Bus, Cluster, LEASE_S
from kig.service import Denied, GuardService
from test_cluster import build, code

NODES = ("node-a", "node-b", "node-c")


def _revoke(cl, admin):
    admin.call("report_lost", device="alice-phone", reason="lost")
    cl.bus.drain()


def test_revoked_device_rejected_everywhere_including_captured_request(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    captured = {n: cl.client(phone, n).envelope("fetch", {"file_id": "report"}) for n in NODES}
    _revoke(cl, admin)
    for n in NODES:
        with pytest.raises(Denied) as e:
            cl.transport(n)(captured[n])           # a request signed before the revocation, sent after
        assert e.value.code in ("revoked", "replay", "stale_request", "unauthorized")


def test_replica_restart_keeps_revocation_and_fails_closed_until_synced(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    _revoke(cl, admin)
    cl.restart("node-c")                              # process restart
    assert "alice-phone" in cl.nodes["node-c"].revoked
    time.sleep(0.01)                                  # requests signed before a node's boot instant are refused by design
    assert code(cl.client(phone, "node-c").fetch, "report") == "revoked"


def test_rollback_of_a_replica_directory_is_healed_by_the_next_pull(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    d = cl.nodes["node-c"].dir
    old = tmp_path / "old-node-c"
    shutil.copytree(d, old)                           # attacker keeps a copy from before the revocation
    _revoke(cl, admin)
    shutil.rmtree(d); shutil.copytree(old, d)         # and puts it back
    cl.restart("node-c")
    time.sleep(0.01)
    assert "alice-phone" not in cl.nodes["node-c"].revoked      # the rolled-back node has forgotten
    cl.bus.partitioned.add("node-c")
    assert code(cl.client(phone, "node-c").fetch, "report") == "node_stale"   # it must not serve in this state
    cl.bus.partitioned.clear()
    assert code(cl.client(phone, "node-c").fetch, "report") == "revoked"       # and the pull fixes it


def test_replaying_an_old_valid_snapshot_cannot_unrevoke(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    old = cl.primary.export_snapshot()                # genuine, signed, taken before the revocation
    _revoke(cl, admin)
    node = cl.nodes["node-b"]
    try:
        node.install_snapshot(old, cl.primary.pub)
    except Denied:
        pass
    assert "alice-phone" in node.revoked
    assert code(cl.client(phone, "node-b").fetch, "report") == "revoked"
    assert node.state["devices"]["alice-phone"]["status"] != "active"


def test_certificate_replay_is_idempotent_and_tamper_is_rejected(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    _revoke(cl, admin)
    certs = [x for x in cl.primary.all_certs() if x["body"]["kind"] == "revoke"]
    for _ in range(3):
        for x in certs:
            assert cl.nodes["node-b"].apply_cert(x, cl.primary.pub) == "revoked"
    bad = copy.deepcopy(certs[0]); bad["body"]["device"] = "bob-laptop"
    with pytest.raises(Denied):
        cl.nodes["node-b"].apply_cert(bad, cl.primary.pub)
    assert "bob-laptop" not in cl.nodes["node-b"].revoked
    assert cl.client(bob, "node-b").fetch("report", auto_rotate=False) == b"payroll"


def test_snapshot_from_another_primary_is_rejected(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    other = Cluster(tmp_path / "evil")
    snap = other.primary.export_snapshot()
    with pytest.raises(Denied):
        cl.nodes["node-b"].install_snapshot(snap, cl.primary.pub)


def test_revoked_id_cannot_be_reenrolled_on_any_node(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    _revoke(cl, admin)
    again = Device.generate("alice-phone", "alice")
    assert code(admin.call, "enroll_device", **again.public_args()) == "conflict"
    cl.sync_all()
    for n in NODES:
        assert code(cl.client(phone, n).fetch, "report") == "revoked"


def test_disabling_a_user_revokes_all_their_devices_on_every_node(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    admin.call("disable_user", user="bob")
    cl.bus.drain()
    for n in NODES:
        assert code(cl.client(bob, n).fetch, "report") == "revoked"


def test_primary_restart_keeps_revocations_and_replicas_stay_consistent(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    _revoke(cl, admin)
    cl.primary = GuardService(cl.primary.dir, clock=cl.clock, name="node-a")
    time.sleep(0.01)
    cl.sync_all()
    for n in NODES:
        assert code(cl.client(phone, n).fetch, "report") == "revoked"


def test_lagging_replica_after_lease_fails_closed_not_open(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path)
    time.sleep(0.02)
    cl.bus.partitioned.add("node-b")
    _revoke(cl, admin)
    real = cl.clock
    cl.clock = lambda: real() + LEASE_S + 1           # time passes while node-b stays cut off
    assert code(cl.client(phone, "node-b").fetch, "report") == "node_stale"
    assert code(cl.client(bob, "node-b").fetch, "report") == "node_stale"
