import time, shutil, pytest
from kig.client import Device, Client
from kig.cluster import LEASE_S
from kig.service import GuardService, Denied
from test_cluster import build, code

def test_P1_device_enrolled_for_a_disabled_user_is_revoked_on_replicas(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path); time.sleep(0.02)
    admin.call("disable_user", user="bob"); cl.bus.drain()
    nd = Device.generate("bob-new", "bob")
    r = code(admin.call, "enroll_device", **nd.public_args())
    cl.bus.drain(); cl.sync_all()
    if r is not None: return                         # refusing to enrol for a disabled user is the safe outcome
    for n in ("node-a", "node-b", "node-c"):
        assert code(cl.client(nd, n).fetch, "report") is not None, f"{n} serves a device of a disabled user"

def test_P2_lease_must_not_extend_when_clock_steps_backwards(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path); time.sleep(0.02)
    cl.bus.partitioned.add("node-b")
    admin.call("report_lost", device="alice-phone", reason="stolen")
    cl.skew = -3600.0                                # wall clock stepped back an hour (NTP, VM resume)
    assert code(cl.client(phone, "node-b").fetch, "report") is not None, "lease never expires while the clock is behind last_sync"
    cl.skew = 0.0

def test_P3_replica_dir_rolled_back_without_harness_restart_still_gets_revocations(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path); time.sleep(0.02)
    d = cl.nodes["node-c"].dir; old = tmp_path / "oldc"; shutil.copytree(d, old)
    admin.call("report_lost", device="alice-phone", reason="lost"); cl.bus.drain(); cl.sync_all()   # cert_seq now past the revocation
    shutil.rmtree(d); shutil.copytree(old, d)
    cl.nodes["node-c"] = GuardService(d, clock=cl.clock, name="node-c", read_only=True, lease_s=5.0)   # restart by the node itself
    cl.pull("node-c"); time.sleep(0.01)
    assert code(cl.client(phone, "node-c").fetch, "report") == "revoked", "rolled-back replica forgot the revocation: incremental pull skips old certs"

