import time, pytest
from kig.service import Denied
from test_cluster import build, code
from kig.cluster import LEASE_S

def test_O1_partitioned_replica_exposure_is_bounded_by_the_lease(tmp_path):
    # adapted: the exposure inside the lease is the documented design (docs/REVOCATION.md); it must end at LEASE_S
    cl, admin, alice, phone, bob = build(tmp_path); time.sleep(0.02)
    cl.bus.partitioned.add("node-b")
    cl.ops.call("report_lost", device="alice-phone", reason="stolen")
    assert code(cl.client(phone, "node-b").fetch, "report") is None          # inside the lease: still served
    cl.skew = LEASE_S + 0.5
    assert code(cl.client(phone, "node-b").fetch, "report") == "node_stale"  # outside the lease: refused

def test_O2_lease_is_enforced_by_the_node_itself(tmp_path):
    cl, admin, alice, phone, bob = build(tmp_path); time.sleep(0.02)
    cl.bus.partitioned.add("node-b")
    cl.ops.call("report_lost", device="alice-phone", reason="stolen")
    cl.skew = LEASE_S + 1
    node = cl.nodes["node-b"]
    from kig.client import Client
    c2 = Client(phone, node.handle, cl.clock, audience="node-b")             # the node's own entry point, no harness
    assert code(c2.fetch, "report") == "node_stale"
    assert code(Client(bob, node.handle, cl.clock, audience="node-b").fetch, "report") == "node_stale"

def test_O2b_fresh_replica_is_closed_until_its_first_sync(tmp_path):
    from kig.service import GuardService
    node = GuardService(tmp_path / "n", name="n", read_only=True, lease_s=LEASE_S)
    from kig.client import Client, Device
    d = Device.generate("x", "x")
    assert code(Client(d, node.handle, audience="n").call, "whoami") == "node_stale"

def test_O3_replica_read_cost_grows_with_history(tmp_path):
    import statistics
    cl, admin, alice, phone, bob = build(tmp_path); time.sleep(0.02)

    def read():
        ts = []
        for _ in range(7):
            t0 = time.perf_counter(); cl.client(bob, "node-b").fetch("report", auto_rotate=False)
            ts.append(time.perf_counter() - t0)
        return statistics.median(ts)
    base = read()
    for i in range(60):
        admin.rotate("report"); time.sleep(0.002)
    cl.bus.drain()
    after = read()
    assert after < base * 3 + 0.02, f"replica read went {base*1000:.1f} ms -> {after*1000:.1f} ms after 60 rotations"
