"""Three real node processes over TCP (kig.node, kig.netcluster).

Each test that changes the cluster starts its own, so one test cannot leave another in a half-cut state.
Waiting is always on a condition with a deadline, never a bare sleep.
"""
import json
import time
import urllib.error
import urllib.request

import pytest

from kig import crypto as c
from kig.client import Device
from kig.netcluster import NetCluster, report
from kig.service import Denied


def until(fn, timeout=10.0, step=0.02):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


def code_of(client, cmd="whoami"):
    try:
        client.call(cmd)
        return "served"
    except Denied as e:
        return e.code


def http(method, url, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-KIG-Cluster-Token"] = token
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, {}


@pytest.fixture
def boss():
    return Device.generate("ops-laptop", "ops")


@pytest.fixture
def nc(tmp_path, boss):
    with NetCluster(tmp_path, boss, lease_s=2.0) as n:
        yield n


def setup_member(nc, boss, name="dev-1"):
    admin = nc.client(boss)
    admin.call("create_user", user="member", role="member")
    d = Device.generate(name, "member")
    admin.call("enroll_device", **d.public_args())
    nc.wait_synced()
    return admin, d


def test_revoked_device_is_refused_by_every_node_process(nc, boss):
    admin, d = setup_member(nc, boss)
    for n in ("node-a", "node-b", "node-c"):
        assert code_of(nc.client(d, n)) == "served"
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    t = nc.measure_revocation(d)
    assert set(t) == {"node-a", "node-b", "node-c"}
    assert max(t.values()) < 2.0, t           # far below the lease on loopback
    for n in ("node-a", "node-b", "node-c"):
        assert code_of(nc.client(d, n)) == "revoked"
    assert code_of(nc.client(boss, "node-b")) == "served"       # other users keep access


def test_three_separate_processes_with_separate_data(nc):
    assert len({p.pid for p in nc.procs.values()}) == 3
    keys = {(nc.base / n / "server_sign.pub").read_bytes() for n in ("node-a", "node-b", "node-c")}
    assert len(keys) == 3                       # each node has its own signing key
    for n in ("node-a", "node-b", "node-c"):
        assert (nc.base / n / ".datalock").exists()      # a data directory of its own, locked by its own process


def test_replica_refuses_writes(nc, boss):
    with pytest.raises(Denied) as e:
        nc.client(boss, "node-b").call("create_user", user="x", role="member")
    assert e.value.status == 421 or e.value.code == "read_only"


def test_sync_endpoints_need_the_cluster_token(nc):
    a, b = nc.url["node-a"], nc.url["node-b"]
    for method, url in [("GET", a + "/sync/position"), ("GET", a + "/sync/certs?after=-1"),
                        ("POST", a + "/sync/snapshot"), ("POST", b + "/sync/push"), ("GET", a + "/node/status"),
                        ("GET", b + "/node/status")]:
        body = {"have": [], "certs": []} if method == "POST" else None
        assert http(method, url, None, body)[0] == 401, url
        assert http(method, url, "x" * 40, body)[0] == 401, url
    assert http("GET", a + "/sync/position", nc.token)[0] == 200


def test_replica_ignores_a_certificate_signed_by_another_key(nc, boss):
    admin, d = setup_member(nc, boss)
    _pub, sec = c.sig_keygen()
    body = {"kind": "revoke", "device": d.device_id, "seq": 99, "ts": time.time()}
    forged = {"body": body, "sig": c.b64e(c.sign(sec, "cert", c.canonical(body)))}
    code, out = http("POST", nc.url["node-b"] + "/sync/push", nc.token, {"certs": [forged]})
    assert code == 400 and out["error"] == "bad_signature"
    assert code_of(nc.client(d, "node-b")) == "served"          # nothing was revoked by the forgery


def test_malformed_push_and_snapshot_requests_are_refused(nc):
    for bad in ({"certs": "x"}, {"certs": [1]}, {}, []):
        assert http("POST", nc.url["node-b"] + "/sync/push", nc.token, bad)[0] == 400
    for bad in ({"have": 5}, {}, []):
        assert http("POST", nc.url["node-a"] + "/sync/snapshot", nc.token, bad)[0] == 400


def test_partitioned_replica_serves_inside_the_lease_then_fails_closed_and_never_unrevokes(nc, boss):
    admin, d = setup_member(nc, boss)
    nc.cut("node-c")
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    assert until(lambda: code_of(nc.client(d, "node-b")) == "revoked")        # the connected replica enforces
    assert code_of(nc.client(d, "node-c")) == "served"                         # inside the lease: the documented gap
    assert until(lambda: code_of(nc.client(boss, "node-c")) == "node_stale", timeout=nc.lease_s + 4)
    assert code_of(nc.client(d, "node-c")) == "node_stale"                     # closed for everyone, not open
    nc.heal("node-c")
    assert until(lambda: code_of(nc.client(d, "node-c")) == "revoked", timeout=10)
    assert until(lambda: code_of(nc.client(boss, "node-c")) == "served", timeout=10)


def test_replica_restart_keeps_revocations_and_fails_closed_until_it_has_pulled(nc, boss):
    admin, d = setup_member(nc, boss)
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    assert until(lambda: code_of(nc.client(d, "node-c")) == "revoked")
    nc.cut("node-c")
    nc.restart("node-c")
    assert code_of(nc.client(boss, "node-c")) == "node_stale"                  # nothing confirmed since the restart
    assert code_of(nc.client(d, "node-c")) in ("node_stale", "revoked")        # never served
    nc.heal("node-c")
    assert until(lambda: code_of(nc.client(boss, "node-c")) == "served", timeout=10)
    assert code_of(nc.client(d, "node-c")) == "revoked"


def test_replica_that_was_down_during_the_revocation_catches_up(nc, boss):
    admin, d = setup_member(nc, boss)
    nc.kill("node-b")
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    nc.restart("node-b")
    assert until(lambda: code_of(nc.client(d, "node-b")) == "revoked", timeout=15)


def test_primary_stops_replicas_fail_closed_and_revocations_stay(nc, boss):
    admin, d = setup_member(nc, boss)
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    assert until(lambda: code_of(nc.client(d, "node-b")) == "revoked")
    nc.kill("node-a")
    assert until(lambda: code_of(nc.client(boss, "node-b")) == "node_stale", timeout=nc.lease_s + 4)
    assert code_of(nc.client(d, "node-b")) == "node_stale"
    nc.restart("node-a")
    assert until(lambda: code_of(nc.client(boss, "node-b")) == "served", timeout=15)
    assert code_of(nc.client(d, "node-b")) == "revoked"


def test_replica_pinned_to_a_different_primary_key_never_serves(tmp_path, boss):
    other = tmp_path / "other.pub"
    other.write_bytes(c.sig_keygen()[0])
    nc = NetCluster(tmp_path / "c", boss, lease_s=2.0, pinned_pub={"node-c": other})
    try:
        nc.start(wait=False)
        assert until(lambda: code_of(nc.client(boss, "node-b")) == "served", timeout=15)
        time.sleep(1.0)
        assert code_of(nc.client(boss, "node-c")) == "node_stale"           # it never trusted this primary
        assert nc.status("node-c")["errors"].get("primary")                 # and says why it cannot sync
        with pytest.raises(RuntimeError):
            nc.wait_synced(timeout=1.5)
    finally:
        nc.stop()


def test_a_member_reads_a_file_on_a_replica_until_revoked(nc, boss):
    admin, d = setup_member(nc, boss)
    admin.put_file("doc", b"for the team", acl=["ops", "member"])
    nc.wait_synced()
    assert nc.client(d, "node-b").fetch("doc", auto_rotate=False) == b"for the team"
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    assert until(lambda: code_of(nc.client(d, "node-b"), "list_files") == "revoked")
    assert until(lambda: code_of(nc.client(d, "node-c"), "list_files") == "revoked")
    with pytest.raises(Denied):
        nc.client(d, "node-b").fetch("doc", auto_rotate=False)


def test_relay_delay_shows_up_in_the_measurement(tmp_path, boss):
    with NetCluster(tmp_path, boss, delay_s=0.3, lease_s=4.0) as nc:
        admin, d = setup_member(nc, boss)
        nc.write(lambda: admin.call("revoke_device", device=d.device_id))
        t = nc.measure_revocation(d)
        assert 0.25 < max(t.values()) < 3.0, t


def test_report_shape_and_honesty_fields():
    r = report(runs=3)
    assert r["simulated"] is False and r["processes"] == 3 and "loopback" in r["note"]
    assert set(r["revocation_to_last_node_ms"]) == {"min", "median", "max"}
    assert r["partition"] == {"node": "node-c", "inside_lease": "served", "after_lease": "node_stale",
                              "after_heal": "revoked"}


def _fresh_reply(nc, after, nonce):
    code, out = http("GET", f"{nc.url['node-a']}/sync/certs?after={after}&nonce={nonce}", nc.token)
    assert code == 200
    return out


def test_certificate_reply_must_be_fresh_complete_and_signed_for_this_request(nc, boss):
    from kig.node import verify_fresh
    admin, d = setup_member(nc, boss)
    nc.write(lambda: admin.call("revoke_device", device=d.device_id))
    pub = (nc.base / "node-a" / "server_sign.pub").read_bytes()
    n1, n2 = "a" * 32, "b" * 32
    got = _fresh_reply(nc, -1, n1)
    assert verify_fresh(got, n1, -1, pub) == got["upto"]
    with pytest.raises(Denied):
        verify_fresh(got, n2, -1, pub)                       # an old reply replayed for a new request
    with pytest.raises(Denied):
        verify_fresh(got, n1, 0, pub)                        # answers a different question
    stripped = dict(got, certs=[])
    with pytest.raises(Denied):
        verify_fresh(stripped, n1, -1, pub)                  # a revocation removed on the way
    other = c.sig_keygen()[0]
    with pytest.raises(Denied):
        verify_fresh(got, n1, -1, other)                     # not signed by the pinned primary
    for bad in ({}, {"certs": [], "proof": 5}, dict(got, proof={"body": {}, "sig": "x"})):
        with pytest.raises(Denied):
            verify_fresh(bad, n1, -1, pub)
    assert got["certs"], "the revocation certificate is in the reply"


def test_certificate_request_needs_a_well_formed_nonce(nc):
    for nonce in ("", "short", "G" * 32, "a" * 65):
        code, _ = http("GET", f"{nc.url['node-a']}/sync/certs?after=-1&nonce={nonce}", nc.token)
        assert code == 400, nonce
