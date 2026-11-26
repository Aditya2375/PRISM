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
from kig.node import OPENER
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
        with OPENER.open(req, timeout=5) as r:
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
    for method, url in [("GET", a + "/sync/certs?after=-1&nonce=" + "a" * 32), ("POST", a + "/sync/blobs"),
                        ("POST", a + "/sync/snapshot"), ("POST", b + "/sync/push"), ("GET", a + "/node/status"),
                        ("GET", b + "/node/status")]:
        body = {"have": [], "certs": []} if method == "POST" else None
        assert http(method, url, None, body)[0] == 401, url
        assert http(method, url, "x" * 40, body)[0] == 401, url
    assert http("GET", a + "/sync/certs?after=-1&nonce=" + "a" * 32, nc.token)[0] == 200
    assert http("GET", a + "/sync/position", nc.token)[0] == 404          # the unsigned position endpoint no longer exists


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
    assert 0 < r["revocation_to_last_node_ms"]["median"] < 2000                  # a real, finite measurement
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
    upto, head, pos = verify_fresh(got, n1, -1, pub)
    assert upto == got["upto"] == head and pos[1] == got["upto"] + 1             # the signed position is part of the proof
    edited = json.loads(json.dumps(got))
    edited["proof"]["body"]["position"] = [0, 1]
    with pytest.raises(Denied):
        verify_fresh(edited, n1, -1, pub)                    # an edited position breaks the signature
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


def test_n1_catch_up_larger_than_one_reply_is_paged(tmp_path, boss):
    with NetCluster(tmp_path, boss, lease_s=2.0) as nc:
        admin = nc.client(boss)
        nc.cut("node-c")
        for i in range(3):
            admin.put_file(f"big{i}", bytes([i + 1]) * 4_500_000, acl=["ops"])
        nc.heal("node-c")
        nc.wait_synced(timeout=40)                      # node-c reached the primary's position, 13.5 MB of ciphertext later
        assert nc.client(boss, "node-c").fetch("big2", auto_rotate=False) == bytes([3]) * 4_500_000
        assert not nc.status("node-c")["errors"].get("primary")


def test_blob_pages_are_capped_and_only_serve_blobs_of_the_current_state(nc, boss):
    admin = nc.client(boss)
    for i in range(3):
        admin.put_file(f"f{i}", bytes([i + 1]) * 1_000_000, acl=["ops"])
    state = http("POST", nc.url["node-a"] + "/sync/snapshot", nc.token, {"have": [], "meta": True})[1]
    assert state["body"]["blobs"] == {}                                       # meta snapshot carries no blobs
    refs = sorted({f["ct"] for f in state["body"]["state"]["files"].values()})
    code, out = http("POST", nc.url["node-a"] + "/sync/blobs", nc.token, {"hashes": refs, "max_bytes": 1_500_000})
    assert code == 200 and 1 <= len(out["blobs"]) < len(refs)                 # capped: not all three in one reply
    code, out = http("POST", nc.url["node-a"] + "/sync/blobs", nc.token, {"hashes": ["0" * 64, refs[0]], "max_bytes": 10})
    assert code == 200 and out["gone"] == ["0" * 64] and list(out["blobs"]) == [refs[0]]   # unknown hashes are reported, not fatal
    for bad in ({"hashes": [], "max_bytes": 5}, {"hashes": [1], "max_bytes": 5}, {"hashes": ["a"], "max_bytes": True}):
        assert http("POST", nc.url["node-a"] + "/sync/blobs", nc.token, bad)[0] == 400
    out = http("POST", nc.url["node-a"] + "/sync/blobs", nc.token, {"hashes": ["../../etc/passwd"], "max_bytes": 5})[1]
    assert out["blobs"] == {} and out["gone"] == ["../../etc/passwd"]          # never used as a path


def test_n2_a_lease_is_not_refreshed_unless_the_node_reached_the_signed_position(tmp_path, boss, monkeypatch):
    """A path attacker who blocks or edits only the snapshot step must not keep a replica's lease fresh."""
    import kig.node as kn
    from kig.service import GuardService
    with NetCluster(tmp_path / "c", boss, lease_s=2.0) as nc:
        admin = nc.client(boss)
        admin.put_file("doc", b"v1", acl=["ops"])
        rep = GuardService(tmp_path / "r", name="node-x", read_only=True, lease_s=2.0)
        pub = (nc.base / "node-a" / "server_sign.pub").read_bytes()
        node = kn.Node(rep, "replica", nc.token, primary_url=nc.url["node-a"], primary_pub=pub)
        real = kn._http
        blocked = {"on": True}

        def attacker(method, url, token, body=None, timeout=2.0):
            if blocked["on"] and "/sync/snapshot" in url:
                raise OSError("snapshot step blocked on the path")
            return real(method, url, token, body, timeout)

        monkeypatch.setattr(kn, "_http", attacker)
        with pytest.raises(OSError):
            node.pull()
        assert rep.last_sync is None                                            # never fresh: it never got the state
        blocked["on"] = False
        node.pull()
        assert rep.last_sync is not None
        first = rep.last_sync
        admin.put_file("doc2", b"v2", acl=["ops"])                              # the primary moves on
        blocked["on"] = True
        time.sleep(0.05)
        with pytest.raises(OSError):
            node.pull()
        assert rep.last_sync == first                                           # not refreshed while behind the position
        blocked["on"] = False
        node.pull()
        assert rep.last_sync > first


def test_a_replica_with_a_long_history_catches_up_page_by_page(tmp_path, boss):
    with NetCluster(tmp_path, boss, lease_s=2.0, cert_page=10) as nc:          # ten audit entries per page
        admin = nc.client(boss)
        admin.call("create_user", user="member", role="member")
        for i in range(40):                                    # several pages of history
            admin.call("enroll_device", **Device.generate(f"d{i}", "member").public_args())
        victim = Device.generate("victim", "member")
        admin.call("enroll_device", **victim.public_args())
        nc.kill("node-c")
        nc.write(lambda: admin.call("revoke_device", device="victim"))
        nc.restart("node-c")
        nc.wait_synced(timeout=40)
        assert code_of(nc.client(victim, "node-c")) == "revoked"
        assert nc.status("node-c")["sync_version"] >= 44
        code, out = http("GET", f"{nc.url['node-a']}/sync/certs?after=-1&nonce={'c' * 32}&limit=100000", nc.token)
        assert code == 200 and out["proof"]["body"]["upto"] == 9 and out["proof"]["body"]["head"] >= 44   # page capped by the node


def test_a_primary_with_a_shorter_log_does_not_refresh_a_lease(nc, boss, monkeypatch):
    """A rolled-back primary (fewer entries, same restore generation) must not make a replica look fresh."""
    import kig.node as kn
    admin = nc.client(boss)
    for i in range(3):
        admin.call("enroll_device", **Device.generate(f"x{i}", "ops").public_args())
    nc.wait_synced()
    from kig.service import GuardService
    pub = (nc.base / "node-a" / "server_sign.pub").read_bytes()
    rep = GuardService(nc.base / "probe", name="probe", read_only=True, lease_s=2.0)
    node = kn.Node(rep, "replica", nc.token, primary_url=nc.url["node-a"], primary_pub=pub)
    node.pull()
    assert rep.last_sync is not None and node.cert_seq >= 3
    before = rep.last_sync
    node.cert_seq += 50                                         # as if we had applied entries the primary no longer has
    with pytest.raises(Denied) as e:
        node.pull()
    assert e.value.code == "rollback" and rep.last_sync == before


def test_the_lease_starts_when_the_request_was_sent(nc, monkeypatch):
    import kig.node as kn
    from kig.service import GuardService
    pub = (nc.base / "node-a" / "server_sign.pub").read_bytes()
    rep = GuardService(nc.base / "probe2", name="probe2", read_only=True, lease_s=2.0)
    node = kn.Node(rep, "replica", nc.token, primary_url=nc.url["node-a"], primary_pub=pub)
    real = kn._http

    def slow(method, url, token, body=None, timeout=2.0):
        out = real(method, url, token, body, timeout)
        if "/sync/certs" in url:
            time.sleep(0.5)                                     # a slow reply
        return out

    monkeypatch.setattr(kn, "_http", slow)
    t0 = rep.mono()
    node.pull()
    assert rep.last_sync - t0 < 0.3                             # counted from before the 0.5 s wait, not after it


def test_http_proxy_environment_is_ignored_for_node_traffic(nc, monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    assert http("GET", nc.url["node-a"] + "/node/status", nc.token)[0] == 200
    assert nc.status("node-a")["role"] == "primary"


def test_token_file_must_be_private_and_a_replica_cannot_bootstrap(tmp_path):
    from kig.node import _read_token, main
    f = tmp_path / "t"
    f.write_text("t" * 40)
    f.chmod(0o644)
    with pytest.raises(ValueError):
        _read_token(f)
    f.chmod(0o600)
    assert _read_token(f) == "t" * 40
    link = tmp_path / "link"
    link.symlink_to(f)
    with pytest.raises(ValueError):
        _read_token(link)
    with pytest.raises(SystemExit):
        main(["--role", "replica", "--name", "n", "--data", str(tmp_path / "d"), "--port", "1", "--cluster-token-file", str(f),
              "--primary-url", "http://127.0.0.1:1", "--primary-pub", str(f), "--bootstrap", "u:d:x"])


def _blob_count(nc, node):
    root = nc.base / node / "blobs"
    return sum(1 for p in root.rglob("*") if p.is_file()) if root.exists() else 0


def test_o1_replicas_delete_ciphertext_of_deleted_files_and_old_versions(nc, boss):
    admin = nc.client(boss)
    admin.put_file("doc", b"x" * 300_000, acl=["ops"])
    nc.wait_synced()
    assert until(lambda: _blob_count(nc, "node-b") == 1 and _blob_count(nc, "node-c") == 1)
    admin.call("delete_file", file_id="doc")
    nc.wait_synced()
    assert until(lambda: _blob_count(nc, "node-a") == 0 and _blob_count(nc, "node-b") == 0 and _blob_count(nc, "node-c") == 0)
    admin.put_file("doc2", b"y" * 100_000, acl=["ops"])
    for _ in range(2):
        admin.rotate("doc2")                                   # keeps the current and one previous version only
    nc.wait_synced()
    want = _blob_count(nc, "node-a")
    assert until(lambda: _blob_count(nc, "node-b") == want and _blob_count(nc, "node-c") == want)
    assert nc.client(boss, "node-b").fetch("doc2", auto_rotate=False) == b"y" * 100_000


def test_o2_blob_that_left_the_state_is_reported_as_gone_and_the_pull_recovers(nc, boss, monkeypatch):
    import kig.node as kn
    from kig.service import GuardService
    admin = nc.client(boss)
    admin.put_file("doc", b"one" * 1000, acl=["ops"])
    pub = (nc.base / "node-a" / "server_sign.pub").read_bytes()
    rep = GuardService(nc.base / "probe3", name="probe3", read_only=True, lease_s=2.0)
    node = kn.Node(rep, "replica", nc.token, primary_url=nc.url["node-a"], primary_pub=pub)
    real = kn._http
    moved = {"done": False}

    def churn(method, url, token, body=None, timeout=2.0):
        if "/sync/blobs" in url and not moved["done"]:
            moved["done"] = True
            admin.rotate("doc")   # the state moves under the pull
            admin.put_file("other", b"three" * 1000, acl=["ops"])
            admin.call("delete_file", file_id="doc")
        return real(method, url, token, body, timeout)

    monkeypatch.setattr(kn, "_http", churn)
    node.pull()                                                 # first snapshot is stale; the node starts over and succeeds
    assert moved["done"] and rep.last_sync is not None
    assert "doc" not in rep.state["files"] and "other" in rep.state["files"]


def test_a_recovered_peer_loses_its_old_error_in_status(nc, boss):
    nc.cut("node-c")
    nc.client(boss).call("create_user", user="late", role="member")
    assert until(lambda: nc.status("node-a")["errors"], timeout=10)            # the primary cannot push to node-c
    nc.heal("node-c")
    assert until(lambda: not nc.status("node-a")["errors"], timeout=10)


def test_p1_more_than_four_churn_restarts_still_finish_within_the_time_budget(nc, boss, monkeypatch):
    import kig.node as kn
    from kig.service import GuardService
    admin = nc.client(boss)
    admin.put_file("doc", b"d" * 5000, acl=["ops"])
    pub = (nc.base / "node-a" / "server_sign.pub").read_bytes()
    rep = GuardService(nc.base / "probe4", name="probe4", read_only=True, lease_s=2.0)
    node = kn.Node(rep, "replica", nc.token, primary_url=nc.url["node-a"], primary_pub=pub)
    real = kn._http
    seen = {"n": 0}

    def churn(method, url, token, body=None, timeout=2.0):
        out = real(method, url, token, body, timeout)
        if "/sync/blobs" in url and seen["n"] < 6:
            seen["n"] += 1
            out = {"blobs": {}, "gone": ["0" * 64]}                   # the primary says something moved, six times in a row
        return out

    monkeypatch.setattr(kn, "_http", churn)
    node.pull()
    assert seen["n"] == 6 and rep.last_sync is not None and "doc" in rep.state["files"]


def test_start_retries_on_fresh_ports_when_a_node_is_not_ready(tmp_path, boss, monkeypatch):
    calls = {"n": 0}
    real = NetCluster._wait_ready

    def flaky(self, name, timeout=30.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated: node-a did not start")
        return real(self, name, timeout)

    monkeypatch.setattr(NetCluster, "_wait_ready", flaky)
    with NetCluster(tmp_path, boss, lease_s=2.0) as nc:
        assert code_of(nc.client(boss)) == "served" and code_of(nc.client(boss, "node-c")) == "served"
        assert calls["n"] > 1
