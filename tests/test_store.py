"""The journaled state store: cost per write, equivalence with the in-memory state, compaction."""
import json
import random
import time

import pytest

from kig import store as st
from kig.client import Client, Device
from kig.service import GuardService
from conftest import code


def _plain(svc):
    return json.loads(json.dumps(svc.state))


def test_reloaded_state_equals_memory_after_random_operations(w, tmp_path):
    rnd = random.Random(7)
    extra = Device.generate("alice-tablet", "alice")
    for i in range(60):
        w.clock.tick(1)
        op = rnd.choice(["put", "rotate", "enroll", "user", "revoke", "read"])
        try:
            if op == "put":
                w.admin.put_file(f"f{i}", b"x" * rnd.randint(1, 500), acl=rnd.choice([["alice"], ["alice", "bob"]]))
            elif op == "rotate":
                w.svc.state["files"]["report"]["needs_rotation"] = True
                w.admin.fetch("report")
            elif op == "enroll" and "alice-tablet" not in w.svc.state["devices"]:
                w.admin.call("enroll_device", **extra.public_args())
            elif op == "user":
                w.admin.call("create_user", user=f"u{i}", role="member")
            elif op == "revoke" and "alice-tablet" in w.svc.state["devices"]:
                w.ops.call("revoke_device", device="alice-tablet")
            else:
                w.bob.fetch("report")
        except Exception:  # noqa: BLE001  denials are fine, we compare state not outcomes
            pass
        if i % 10 == 9:
            fresh = GuardService(tmp_path / "data", clock=w.clock)
            assert _plain(fresh) == _plain(w.svc), f"disk and memory diverged after op {i}"


def test_in_place_edits_of_nested_records_are_journaled(w, tmp_path):
    f = w.svc.state["files"]["report"]
    f["wraps"]["bob-laptop"]["note"] = "x"          # nested dict edit
    f["acl"].append("zed")                           # nested list edit
    w.svc._persist()
    got = GuardService(tmp_path / "data", clock=w.clock).state["files"]["report"]
    assert got["wraps"]["bob-laptop"]["note"] == "x" and got["acl"][-1] == "zed"


def test_deleting_a_record_is_journaled(w, tmp_path):
    del w.svc.state["files"]["report"]
    w.svc._persist()
    assert "report" not in GuardService(tmp_path / "data", clock=w.clock).state["files"]


def test_snapshot_is_taken_after_many_journal_entries_and_replay_stays_short(w, tmp_path, monkeypatch):
    monkeypatch.setattr(st, "MAX_WAL_ENTRIES", 20)
    for i in range(30):
        w.clock.tick(1)
        w.admin.call("create_user", user=f"n{i}", role="member")
    assert w.svc.store.wal_entries < 20
    n = len((tmp_path / "data" / "state.wal").read_text().splitlines())
    assert n < 20
    assert len(GuardService(tmp_path / "data", clock=w.clock).state["users"]) == len(w.svc.state["users"])


def test_crash_between_snapshot_and_journal_truncate_is_harmless(w, tmp_path):
    d = tmp_path / "data"
    old_wal = (d / "state.wal").read_text()
    w.svc.store.force_snapshot = True
    w.svc._persist()                                   # new snapshot; journal truncated
    (d / "state.wal").write_text(old_wal)              # simulate the crash that left the old journal behind
    fresh = GuardService(d, clock=w.clock)
    assert _plain(fresh) == _plain(w.svc)
    w.clock.tick(1)
    Client(w.alice_laptop, fresh.handle, w.clock).call("create_user", user="after", role="member")
    assert "after" in GuardService(d, clock=w.clock).state["users"]


def test_write_cost_does_not_grow_with_the_number_of_files(tmp_path):
    from conftest import Clock
    clock = Clock()
    svc = GuardService(tmp_path / "d", clock=clock)
    clock.tick(1)
    a = Device.generate("a-1", "a")
    svc.bootstrap("a", "a-1", a.sign_pub, a.kem_pub)
    ca = Client(a, svc.handle, clock)

    def timed(n):
        t = []
        for i in range(n):
            clock.tick(1)
            t0 = time.perf_counter()
            ca.put_file(f"{n}-{time.perf_counter_ns()}", b"x" * 500, acl=["a"])
            t.append(time.perf_counter() - t0)
        return sorted(t)[len(t) // 2]
    early = timed(40)
    for i in range(400):
        clock.tick(1)
        ca.put_file(f"bulk{i}", b"y" * 500, acl=["a"])
    late = timed(40)
    assert late < early * 3 + 0.02, f"put got slower with more files: {early*1000:.1f} ms -> {late*1000:.1f} ms"
