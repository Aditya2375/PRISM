"""Seeded fuzzing: whatever bytes arrive, the service answers with a clean error and its state stays valid."""
import copy
import json
import random

import pytest

from kig.service import Denied


def _mutate(rnd, v, depth=0):
    if isinstance(v, dict) and v and rnd.random() < 0.7:
        k = rnd.choice(list(v))
        out = dict(v)
        r = rnd.random()
        if r < 0.15:
            del out[k]
        elif r < 0.3:
            out[rnd.choice(["x", "cmd", "args", "sig"])] = rnd.choice([None, 1, -1, 1e999, "", [], {}, "A" * 5000, True])
        else:
            out[k] = _mutate(rnd, v[k], depth + 1)
        return out
    if isinstance(v, list) and v:
        out = list(v); i = rnd.randrange(len(out)); out[i] = _mutate(rnd, out[i], depth + 1); return out
    if isinstance(v, str):
        r = rnd.random()
        if r < 0.3 and v:
            i = rnd.randrange(len(v)); return v[:i] + rnd.choice("AZ0_-=\x00é") + v[i + 1:]
        return rnd.choice([v, "", v * 3, v[: len(v) // 2], "../../etc/passwd"])
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return rnd.choice([0, -1, 2**63, 1e308, v + 1, None, "1"])
    return rnd.choice([None, 0, "x", [], {}])


@pytest.mark.parametrize("seed", range(6))
def test_mutated_envelopes_never_crash_or_corrupt(w, seed):
    rnd = random.Random(seed)
    cmds = [("whoami", {}), ("list_files", {}), ("fetch", {"file_id": "report"}),
            ("create_user", {"user": "zed", "role": "member"}), ("eligible", {"users": ["alice"]})]
    before = json.dumps(w.svc.state["files"], sort_keys=True), sorted(w.svc.state["users"])
    for i in range(120):
        cmd, args = rnd.choice(cmds)
        env = w.admin.envelope(cmd, args)
        bad = _mutate(rnd, copy.deepcopy(env))
        try:
            w.svc.handle(bad)
        except Denied as e:
            assert 400 <= e.status < 600, e
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"unclean failure {type(e).__name__}: {e} for {json.dumps(bad, default=str)[:200]}")
    assert json.dumps(w.svc.state["files"], sort_keys=True) == before[0]       # none of it changed any file
    assert w.admin.fetch("report", auto_rotate=False)                          # and the service still serves
    assert w.svc.audit.verify()[0]


@pytest.mark.parametrize("seed", range(4))
def test_mutated_manifests_and_responses_are_refused_by_client(w, seed):
    from kig import crypto as c
    rnd = random.Random(seed)
    good = w.admin.call("fetch", file_id="report")
    for i in range(60):
        r = _mutate(rnd, copy.deepcopy(good))
        if r == good:
            continue
        w.admin.pins = {"signers": {}, "owners": {}, "writers": {}, "writer_users": {}, "admins": {}}
        try:
            out = w.admin._open("report", r)
        except (c.CryptoError, KeyError, TypeError, ValueError, AttributeError, UnicodeError):
            continue
        # if it decrypted, only fields that do not matter to the plaintext or the manifest may have changed
        assert out == b"top secret payroll"
        assert r["acl"] == good["acl"] and r["owner"] == good["owner"] and r["epoch"] == good["epoch"]


@pytest.mark.parametrize("seed", range(6))
def test_validly_signed_garbage_arguments_never_crash_or_corrupt(w, seed):
    """The signature check is the first wall; this goes through it, so the command code sees the junk."""
    rnd = random.Random(100 + seed)
    cmds = [("create_user", {"user": "zed", "role": "member"}), ("enroll_device", w.bob_laptop.public_args()),
            ("put_file", {"file_id": "n1", "acl": ["alice"], "ciphertext": "AAAA", "wraps": {}, "commit": "0" * 64}),
            ("rotate", {"file_id": "report", "expected_epoch": 1, "ciphertext": "AAAA", "wraps": {}, "commit": "0" * 64}),
            ("revoke_device", {"device": "nobody"}), ("set_role", {"user": "bob", "role": "admin"}),
            ("fetch", {"file_id": "report", "epoch": 1}), ("eligible", {"users": ["alice", "bob"]})]
    files_before = json.dumps(w.svc.state["files"], sort_keys=True)
    devices_before = json.dumps(w.svc.state["devices"], sort_keys=True)
    for i in range(150):
        cmd, args = rnd.choice(cmds)
        junk = _mutate(rnd, copy.deepcopy(args))
        if not isinstance(junk, dict):
            junk = {}
        if cmd in ("create_user", "set_role") and junk.get("user") in ("bob", "alice", "zed") and junk.get("role") == "admin":
            continue                                           # a legitimate privilege change is not what this checks
        w.clock.tick(1)
        try:
            w.svc.handle(w.admin.envelope(cmd, junk))
        except Denied as e:
            assert 400 <= e.status < 600
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"unclean failure {type(e).__name__}: {e} for {cmd} {json.dumps(junk, default=str)[:200]}")
    assert w.svc.audit.verify()[0]
    assert set(w.svc.state["devices"]) >= {"alice-laptop", "bob-laptop"}
    from kig import doctor
    assert all(r[0] != "FAIL" for r in doctor.check(w.svc.dir))
