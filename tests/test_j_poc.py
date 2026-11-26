import json, os, random, pytest
from kig.client import Client, Device
from kig.service import Denied, GuardService
from conftest import World, Clock

def _norm(s): return json.loads(json.dumps(s, sort_keys=True))

def test_J1_deleting_state_wal_must_not_silently_roll_back_and_gc_blobs(w):
    w.admin.rotate("report", acl=["alice"])                      # bob removed from ACL, committed to wal
    d = w.svc.dir
    assert (d / "state.wal").exists() and (d / "state.wal").stat().st_size > 0
    os.unlink(d / "state.wal")
    try:
        svc2 = GuardService(d, clock=w.clock)
    except Exception:
        return                                                    # refusing is the safe outcome
    assert "bob" in svc2.state["users"] and "report" in svc2.state["files"], "users/files silently rolled back"
    assert [p for p in (d / "blobs").rglob("*") if p.is_file()], "blobs were garbage-collected"

def test_J2_truncating_wal_to_earlier_line_loses_acl_removal(w):
    w.admin.rotate("report", acl=["alice"])
    d = w.svc.dir; lines = (d / "state.wal").read_bytes().splitlines(keepends=True)
    (d / "state.wal").write_bytes(b"".join(lines[:-3]))           # drop the last 3 commits cleanly
    try:
        svc2 = GuardService(d, clock=w.clock)
    except Exception:
        return
    assert svc2.state["files"].get("report", {}).get("acl") == ["alice"], "ACL removal rolled back: bob can read again"

def test_J3_complete_but_unterminated_last_line_is_not_padded_with_NUL(w):
    d = w.svc.dir; p = d / "state.wal"
    raw = p.read_bytes(); assert raw.endswith(b"\n")
    p.write_bytes(raw[:-1])                                       # power loss after all bytes but the newline
    svc2 = GuardService(d, clock=w.clock); w.clock.tick(1)
    adm = Client(w.alice_laptop, svc2.handle, w.clock)
    adm.call("create_user", user="carol")                         # acknowledged write
    svc3 = GuardService(d, clock=w.clock)
    assert "carol" in svc3.state["users"], "acknowledged write lost after restart (NUL splice in state.wal)"

def test_J4_model_check_memory_equals_disk_after_random_commands(tmp_path):
    rnd = random.Random(7)
    w = World(tmp_path)
    users = ["alice", "bob"]; devs = {"alice": [w.alice_laptop], "bob": [w.bob_laptop]}
    n = 0
    for step in range(120):
        w.clock.tick(1)
        op = rnd.choice(["user", "dev", "put", "rot", "rev", "acl"])
        try:
            if op == "user":
                u = f"u{step}"; w.admin.call("create_user", user=u); users.append(u)
            elif op == "dev":
                u = rnd.choice(users[:2]); d = Device.generate(f"d{step}", u); w.admin.call("enroll_device", **d.public_args())
            elif op == "put":
                w.admin.put_file(f"f{step}", b"x", acl=["alice", rnd.choice(users)])
            elif op == "rot":
                f = rnd.choice([x["file_id"] for x in w.admin.call("list_files")["files"]]); w.admin.rotate(f)
            elif op == "rev":
                w.ops.call("revoke_device", device=f"d{rnd.randrange(step+1)}")
            elif op == "acl":
                f = rnd.choice([x["file_id"] for x in w.admin.call("list_files")["files"]]); w.admin.rotate(f, acl=["alice"])
        except (Denied, Exception):
            pass
        mem = _norm(w.svc.state)
        disk = _norm(GuardService(w.svc.dir, clock=w.clock).state)
        for k in ("users", "devices", "files"):
            assert mem[k] == disk[k], f"{k} differs between memory and disk after step {step} ({op})"
