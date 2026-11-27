"""Randomised crash test: random operations, random kill points, restart, check invariants."""
import random

import pytest

from kig.client import Client, Device
from kig.service import Denied, GuardService, SimulatedCrash

POINTS = [None, None, "after_revoked_journal", "after_audit", "before_state_rename",
          "rotate_before_prepare", "rotate_after_prepare", "rotate_mid_commit", "rotate_after_commit"]


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.mark.parametrize("seed", range(12))
def test_random_kills_never_break_invariants(tmp_path, seed):
    rnd = random.Random(seed)
    clock = Clock()
    data = tmp_path / "d"
    svc = GuardService(data, clock=clock)
    clock.t += 1
    admin = Device.generate("adm", "adm")
    svc.bootstrap("adm", "adm", admin.sign_pub, admin.kem_pub)
    devs = {"adm": admin}

    def cl(dev):
        return Client(dev, svc.handle, clock)

    cl(admin).call("create_user", user="u1")
    for i in range(3):
        d = Device.generate(f"d{i}", "u1")
        cl(admin).call("enroll_device", **d.public_args())
        devs[d.device_id] = d
    cl(admin).put_file("f", b"payload-1", acl=["adm", "u1"])
    revoked: set[str] = set()
    plaintext = b"payload-1"
    for step in range(25):
        clock.t += rnd.choice([0.5, 5, 40])
        op = rnd.choice(["rotate", "revoke", "fetch", "rotate"])
        point = rnd.choice(POINTS)
        svc.crash_at = point
        live = [d for d in devs if d not in revoked and d != "adm"]
        try:
            if op == "revoke" and len(live) > 1:
                target = rnd.choice(live)
                try:
                    cl(admin).call("revoke_device", device=target)
                    revoked.add(target)
                except SimulatedCrash:
                    pass                                   # may or may not have taken effect, see below
                    if target in svc.revoked:
                        revoked.add(target)
            elif op == "rotate":
                cl(admin).rotate("f")
            else:
                cl(admin).fetch("f", auto_rotate=False)
        except (SimulatedCrash, Denied):
            pass
        if point:
            before = set(svc.revoked)
            svc = GuardService(data, clock=clock)       # restart
            clock.t += 1
            # invariants
            assert before <= svc.revoked                 # revoked set only grows
            assert svc.audit.verify() == (True, "ok")
            f = svc.state["files"]["f"]
            assert isinstance(f["epoch"], int) and f["epoch"] >= 1
            assert not (set(f["wraps"]) & svc.revoked)   # no revoked device holds a wrap
            assert svc._load_blob(f["ct"])
            opens = [e for e in svc.audit.entries if e["type"] == "file.rotate_prepared"]
            for e in opens:
                d = e["data"]
                assert any(x["type"] in ("file.rotated", "file.rotate_recovered", "file.rotate_aborted")
                           and x["data"].get("file") == "f" and x["data"].get("epoch", x["data"].get("to_epoch")) == d["to_epoch"]
                           for x in svc.audit.entries), "prepare record left open after restart"
        revoked |= svc.revoked
        svc.crash_at = None
        # data still decrypts for the admin, and revoked devices are refused
        assert cl(admin).fetch("f", auto_rotate=False) == plaintext
        for r in sorted(revoked)[:2]:
            with pytest.raises(Denied) as e:
                cl(devs[r]).fetch("f", auto_rotate=False)
            assert e.value.code == "revoked"
