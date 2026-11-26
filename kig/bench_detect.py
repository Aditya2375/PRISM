"""Measure the detection rules. Run: python -m kig.bench_detect [--reps N] [--json]

Two things are measured, both on a fresh in-process service with a controllable clock:

* False alerts: a benign trace (routine reads, writes, rotations, enrolments, one mistyped signature) is replayed
  and every alert counts as false. Reported per 1,000 requests.
* Attack scenarios: each is run `reps` times. A scenario is detected when an alert of the expected rule appears.
  Time to alert runs from the first malicious request to the alert in the audit log: wall milliseconds on this
  machine, and seconds on the service clock (the clock the rules use). Rules that need several events (a burst)
  cannot alert before the last one, so the service-clock time is the honest figure for those.

Precision, recall and F1 are computed over all repetitions. Three scenarios are ones the rules are NOT built to
catch (a slow guessing attack under the burst threshold, a member probing files outside its list, a valid admin
reading everything). They stay in the denominator, so recall is below 1 on purpose.

The scenarios are written by the authors of the rules. The numbers say what these rules do on these traces. They are
not a claim about real traffic. Wall times depend on the machine.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import platform
import statistics
import sys
import tempfile
import time
from typing import Any, Callable

from .client import Client, Device
from .service import COOLING_OFF_S, Denied, GuardService


class _Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, s: float) -> None:
        self.t += s


class _World:
    """alice (admin) with a laptop and a limited phone, bob (member) with a laptop, one shared file."""

    def __init__(self, tmp: str) -> None:
        self.clock = _Clock()
        self.svc = GuardService(tmp, clock=self.clock)
        self.requests = 0
        self.mark_clock = 0.0
        self.mark_wall = 0.0
        self.clock.tick(1)
        self.alice_laptop = Device.generate("alice-laptop", "alice")
        self.svc.bootstrap("alice", "alice-laptop", self.alice_laptop.sign_pub, self.alice_laptop.kem_pub)
        self.admin = Client(self.alice_laptop, self._handle, self.clock)
        self.admin.call("create_user", user="bob", role="member")
        self.alice_phone = Device.generate("alice-phone", "alice")
        self.bob_laptop = Device.generate("bob-laptop", "bob")
        self.admin.call("enroll_device", **self.alice_phone.public_args(), limited=True)
        self.admin.call("enroll_device", **self.bob_laptop.public_args())
        self.bob = Client(self.bob_laptop, self._handle, self.clock)
        self.admin.put_file("report", b"payroll", acl=["alice", "bob"])
        self.clock.tick(COOLING_OFF_S + 1)        # enrolled devices are now old enough to do admin work

    def mark(self) -> None:
        """The first malicious request is about to be made: time to alert is counted from here."""
        self.mark_clock, self.mark_wall = self.clock(), time.perf_counter()

    def _handle(self, env: dict[str, Any], source: str = "local") -> dict[str, Any]:
        self.requests += 1
        return self.svc.handle(env, source=source)

    def send(self, env: dict[str, Any], source: str) -> str:
        try:
            self._handle(env, source)
            return "ok"
        except Denied as e:
            return e.code

    def alerts(self) -> list[dict[str, Any]]:
        return self.svc.alerts()


# ------------------------------------------------------------------ benign trace

def benign(w: _World, cycles: int) -> None:
    """Routine use. Seeded by position only, so every run is the same."""
    for i in range(cycles):
        w.clock.tick(7)
        assert w.bob.fetch("report", auto_rotate=False) == b"payroll"
        w.clock.tick(3)
        w.admin.fetch("report")
        w.clock.tick(3)
        w.admin.put_file(f"doc-{i}", b"x" * 64, acl=["alice", "bob"])
        w.bob.call("list_files")
        w.bob.call("whoami")
        if i % 10 == 5:                              # one mistyped signature in a while: under the burst threshold
            env = w.bob.envelope("whoami")
            env["sig"] = env["sig"][:-4] + ("AAAA" if not env["sig"].endswith("AAAA") else "BBBB")
            w.send(env, "10.0.0.5")
        if i % 15 == 7:                              # a new colleague is enrolled
            u = f"user{i}"
            w.admin.call("create_user", user=u)
            w.admin.call("enroll_device", **Device.generate(f"{u}-pc", u).public_args())


# ------------------------------------------------------------------ attacks
# each returns (expected rule, number of malicious requests made); the runner times it

def s_lost_device_use(w: _World) -> str:
    stolen = Client(w.bob_laptop, w._handle, w.clock)
    w.admin.call("report_lost", device="bob-laptop", reason="stolen")
    w.clock.tick(5)
    w.mark()
    w.send(stolen.envelope("whoami"), "203.0.113.9")
    return "R1-REVOKED-DEVICE-USE"


def s_replay(w: _World) -> str:
    env = w.bob.envelope("whoami")
    w.send(env, "10.0.0.5")
    w.mark()
    w.send(dict(env), "203.0.113.9")
    return "R2-REPLAY"


def s_bad_signature_burst(w: _World) -> str:
    w.mark()
    for _ in range(3):
        env = w.bob.envelope("whoami")
        env["sig"] = env["sig"][:-4] + ("AAAA" if not env["sig"].endswith("AAAA") else "BBBB")
        w.send(env, "203.0.113.9")
        w.clock.tick(1)
    return "R3-AUTH-FAILURE-BURST"


def s_junk_flood(w: _World) -> str:
    w.mark()
    for i in range(40):
        env = w.bob.envelope("whoami")
        env["device"] = f"ghost-{i}"
        w.send(env, "203.0.113.9")
    w.clock.tick(61)
    w.send(w.admin.envelope("whoami"), "10.0.0.1")     # the next request flushes the summary
    return "R3-AUTH-FAILURE-BURST"


def s_fresh_admin(w: _World) -> str:
    w.admin.call("create_user", user="mallory")
    w.admin.call("enroll_device", **Device.generate("mallory-pc", "mallory").public_args())
    w.clock.tick(30)
    w.mark()
    w.admin.call("set_role", user="mallory", role="admin")
    return "R4-PRIVILEGE-ESCALATION"


def s_stolen_admin_removes_phone(w: _World) -> str:
    w.mark()
    w.admin.call("report_lost", device="alice-phone", reason="removed by the holder of the laptop")
    return "R5-ADMIN-LIMITED-DEVICE-REMOVED"


def s_slow_guessing(w: _World) -> str:
    """Two bad signatures per 65 s for 11 minutes: never 3 within 60 s, so the burst rule does not fire."""
    for _ in range(10):
        for _ in range(2):
            env = w.bob.envelope("whoami")
            env["sig"] = env["sig"][:-4] + ("AAAA" if not env["sig"].endswith("AAAA") else "BBBB")
            w.send(env, "203.0.113.9")
            w.clock.tick(25)
        w.clock.tick(15)
    return "R3-AUTH-FAILURE-BURST"


def s_probe_outside_acl(w: _World) -> str:
    w.admin.put_file("secret-hr", b"hr only", acl=["alice"])
    for _ in range(5):
        w.send(w.bob.envelope("fetch", {"file_id": "secret-hr"}), "10.0.0.5")
    return "NONE-EXPECTED-TO-MISS"


def s_valid_admin_reads_all(w: _World) -> str:
    for i in range(5):
        w.admin.put_file(f"f{i}", b"x", acl=["alice"])
    for i in range(5):
        w.admin.fetch(f"f{i}")
    return "NONE-EXPECTED-TO-MISS"


SCENARIOS: list[tuple[str, Callable[[_World], str], bool]] = [
    # name, function, built to be caught
    ("lost device used after it was reported lost", s_lost_device_use, True),
    ("captured request replayed from another source", s_replay, True),
    ("three bad signatures in a minute from one source", s_bad_signature_burst, True),
    ("flood of unknown device ids (summary alert)", s_junk_flood, True),
    ("fresh account promoted to admin", s_fresh_admin, True),
    ("admin device removes the owner's limited phone", s_stolen_admin_removes_phone, True),
    ("slow guessing: 2 bad signatures per 65 s for 11 minutes", s_slow_guessing, False),
    ("member probes a file outside its list", s_probe_outside_acl, False),
    ("valid admin device reads many files", s_valid_admin_reads_all, False),
]


def _med(xs: list[float]) -> float:
    return round(statistics.median(xs), 1)


def run(reps: int = 10, benign_worlds: int = 5, benign_cycles: int = 40) -> dict[str, Any]:
    err = io.StringIO()
    with contextlib.redirect_stderr(err):                       # alerts also print one line each; keep the report clean
        fa_alerts, fa_requests, fa_by_rule = 0, 0, {}
        for _ in range(benign_worlds):
            with tempfile.TemporaryDirectory() as tmp:
                w = _World(tmp)
                n0, a0 = w.requests, len(w.alerts())
                benign(w, benign_cycles)
                al = w.alerts()[a0:]
                fa_requests += w.requests - n0
                fa_alerts += len(al)
                for a in al:
                    fa_by_rule[a["rule"]] = fa_by_rule.get(a["rule"], 0) + 1
        rows, tp, fn, fp_attack = [], 0, 0, 0
        for name, fn_, built in SCENARIOS:
            wall, sim, hit = [], [], 0
            for _ in range(reps):
                with tempfile.TemporaryDirectory() as tmp:
                    w = _World(tmp)
                    a0 = len(w.alerts())
                    w.mark()
                    expected = fn_(w)
                    el = time.perf_counter() - w.mark_wall
                    c0 = w.mark_clock
                    new = w.alerts()[a0:]
                    got = [a for a in new if a["rule"] == expected]
                    other = [a for a in new if a["rule"] != expected]
                    fp_attack += len(other)
                    if got:
                        hit += 1
                        wall.append(el * 1000)
                        sim.append(max(0.0, got[0]["ts"] - c0))
            tp += hit
            fn += reps - hit
            rows.append({
                "scenario": name, "built_to_be_caught": built, "runs": reps, "detected": hit,
                "wall_ms": {"min": round(min(wall), 1), "median": _med(wall), "max": round(max(wall), 1)} if wall else None,
                "service_clock_s": {"min": round(min(sim), 1), "median": _med(sim), "max": round(max(sim), 1)} if sim else None,
            })
    fp = fa_alerts + fp_attack
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}; wall times are not portable",
        "false_alerts": {"benign_requests": fa_requests, "alerts": fa_alerts,
                         "per_1000_requests": round(1000 * fa_alerts / fa_requests, 2) if fa_requests else 0.0,
                         "by_rule": fa_by_rule},
        "attack_runs": tp + fn, "true_positives": tp, "false_negatives": fn,
        "false_positives": fp, "false_positives_in_attack_runs": fp_attack,
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "scenarios": rows,
        "note": "scenarios and rules were written by the same people; a slow attack, a probe and a valid insider are included on purpose and are missed",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = run(reps=a.reps)
    if a.json:
        print(json.dumps(r, indent=2))
        return 0
    fa = r["false_alerts"]
    print(f"machine: {r['machine']}")
    print(f"benign replay: {fa['benign_requests']} requests, {fa['alerts']} false alerts = {fa['per_1000_requests']} per 1,000"
          + (f" {fa['by_rule']}" if fa["by_rule"] else ""))
    print(f"{'scenario':<58}{'caught':>8}{'wall ms min/med/max':>26}{'service s min/med/max':>26}")
    for s in r["scenarios"]:
        w = s["wall_ms"]
        c = s["service_clock_s"]
        print(f"{s['scenario']:<58}{str(s['detected']) + '/' + str(s['runs']):>8}"
              f"{(f'{w['min']}/{w['median']}/{w['max']}' if w else '-'):>26}"
              f"{(f'{c['min']}/{c['median']}/{c['max']}' if c else '-'):>26}")
    print(f"attack runs {r['attack_runs']}: TP {r['true_positives']} FN {r['false_negatives']} FP {r['false_positives']}"
          f" (of which {r['false_positives_in_attack_runs']} inside attack runs)")
    print(f"precision {r['precision']}  recall {r['recall']}  F1 {r['f1']}")
    print(r["note"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
