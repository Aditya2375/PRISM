"""Measure P.R.I.S.M. operation cost at several store sizes.

    python -m kig.bench [--sizes 100,500,2000] [--json]

Numbers are wall-clock medians on the machine that runs this, using the
in-process service (no network). They show how cost grows with the number of
files; they are not a throughput promise.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from . import backup, crypto as c
from .client import Client, Device
from .service import GuardService


PER_OWNER = 800                   # stays below the service's per-owner file limit


class _Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t

    def tick(self, s: float = 1) -> None:
        self.t += s


def _ms(fn, n: int) -> float:
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    return round(statistics.median(ts), 2)


def run(size: int, payload: int = 2048) -> dict:
    clock = _Clock()
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        svc = GuardService(d / "p", clock=clock)
        clock.tick()
        a = Device.generate("a-1", "a")
        svc.bootstrap("a", "a-1", a.sign_pub, a.kem_pub)
        cl = Client(a, svc.handle, clock)
        for i in range(3):
            cl.call("enroll_device", **Device.generate(f"a-{i + 2}", "a").public_args())
        t0 = time.perf_counter()
        # each owner is limited to MAX_USER_FILES (1000), so a large store is spread over several owners
        per_owner = PER_OWNER
        fillers = [cl]
        for j in range(1, -(-size // per_owner)):
            cl.call("create_user", user=f"m{j}", role="member")
            m = Device.generate(f"m{j}-1", f"m{j}")
            cl.call("enroll_device", **m.public_args())
            fillers.append(Client(m, svc.handle, clock))
        for i in range(size):
            clock.tick()
            who = fillers[i // per_owner]
            who.put_file(f"f{i}", os.urandom(payload), acl=[who.dev.user])
        fill = (time.perf_counter() - t0) / size * 1000
        out = {"files": size, "avg_put_while_filling_ms": round(fill, 2)}
        k = [0]

        def put():
            clock.tick(); k[0] += 1
            cl.put_file(f"n{k[0]}", os.urandom(payload), acl=["a"])
        out["put_ms"] = _ms(put, 20)
        out["fetch_ms"] = _ms(lambda: cl.fetch("f0"), 20)

        def rot():
            clock.tick(); cl.rotate("f0")
        out["rotate_ms"] = _ms(rot, 5)
        bp, bs = c.kem_keygen()
        bk = d / "b.bak"
        tracemalloc.start()
        t0 = time.perf_counter()
        backup.create(svc, bp, bk)
        out["backup_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        out["backup_peak_mem_mb"] = round(tracemalloc.get_traced_memory()[1] / 1e6, 1)
        tracemalloc.reset_peak()
        t0 = time.perf_counter()
        backup.restore(bk, d / "r", bp, bs, svc.dir / "server_sign.pub",
                       svc.dir / "server_sign.key", accept_rollback=True)
        out["restore_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        out["restore_peak_mem_mb"] = round(tracemalloc.get_traced_memory()[1] / 1e6, 1)
        tracemalloc.stop()
        out["backup_mb"] = round(bk.stat().st_size / 1e6, 2)
        t0 = time.perf_counter()
        GuardService(svc.dir, clock=clock)
        out["startup_replay_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m kig.bench")
    ap.add_argument("--sizes", default="100,500,2000")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    rows = [run(int(s)) for s in ns.sizes.split(",")]
    if ns.json:
        print(json.dumps(rows, indent=2))
        return 0
    keys = list(rows[0])
    print("  ".join(f"{k:>22}" for k in keys))
    for r in rows:
        print("  ".join(f"{r[k]:>22}" for k in keys))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
