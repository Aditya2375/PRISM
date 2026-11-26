"""Run the three-node cluster as three real processes on localhost and measure revocation over real sockets.

  python -m kig.netcluster            # prints the report as JSON (about 10 s)
  python -m kig.netcluster --runs 30  # more revocations in the timing sample

What is real: three OS processes (``kig.node``), each with its own data directory, signing key and audit log, talking
HTTP over TCP. Every sync message goes through a small TCP relay owned by this harness, so a link can be cut or
slowed down without touching the nodes' code. What is still a simulation: all processes share one host, one clock
and the loopback interface, so the times below are not WAN times. ``injected_delay_ms`` is added by the relay when
asked for and is reported with the result.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from . import crypto as c
from .client import Client, Device
from .cluster import LEASE_S
from .node import OPENER
from .service import Denied

NODES = ("node-a", "node-b", "node-c")


class Relay:
    """A TCP relay in front of one node. ``cut()`` refuses and drops connections; ``delay_s`` slows each new one."""

    def __init__(self, target_port: int):
        self.target_port = target_port
        self.delay_s = 0.0
        self.is_cut = False
        self._conns: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        self._closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    def cut(self) -> None:
        self.is_cut = True
        with self._lock:
            conns, self._conns = list(self._conns), set()
        for s in conns:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()

    def heal(self) -> None:
        self.is_cut = False

    def close(self) -> None:
        self._closed = True
        self.cut()
        self._srv.close()

    def _accept(self) -> None:
        while not self._closed:
            try:
                cs, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(cs,), daemon=True).start()

    def _serve(self, cs: socket.socket) -> None:
        if self.is_cut:
            cs.close()
            return
        if self.delay_s:
            time.sleep(self.delay_s)
        try:
            ts = socket.create_connection(("127.0.0.1", self.target_port), timeout=5)
        except OSError:
            cs.close()
            return
        with self._lock:
            self._conns.update((cs, ts))

        def pipe(a: socket.socket, b: socket.socket) -> None:
            try:
                while True:
                    d = a.recv(65536)
                    if not d or self.is_cut:
                        break
                    b.sendall(d)
            except OSError:
                pass
            finally:
                for s in (a, b):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    s.close()                      # a relay must not leak a descriptor per connection
                    with self._lock:
                        self._conns.discard(s)

        threading.Thread(target=pipe, args=(cs, ts), daemon=True).start()
        threading.Thread(target=pipe, args=(ts, cs), daemon=True).start()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class NetCluster:
    """Three kig.node processes. Clients talk to each node directly. Node to node traffic goes through relays."""

    def __init__(self, base_dir: str | Path, boss: Device, delay_s: float = 0.0, lease_s: float = LEASE_S,
                 pull_interval: float = 0.25, pinned_pub: dict[str, Path] | None = None, cert_page: int = 200):
        self.cert_page = cert_page
        self.pinned_pub = pinned_pub or {}         # tests: node -> a different "primary public key" file to pin
        self.spawn_extra: dict[str, list[str]] = {}
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self.boss = boss
        self.lease_s, self.pull_interval = lease_s, pull_interval
        self.token = secrets.token_urlsafe(32)
        self.token_file = self.base / "cluster.token"
        fd = os.open(self.token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # never readable by others, even briefly
        with os.fdopen(fd, "w") as f:
            f.write(self.token)
        self.ports = {n: _free_port() for n in NODES}
        self.url = {n: f"http://127.0.0.1:{p}" for n, p in self.ports.items()}
        self.procs: dict[str, subprocess.Popen] = {}
        self.relays: dict[str, Relay] = {}       # "to-node-b": primary to replica; "from-node-b": replica to primary
        self.logs: dict[str, Any] = {}
        self.delay_s = delay_s
        self.t_ack = 0.0
        self.pub_file = self.base / "primary.pub"

    # -- lifecycle -----------------------------------------------------------
    def start(self, wait: bool = True) -> "NetCluster":
        try:
            self._start(wait)
        except BaseException:
            self.stop()                          # never leave node processes behind
            raise
        return self

    def _start(self, wait: bool) -> None:
        pubjson = self.base / "boss.pub.json"
        pubjson.write_text(json.dumps({"sign_pub": c.b64e(self.boss.sign_pub), "kem_pub": c.b64e(self.boss.kem_pub)}))
        for n in ("node-b", "node-c"):
            self.relays["to-" + n] = Relay(self.ports[n])
            self.relays["from-" + n] = Relay(self.ports["node-a"])
        for r in self.relays.values():
            r.delay_s = self.delay_s
        self._spawn("node-a", ["--role", "primary",
                               "--bootstrap", f"{self.boss.user}:{self.boss.device_id}:{pubjson}",
                               "--peer", f"http://127.0.0.1:{self.relays['to-node-b'].port}",
                               "--peer", f"http://127.0.0.1:{self.relays['to-node-c'].port}"])
        self._wait_ready("node-a")
        self.pub_file.write_bytes((self.base / "node-a" / "server_sign.pub").read_bytes())
        for n in ("node-b", "node-c"):
            self._spawn(n, ["--role", "replica", "--primary-url", f"http://127.0.0.1:{self.relays['from-' + n].port}",
                            "--primary-pub", str(self.pinned_pub.get(n, self.pub_file)), "--lease", str(self.lease_s)])
        for n in ("node-b", "node-c"):
            self._wait_ready(n)
        if wait:
            self.wait_synced()

    def kill(self, name: str) -> None:
        p = self.procs[name]
        if p.poll() is None:
            p.kill()
            p.wait(5)

    def restart(self, name: str) -> None:
        """Stop a node process and start it again on the same port and data directory."""
        self.kill(name)
        self._spawn(name, self.spawn_extra[name])
        self._wait_ready(name)

    def _spawn(self, name: str, extra: list[str]) -> None:
        self.spawn_extra[name] = extra
        log = open(self.base / f"{name}.log", "ab")
        self.logs[name] = log
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent) + os.pathsep + os.environ.get("PYTHONPATH", ""))
        self.procs[name] = subprocess.Popen(
            [sys.executable, "-m", "kig.node", "--name", name, "--data", str(self.base / name), "--port",
             str(self.ports[name]), "--cluster-token-file", str(self.token_file),
             "--pull-interval", str(self.pull_interval), "--cert-page", str(self.cert_page), *extra],
            stdout=log, stderr=log, env=env)

    def _wait_ready(self, name: str, timeout: float = 30.0) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if self.procs[name].poll() is not None:
                raise RuntimeError(f"{name} exited early; see {self.base / (name + '.log')}")
            try:
                with OPENER.open(self.url[name] + "/healthz", timeout=1):
                    return
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        raise RuntimeError(f"{name} did not start in {timeout}s")

    def status(self, name: str) -> dict[str, Any]:
        req = urllib.request.Request(self.url[name] + "/node/status", headers={"X-KIG-Cluster-Token": self.token})
        with OPENER.open(req, timeout=2) as r:
            return json.load(r)

    def wait_synced(self, timeout: float = 15.0) -> None:
        """Until every replica has the primary's audit length and a fresh lease."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                head = self.status("node-a")["sync_version"]
                sts = [self.status(n) for n in ("node-b", "node-c")]
                if all(s["sync_version"] >= head and s["lease_age_s"] is not None and s["lease_age_s"] < self.lease_s
                       for s in sts):
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)
        raise RuntimeError("replicas did not catch up")

    def cut(self, node: str) -> None:
        """Cut every sync link between the primary and one replica."""
        self.relays["to-" + node].cut()
        self.relays["from-" + node].cut()

    def heal(self, node: str) -> None:
        self.relays["to-" + node].heal()
        self.relays["from-" + node].heal()

    def stop(self) -> None:
        for p in self.procs.values():
            if p.poll() is None:
                p.terminate()
        for p in self.procs.values():
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for r in self.relays.values():
            r.close()
        for f in self.logs.values():
            f.close()

    def __enter__(self) -> "NetCluster":
        return self.start()

    def __exit__(self, *a: Any) -> None:
        self.stop()

    # -- traffic -------------------------------------------------------------
    def transport(self, node: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
        url = self.url[node]

        def send(env: dict[str, Any]) -> dict[str, Any]:
            req = urllib.request.Request(url + "/v1/command", data=json.dumps(env).encode(),
                                         headers={"Content-Type": "application/json"})
            try:
                with OPENER.open(req, timeout=10) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                try:
                    body = json.load(e)
                except (ValueError, OSError):
                    body = {}
                raise Denied(str(body.get("error", "error"))[:64], str(body.get("reason", ""))[:200], e.code) from None
            except (urllib.error.URLError, OSError, ValueError, TimeoutError):
                raise Denied("unreachable", "node unreachable", 502) from None
        return send

    def client(self, device: Device, node: str = "node-a") -> Client:
        return Client(device, self.transport(node), time.time, audience=node)

    def write(self, fn: Callable[[], Any]) -> Any:
        """Run a write on the primary and note when it was acknowledged."""
        out = fn()
        self.t_ack = time.time()
        return out

    def measure_revocation(self, device: Device, timeout: float = 8.0) -> dict[str, float]:
        """Seconds from the primary's acknowledgement until each replica refuses the device with `revoked`.

        One polling thread per replica, each over its own real HTTP connection. The reading includes the poll
        round trip (a millisecond or two on loopback).
        """
        t0 = self.t_ack
        out: dict[str, float] = {"node-a": 0.0}
        lock = threading.Lock()

        def poll(name: str) -> None:
            cl = self.client(device, name)
            end = time.time() + timeout
            while time.time() < end:
                try:
                    cl.call("whoami")
                except Denied as e:
                    if e.code == "revoked":
                        with lock:
                            out[name] = round(time.time() - t0, 4)
                        return
                time.sleep(0.001)
            with lock:
                out[name] = float("inf")

        ts = [threading.Thread(target=poll, args=(n,)) for n in ("node-b", "node-c")]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return out


def report(runs: int = 20, delay_ms: float = 0.0) -> dict[str, Any]:
    """Revoke a fresh device ``runs`` times across the three processes; then cut one replica off and let the lease expire."""
    boss = Device.generate("ops-laptop", "ops")
    with tempfile.TemporaryDirectory() as tmp, NetCluster(tmp, boss, delay_s=delay_ms / 1000.0, lease_s=2.0) as nc:
        admin = nc.client(boss)
        admin.call("create_user", user="member", role="member")
        times: list[float] = []
        per_node: dict[str, list[float]] = {"node-b": [], "node-c": []}
        for i in range(runs):
            d = Device.generate(f"dev-{i}", "member")
            admin.call("enroll_device", **d.public_args())
            nc.wait_synced()
            nc.write(lambda: admin.call("revoke_device", device=d.device_id))
            t = nc.measure_revocation(d)
            times.append(max(t.values()))
            for n in per_node:
                per_node[n].append(t[n])
        # one replica loses its link to the primary
        spare = Device.generate("dev-spare", "member")
        admin.call("enroll_device", **spare.public_args())
        nc.wait_synced()
        nc.cut("node-c")
        nc.write(lambda: admin.call("revoke_device", device="dev-spare"))
        inside = "served"
        try:
            nc.client(spare, "node-c").call("whoami")
        except Denied as e:
            inside = e.code
        time.sleep(nc.lease_s + 0.5)
        after = "served"
        try:
            nc.client(boss, "node-c").call("whoami")
        except Denied as e:
            after = e.code
        nc.heal("node-c")
        healed = "not enforced"
        end = time.time() + 10
        while time.time() < end:
            try:
                nc.client(spare, "node-c").call("whoami")
            except Denied as e:
                if e.code == "revoked":
                    healed = "revoked"
                    break
            time.sleep(0.05)
    return {"simulated": False,
            "note": "three OS processes over TCP on one host (loopback), one clock; not a WAN measurement",
            "processes": 3, "runs": runs, "injected_delay_ms": delay_ms, "lease_s": 2.0,
            "revocation_to_last_node_ms": {"min": round(min(times) * 1000, 1), "median": round(statistics.median(times) * 1000, 1),
                                           "max": round(max(times) * 1000, 1)},
            "per_node_median_ms": {n: round(statistics.median(v) * 1000, 1) for n, v in per_node.items()},
            "partition": {"node": "node-c", "inside_lease": inside, "after_lease": after, "after_heal": healed}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m kig.netcluster")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--delay-ms", type=float, default=0.0, help="delay the relay adds to every new node to node connection")
    ns = ap.parse_args(argv)
    print(json.dumps(report(ns.runs, ns.delay_ms), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
