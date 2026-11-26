"""Three-node cluster (one primary, two read replicas) with signed revocation.

Single-host simulation: nodes are in-process with their own data directories,
keys and audit logs. Messages pass through a bus with configurable delay and
partitions, so propagation time is measured, not assumed.

* Writes go to the primary only.
* The primary pushes signed revocation and epoch certificates to every replica
  the moment they are committed. Replicas verify the signature and enforce.
* Replicas also pull all certificates and a signed snapshot to catch up after a
  partition. A replica never un-revokes a device when it installs a snapshot.
* Requests carry an audience, so a request captured at one node cannot be
  replayed at another.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable

from .client import Client, Device
from .service import Denied, GuardService


class Bus:
    def __init__(self, delay_s: Callable[[str], float] = lambda node: 0.0):
        self.delay_s = delay_s
        self.partitioned: set[str] = set()
        self.threads: list[threading.Thread] = []

    def send(self, node: str, fn: Callable[[], None]) -> None:
        if node in self.partitioned:
            return  # dropped; the node must pull later

        def run() -> None:
            d = self.delay_s(node)
            if d:
                time.sleep(d)
            if node not in self.partitioned:
                fn()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.threads.append(t)

    def drain(self, timeout: float = 5.0) -> None:
        end = time.time() + timeout
        for t in self.threads:
            t.join(max(0.0, end - time.time()))
        self.threads = [t for t in self.threads if t.is_alive()]


LEASE_S = 5.0  # a replica that cannot reach the primary for longer than this refuses all requests


class Cluster:
    def __init__(self, base_dir: str | Path, replicas: tuple[str, ...] = ("node-b", "node-c"),
                 clock: Callable[[], float] = time.time, bus: Bus | None = None):
        base = Path(base_dir)
        self._base_clock = clock
        self.skew = 0.0                       # tests move every node's clock together by changing this
        self.clock = lambda: self._base_clock() + self.skew
        self.bus = bus or Bus()
        self.primary = GuardService(base / "node-a", clock=self.clock, name="node-a")
        self.nodes: dict[str, GuardService] = {
            r: GuardService(base / r, clock=self.clock, name=r, read_only=True, lease_s=LEASE_S) for r in replicas
        }
        self.enforced_at: dict[tuple[str, str], float] = {}
        self.cert_seq: dict[str, int] = {}    # per replica: highest certificate sequence already applied
        self.sync_all()

    @property
    def all_nodes(self) -> dict[str, GuardService]:
        return {"node-a": self.primary, **self.nodes}

    def transport(self, node: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
        if node == "node-a":
            return self.primary.handle

        def handle(env: dict[str, Any], source: str = "local") -> dict[str, Any]:
            # Pull on every request while the primary is reachable. The lease itself is enforced by the node:
            # if it cannot confirm it is current, it refuses everyone.
            if node not in self.bus.partitioned:
                self.pull(node)
            return self.nodes[node].handle(env, source)

        return handle

    def restart(self, node: str) -> GuardService:
        """Simulate a replica process restart: state is reloaded from disk and the last-sync time is forgotten,
        so the node fails closed (when partitioned) until it has pulled from the primary again."""
        old = self.nodes[node]
        self.nodes[node] = GuardService(old.dir, clock=self.clock, name=node, read_only=True, lease_s=LEASE_S)
        self.cert_seq.pop(node, None)
        return self.nodes[node]

    def tick(self) -> None:
        """The 1 s background pull for every reachable replica."""
        for name in self.nodes:
            if name not in self.bus.partitioned:
                self.pull(name)

    def client(self, device: Device, node: str = "node-a") -> Client:
        return Client(device, self.transport(node), self.clock, audience=node)

    def benchmark_revocation(self, runs: int = 50, push_delay=(0.005, 0.05), seed: int = 1) -> dict[str, float]:
        """Revoke a fresh device ``runs`` times; time until the LAST node rejects it (seconds)."""
        import random
        import statistics
        rnd = random.Random(seed)
        self.bus.delay_s = lambda n: rnd.uniform(*push_delay)
        owner = Device.generate("bench-owner", "bench")
        self.primary.bootstrap("bench", "bench-owner", owner.sign_pub, owner.kem_pub)
        admin = self.writer(owner)
        times = []
        for i in range(runs):
            d = Device.generate(f"bench-dev-{i}", "bench")
            admin.call("enroll_device", **d.public_args())
            self.bus.drain()
            self.sync_all()
            admin.call("revoke_device", device=d.device_id)
            t = self.measure_revocation(d)
            times.append(max(t.values()))
        return {"runs": runs, "min_s": min(times), "median_s": statistics.median(times), "max_s": max(times)}

    def writer(self, device: Device) -> Client:
        """A client whose writes go through the primary and are replicated."""
        return Client(device, self.submit, self.clock, audience="node-a")

    # -- replication ---------------------------------------------------------
    def sync_all(self) -> None:
        for name in self.nodes:
            self.pull(name)

    def pull(self, node: str) -> None:
        """Catch-up path for a node that missed pushes (partition healed, restart).

        Cheap when nothing changed: the snapshot is built only if the primary is ahead of the node, and only
        certificates after the node's last applied sequence are sent.
        """
        n = self.nodes[node]
        if (int(n.snapshot_generation), int(n.snapshot_version)) < self.primary.sync_position():
            n.install_snapshot(self.primary.export_snapshot(have=n.blob_hashes()), self.primary.pub)
        upto = len(self.primary.audit.entries) - 1
        for cert in self.primary.all_certs(after_seq=self.cert_seq.get(node, -1)):
            self._apply(node, cert)
        self.cert_seq[node] = upto
        n.last_sync = self.clock()

    def _apply(self, node: str, cert: dict[str, Any]) -> str:
        r = self.nodes[node].apply_cert(cert, self.primary.pub)
        if r == "revoked":
            self.enforced_at.setdefault((node, cert["body"]["device"]), self.clock())
        return r

    def submit(self, env: dict[str, Any], source: str = "local") -> dict[str, Any]:
        """Send a write envelope to the primary, then push any certificates it produced."""
        n0 = len(self.primary.audit.entries)
        result = self.primary.handle(env, source)
        certs = self.primary.certs_from_entries(self.primary.audit.entries[n0:])
        for name, node in self.nodes.items():
            for cert in certs:
                self.bus.send(name, lambda node=name, cert=cert: self._apply(node, cert))
            self.bus.send(name, lambda node=node: node.install_snapshot(
                self.primary.export_snapshot(have=node.blob_hashes()), self.primary.pub))
        self.primary_ack_at = self.clock()
        return result

    def measure_revocation(self, device: Device, timeout: float = 5.0) -> dict[str, float]:
        """Seconds from primary acknowledgement until each node rejects the revoked device."""
        t0 = getattr(self, "primary_ack_at", self.clock())
        out: dict[str, float] = {"node-a": 0.0}
        deadline = time.time() + timeout
        pending = set(self.nodes)
        while pending and time.time() < deadline:
            for name in sorted(pending):
                cl = self.client(device, name)
                try:
                    cl.call("whoami")
                except Denied as e:
                    if e.code == "revoked":
                        out[name] = round(self.clock() - t0, 4)
                        pending.discard(name)
            time.sleep(0.001)
        for name in pending:
            out[name] = float("inf")
        return out
