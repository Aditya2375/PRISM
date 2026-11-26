"""One cluster node as its own OS process, speaking HTTP.

  python -m kig.node --role primary --name node-a --data D --port 9001 --cluster-token-file T \
        --peer http://127.0.0.1:9002 --peer http://127.0.0.1:9003 [--bootstrap USER:DEVICE:PUBFILE]
  python -m kig.node --role replica --name node-b --data D --port 9002 --cluster-token-file T \
        --primary-url http://127.0.0.1:9001 --primary-pub PRIMARY_PUBLIC_KEY_FILE

It is the same replication logic as ``kig.cluster`` (signed revocation certificates, signed snapshots, lease that
fails closed), carried over real sockets instead of in-process calls.

* Clients and operators use the normal API (``POST /v1/command``, ``GET /v1/...``) on every node. Replicas
  refuse writes.
* ``/sync/*`` and ``/node/status`` need the shared cluster token in ``X-KIG-Cluster-Token``. That token only keeps
  strangers from reading metadata. It never makes anything trusted: a replica installs only certificates and snapshots
  that verify against the primary public key it was started with (``--primary-pub``, pinned from a file, never fetched
  over the network).
* The primary pushes new certificates to every peer as soon as a command is committed, and retries a peer that does
  not answer. A replica also pulls every ``--pull-interval`` seconds. Only a completed pull refreshes its lease, so
  a replica that cannot reach the primary for ``--lease`` seconds answers ``node_stale`` to everyone.
"""
from __future__ import annotations

import argparse
import contextlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from . import crypto as c
from .api import MAX_BODY, create_app, read_capped
from .cluster import LEASE_S
from .service import Denied, GuardService

HTTP_TIMEOUT = 2.0
TOKEN_HEADER = "x-kig-cluster-token"


def _read_token(path: str | Path) -> str:
    tok = Path(path).read_text().strip()
    if len(tok) < 32 or not tok.isascii() or not tok.isprintable() or " " in tok:
        raise ValueError("the cluster token must be at least 32 printable characters without spaces")
    return tok


def _http(method: str, url: str, token: str, body: Any = None, timeout: float = HTTP_TIMEOUT) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "X-KIG-Cluster-Token": token})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError("reply too large")
        return json.loads(raw)


def verify_fresh(got: dict[str, Any], nonce: str, after: int, primary_pub: bytes) -> int:
    """Check that a certificate reply is complete and was produced for THIS request by the pinned primary key.

    The proof is signed over the replica's random nonce, the highest audit sequence and a hash of the certificate list.
    An old reply replayed by someone in the middle, or one with certificates stripped out, fails here, so it cannot
    refresh the lease. Returns the audit sequence the reply covers.
    """
    try:
        proof = got["proof"]
        body = proof["body"]
        ok = c.verify(primary_pub, "fresh", c.canonical(body), c.b64d(proof["sig"]))
        certs = got["certs"]
        upto = body["upto"]
        good = (ok and body["nonce"] == nonce and not isinstance(upto, bool) and isinstance(upto, int)
                and body["after"] == max(-1, min(after, upto))        # the primary clamps after to its own length
                and body["certs_hash"] == c.sha256_hex(c.canonical(certs)))
    except Exception:  # noqa: BLE001  any malformed reply is a failed proof
        good = False
    if not good:
        raise Denied("bad_proof", "the primary's reply was not fresh, complete and signed for this request", 400)
    return upto


class Node:
    """The node-specific parts around a GuardService: sync endpoints and background threads."""

    def __init__(self, svc: GuardService, role: str, token: str, peers: list[str] | None = None,
                 primary_url: str | None = None, primary_pub: bytes | None = None, pull_interval: float = 0.25):
        if role not in ("primary", "replica"):
            raise ValueError("role must be primary or replica")
        if role == "replica" and (not primary_url or not primary_pub):
            raise ValueError("a replica needs --primary-url and --primary-pub")
        if role == "primary" and primary_url:
            raise ValueError("a primary has no primary url")
        self.svc, self.role, self.token = svc, role, token
        self.peers = [p.rstrip("/") for p in (peers or [])]
        self.primary_url = primary_url.rstrip("/") if primary_url else None
        self.primary_pub = primary_pub
        self.pull_interval = pull_interval
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.cert_seq = -1                     # replica: highest audit sequence whose certificates were applied
        self.acked: dict[str, int] = {p: -1 for p in self.peers}   # primary: per peer, last audit seq acknowledged
        self.last_error: dict[str, str] = {}
        self._pull_lock = threading.Lock()
        self.threads: list[threading.Thread] = []

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self.role == "replica":
            self.threads.append(threading.Thread(target=self._pull_loop, daemon=True, name="pull"))
        else:
            for p in self.peers:
                self.threads.append(threading.Thread(target=self._push_loop, args=(p,), daemon=True, name=f"push-{p}"))
        for t in self.threads:
            t.start()

    def close(self) -> None:
        self.stop.set()
        self.wake.set()

    def committed(self) -> None:
        """The primary calls this after a command: push now instead of waiting for the next tick."""
        self.wake.set()

    # -- primary: push -------------------------------------------------------
    def _push_loop(self, peer: str) -> None:
        while not self.stop.is_set():
            self.wake.wait(0.5)
            if self.stop.is_set():
                return
            try:
                self._push_once(peer)
            except Exception as e:  # noqa: BLE001  a down peer is retried on the next tick
                self.last_error[peer] = type(e).__name__
            time.sleep(0.002)                  # lets several pushers share one wake without a busy loop

    def _push_once(self, peer: str) -> None:
        svc = self.svc
        with svc._lock:
            upto = len(svc.audit.entries) - 1
            start = self.acked[peer] + 1
            certs = svc.certs_from_entries(svc.audit.entries[start:upto + 1]) if upto >= start else []
        if upto <= self.acked[peer]:
            return
        _http("POST", peer + "/sync/push", self.token, {"certs": certs, "upto": upto})
        self.acked[peer] = upto
        self.last_error.pop(peer, None)

    # -- replica: pull -------------------------------------------------------
    def _pull_loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.pull()
            except Exception as e:  # noqa: BLE001  the lease is what protects us while the primary is out of reach
                self.last_error["primary"] = type(e).__name__
            self.wake.wait(self.pull_interval)
            self.wake.clear()

    def pull(self) -> None:
        """Catch up with the primary. Only a pull that completes refreshes the lease."""
        assert self.primary_url and self.primary_pub
        with self._pull_lock:
            n = self.svc
            pos = _http("GET", self.primary_url + "/sync/position", self.token)["position"]
            if (int(n.snapshot_generation), int(n.snapshot_version)) < (int(pos[0]), int(pos[1])):
                snap = _http("POST", self.primary_url + "/sync/snapshot", self.token,
                             {"have": sorted(n.blob_hashes())}, timeout=10.0)
                n.install_snapshot(snap, self.primary_pub)
            nonce = secrets.token_hex(16)
            got = _http("GET", f"{self.primary_url}/sync/certs?after={self.cert_seq}&nonce={nonce}", self.token)
            upto = verify_fresh(got, nonce, self.cert_seq, self.primary_pub)
            for cert in got["certs"]:
                n.apply_cert(cert, self.primary_pub)
            self.cert_seq = upto
            n.last_sync = n.mono()
            self.last_error.pop("primary", None)

    def apply_pushed(self, certs: list[dict[str, Any]]) -> int:
        """A pushed certificate counts only if it verifies against the pinned primary key. It never refreshes the lease."""
        assert self.primary_pub
        done = 0
        for cert in certs:
            self.svc.apply_cert(cert, self.primary_pub)
            done += 1
        self.wake.set()                        # fetch the matching snapshot now
        return done


def create_node_app(data_dir: str | Path, role: str, name: str, token: str, peers: list[str] | None = None,
                    primary_url: str | None = None, primary_pub: bytes | None = None, lease_s: float = LEASE_S,
                    pull_interval: float = 0.25, cors_origins: list[str] | None = None) -> tuple[FastAPI, Node]:
    svc = GuardService(data_dir, name=name, read_only=(role == "replica"),
                       lease_s=lease_s if role == "replica" else None)
    node = Node(svc, role, token, peers, primary_url, primary_pub, pull_interval)
    app = create_app(data_dir, service=svc, cors_origins=cors_origins)
    app.state.node = node

    def authed(tok: str) -> None:
        if not hmac.compare_digest(tok.encode(), token.encode()):
            raise Denied("unauthorized", "cluster token required", 401)

    if role == "primary":
        @app.middleware("http")
        async def after_command(request: Request, call_next):
            resp = await call_next(request)
            if request.method == "POST" and request.url.path == "/v1/command":
                node.committed()
            return resp

        @app.get("/sync/position")
        def position(x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            return {"position": list(svc.sync_position())}

        @app.get("/sync/certs")
        def certs(after: int = -1, nonce: str = "", x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            if not 16 <= len(nonce) <= 64 or any(ch not in "0123456789abcdef" for ch in nonce):
                raise Denied("bad_request", "nonce must be 16 to 64 lowercase hex characters", 400)
            with svc._lock:
                upto = len(svc.audit.entries) - 1
                after = max(-1, min(after, upto))
                lst = svc.all_certs(after_seq=after)
                body = {"nonce": nonce, "after": after, "upto": upto, "certs_hash": c.sha256_hex(c.canonical(lst))}
                sig = c.b64e(c.sign(svc._sec, "fresh", c.canonical(body)))
                return {"certs": lst, "upto": upto, "proof": {"body": body, "sig": sig}}

        @app.post("/sync/snapshot")
        async def snapshot(request: Request, x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            try:
                body = json.loads(await read_capped(request, MAX_BODY))
                have = {str(h) for h in body["have"]}
            except (ValueError, KeyError, TypeError, RecursionError):
                raise Denied("bad_request", "have must be a list of blob hashes", 400) from None
            return svc.export_snapshot(have=have)
    else:
        @app.post("/sync/push")
        async def push(request: Request, x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            try:
                body = json.loads(await read_capped(request, MAX_BODY))
                certs = body["certs"]
                if not isinstance(certs, list) or any(not isinstance(x, dict) for x in certs):
                    raise ValueError
            except (ValueError, KeyError, TypeError, RecursionError):
                raise Denied("bad_request", "certs must be a list of certificates", 400) from None
            return {"applied": node.apply_pushed(certs)}

    @app.get("/node/status")
    def status(x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
        authed(x_kig_cluster_token)
        m = svc.metrics()
        return {"name": name, "role": role, "audit_entries": m["audit_entries"], "lease_age_s": m["lease_age_s"],
                "sync_version": len(svc.audit.entries) if role == "primary" else int(svc.snapshot_version),
                "errors": dict(node.last_error), "acked": dict(node.acked)}

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        node.start()
        try:
            yield
        finally:
            node.close()

    app.router.lifespan_context = lifespan

    return app, node


def _bootstrap(data_dir: str, spec: str) -> None:
    """USER:DEVICE:PUBFILE, a JSON file with sign_pub and kem_pub (base64), as `kig keygen` prints."""
    user, device, pubfile = spec.split(":", 2)
    pub = json.loads(Path(pubfile).read_text())
    svc = GuardService(data_dir, name="bootstrap")   # the data directory lock is per process, so the node reuses it
    if not svc.state["users"]:
        svc.bootstrap(user, device, c.b64d(pub["sign_pub"]), c.b64d(pub["kem_pub"]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m kig.node")
    ap.add_argument("--role", required=True, choices=["primary", "replica"])
    ap.add_argument("--name", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--cluster-token-file", required=True)
    ap.add_argument("--peer", action="append", default=[])
    ap.add_argument("--primary-url")
    ap.add_argument("--primary-pub", help="file holding the primary's raw public key (the server_key file)")
    ap.add_argument("--lease", type=float, default=LEASE_S)
    ap.add_argument("--pull-interval", type=float, default=0.25)
    ap.add_argument("--bootstrap")
    ns = ap.parse_args(argv)
    token = _read_token(ns.cluster_token_file)
    pub = Path(ns.primary_pub).read_bytes() if ns.primary_pub else None
    if ns.bootstrap:
        _bootstrap(ns.data, ns.bootstrap)
    app, _ = create_node_app(ns.data, ns.role, ns.name, token, ns.peer, ns.primary_url, pub, ns.lease, ns.pull_interval)
    import uvicorn
    uvicorn.run(app, host=ns.host, port=ns.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
