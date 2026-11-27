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
import stat
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
PAGE_BYTES = 2 * 1024 * 1024      # ciphertext per blob page; a single larger blob goes alone (a file is at most MAX_FILE_BYTES)
TOKEN_HEADER = "x-kig-cluster-token"


# Node to node traffic never goes through an HTTP proxy named in the environment: the cluster token travels in it.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CERT_PAGE = 200            # audit entries per certificate page


def _read_token(path: str | Path) -> str:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise ValueError(f"the cluster token file {path} must be a regular file readable only by its owner (chmod 600)")
    tok = Path(path).read_text().strip()
    if len(tok) < 32 or not tok.isascii() or not tok.isprintable() or " " in tok:
        raise ValueError("the cluster token must be at least 32 printable characters without spaces")
    return tok


def _http(method: str, url: str, token: str, body: Any = None, timeout: float = HTTP_TIMEOUT) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "X-KIG-Cluster-Token": token})
    with OPENER.open(req, timeout=timeout) as r:
        raw = r.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError("reply too large")
        return json.loads(raw)


def verify_fresh(got: dict[str, Any], nonce: str, after: int, primary_pub: bytes) -> tuple[int, int, tuple[int, int]]:
    """Check that a certificate reply is complete and was produced for THIS request by the pinned primary key.

    The proof is signed over the replica's random nonce, the primary's position (restore generation, audit length), the
    highest audit sequence and a hash of the certificate list.
    An old reply replayed by someone in the middle, or one with certificates stripped out, fails here, so it cannot
    refresh the lease. Returns the last audit sequence the reply covers, the primary's last sequence, and its signed position.
    """
    try:
        proof = got["proof"]
        body = proof["body"]
        ok = c.verify(primary_pub, "fresh", c.canonical(body), c.b64d(proof["sig"]))
        certs = got["certs"]
        upto, head = body["upto"], body["head"]
        pos = body["position"]
        good = (ok and isinstance(pos, list) and isinstance(head, int) and not isinstance(head, bool) and upto <= head and len(pos) == 2 and all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in pos) and body["nonce"] == nonce and not isinstance(upto, bool) and isinstance(upto, int)
                and body["after"] == max(-1, min(after, head))        # the primary clamps after to its own length
                and body["certs_hash"] == c.sha256_hex(c.canonical(certs)))
    except Exception:  # noqa: BLE001  any malformed reply is a failed proof
        good = False
    if not good:
        raise Denied("bad_proof", "the primary's reply was not fresh, complete and signed for this request", 400)
    return upto, head, (pos[0], pos[1])


class Node:
    """The node-specific parts around a GuardService: sync endpoints and background threads."""

    def __init__(self, svc: GuardService, role: str, token: str, peers: list[str] | None = None,
                 primary_url: str | None = None, primary_pub: bytes | None = None, pull_interval: float = 0.25, cert_page: int = CERT_PAGE):
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
        self.cert_page = max(1, min(int(cert_page), CERT_PAGE))   # audit entries per certificate page
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
        while True:
            with svc._lock:
                head = len(svc.audit.entries) - 1
                start = self.acked[peer] + 1
                upto = min(head, start + self.cert_page - 1)
                if upto < start:
                    self.last_error.pop(peer, None)
                    return
                certs = svc.certs_from_entries(svc.audit.entries[start:upto + 1])
            _http("POST", peer + "/sync/push", self.token, {"certs": certs, "upto": upto})
            self.acked[peer] = upto
        self.last_error.pop(peer, None)

    # -- replica: pull -------------------------------------------------------
    def _pull_loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.pull()
            except Exception as e:  # noqa: BLE001  the lease is what protects us while the primary is out of reach
                why = f"{type(e).__name__}:{e.code}" if isinstance(e, Denied) else type(e).__name__
                if self.last_error.get("primary") != why:
                    print(json.dumps({"node": self.svc.name, "event": "sync_failing", "error": why}), file=sys.stderr, flush=True)
                self.last_error["primary"] = why
            self.wake.wait(self.pull_interval)
            self.wake.clear()

    def pull(self) -> None:
        """Catch up with the primary. Only a pull that completes AND leaves this node at the primary's signed position
        refreshes the lease, and the lease clock starts when the last certificate request was sent, not when the
        reply arrived. Nothing outside the signed proof can keep a lease fresh."""
        assert self.primary_url and self.primary_pub
        with self._pull_lock:
            n = self.svc
            cert_seq = self.cert_seq
            while True:
                nonce = secrets.token_hex(16)
                sent = n.mono()
                got = _http("GET", f"{self.primary_url}/sync/certs?after={cert_seq}&nonce={nonce}&limit={CERT_PAGE}",
                            self.token)
                upto, head, pos = verify_fresh(got, nonce, cert_seq, self.primary_pub)
                if head < cert_seq and pos[0] <= int(n.snapshot_generation):
                    # the primary has fewer entries than we already applied and no restore generation explains it
                    raise Denied("rollback", "the primary's log is shorter than what this node already applied", 503)
                for cert in got["certs"]:
                    n.apply_cert(cert, self.primary_pub)
                reset = head < cert_seq               # a restored primary (higher generation): read its log from the start
                cert_seq = -1 if reset else upto
                if not reset and upto >= head:
                    break
            if (int(n.snapshot_generation), int(n.snapshot_version)) < pos:
                self._install_snapshot()
            if (int(n.snapshot_generation), int(n.snapshot_version)) < pos:
                raise Denied("behind", "this node did not reach the primary's signed position", 503)
            self.cert_seq = cert_seq
            n.last_sync = sent
            self.last_error.pop("primary", None)

    def _install_snapshot(self) -> None:
        """Signed state first, then the missing blobs in pages of about PAGE_BYTES, each checked against its hash.
        If the primary says a blob left its state meanwhile (files changed again), start over from a newer snapshot; blobs
        already fetched are kept (they are stored by hash), so each round only fetches what is new."""
        n = self.svc
        deadline = time.monotonic() + max(2.0, float(n.lease_s or LEASE_S))   # about one lease, then give up and fail closed
        tries = 0
        while tries < 2 or time.monotonic() < deadline:
            tries += 1
            snap = _http("POST", self.primary_url + "/sync/snapshot", self.token, {"have": [], "meta": True}, timeout=10.0)
            try:
                refs = n.blob_refs(snap["body"]["state"])
            except (KeyError, TypeError, AttributeError):
                raise Denied("bad_snapshot", "malformed snapshot", 400) from None
            if not c.verify(self.primary_pub, "snapshot", c.canonical(snap["body"]), c.b64d(snap["sig"])):
                raise Denied("bad_signature", "snapshot signature invalid", 400)   # before any blob is fetched
            missing = sorted(h for h in refs if not n.has_blob(h))
            restart = False
            while missing and not restart:
                reply = _http("POST", self.primary_url + "/sync/blobs", self.token,
                              {"hashes": missing[:64], "max_bytes": PAGE_BYTES}, timeout=10.0)
                page, gone = reply["blobs"], reply.get("gone", [])
                if not isinstance(page, dict) or not isinstance(gone, list):
                    raise Denied("bad_snapshot", "malformed blob page", 400)
                for h, b64 in page.items():
                    if h not in refs:
                        raise Denied("bad_snapshot", "blob that the signed state does not refer to", 400)
                    n.store_synced_blob(h, b64)
                if gone:
                    restart = True
                elif not page:
                    raise Denied("bad_snapshot", "empty blob page", 400)
                missing = [h for h in missing if not n.has_blob(h)]
            if restart:
                continue
            n.install_snapshot(snap, self.primary_pub)
            return
        raise Denied("churn", "the primary's files changed faster than this node could copy them", 503)

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
                    pull_interval: float = 0.25, cors_origins: list[str] | None = None,
                    cert_page: int = CERT_PAGE) -> tuple[FastAPI, Node]:
    svc = GuardService(data_dir, name=name, read_only=(role == "replica"),
                       lease_s=lease_s if role == "replica" else None)
    node = Node(svc, role, token, peers, primary_url, primary_pub, pull_interval, cert_page)
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

        @app.get("/sync/certs")
        def certs(after: int = -1, nonce: str = "", limit: int = CERT_PAGE,
                  x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            if not 16 <= len(nonce) <= 64 or any(ch not in "0123456789abcdef" for ch in nonce):
                raise Denied("bad_request", "nonce must be 16 to 64 lowercase hex characters", 400)
            limit = max(1, min(limit, node.cert_page))
            with svc._lock:
                head = len(svc.audit.entries) - 1
                after = max(-1, min(after, head))
                upto = min(head, after + limit)           # this page covers entries after+1 .. upto
                lst = svc.certs_from_entries(svc.audit.entries[after + 1:upto + 1])
                body = {"nonce": nonce, "after": after, "upto": upto, "head": head, "position": list(svc.sync_position()),
                        "certs_hash": c.sha256_hex(c.canonical(lst))}
                sig = c.b64e(c.sign(svc._sec, "fresh", c.canonical(body)))
                return {"certs": lst, "upto": upto, "proof": {"body": body, "sig": sig}}

        @app.post("/sync/snapshot")
        async def snapshot(request: Request, x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            try:
                body = json.loads(await read_capped(request, MAX_BODY))
                have = {str(h) for h in body["have"]}
                meta = body.get("meta", False)
                if not isinstance(meta, bool):
                    raise ValueError
            except (ValueError, KeyError, TypeError, RecursionError):
                raise Denied("bad_request", "have must be a list of blob hashes", 400) from None
            return svc.export_snapshot(have=have, with_blobs=not meta)

        @app.post("/sync/blobs")
        async def blobs(request: Request, x_kig_cluster_token: str = Header(default="")) -> dict[str, Any]:
            authed(x_kig_cluster_token)
            try:
                body = json.loads(await read_capped(request, MAX_BODY))
                hashes, cap = body["hashes"], body["max_bytes"]
                if (not isinstance(hashes, list) or not 1 <= len(hashes) <= 256 or not all(isinstance(h, str) for h in hashes)
                        or isinstance(cap, bool) or not isinstance(cap, int)):
                    raise ValueError
            except (ValueError, KeyError, TypeError, RecursionError):
                raise Denied("bad_request", "hashes must be a list of 1 to 256 blob hashes and max_bytes an integer", 400) from None
            got, gone = svc.read_blobs(hashes, max(1, min(cap, PAGE_BYTES)))
            return {"blobs": got, "gone": gone}
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
    ap.add_argument("--cert-page", type=int, default=CERT_PAGE, help="audit entries per certificate page (at most 200)")
    ap.add_argument("--bootstrap")
    ns = ap.parse_args(argv)
    if ns.bootstrap and ns.role != "primary":
        ap.error("--bootstrap is only for the primary; a replica gets its state from the primary")
    token = _read_token(ns.cluster_token_file)
    pub = Path(ns.primary_pub).read_bytes() if ns.primary_pub else None
    if ns.bootstrap:
        _bootstrap(ns.data, ns.bootstrap)
    app, _ = create_node_app(ns.data, ns.role, ns.name, token, ns.peer, ns.primary_url, pub, ns.lease, ns.pull_interval, None, ns.cert_page)
    import uvicorn
    uvicorn.run(app, host=ns.host, port=ns.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
