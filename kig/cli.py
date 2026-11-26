"""Operator and device command line.

  python -m kig.cli init --data ./data --user asha --device asha-laptop --out asha-laptop.json
  python -m kig.cli keygen --user ravi --device ravi-laptop --out ravi-laptop.json
  python -m kig.cli call --url http://127.0.0.1:8443 --key asha-laptop.json enroll_device '{...}'
"""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys
import urllib.error
import urllib.request

from . import crypto as c
from .client import Client, Device
from .service import Denied, GuardService


def _post(url: str):
    def send(env):
        req = urllib.request.Request(url.rstrip("/") + "/v1/command", data=json.dumps(env).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = json.load(e)
            raise Denied(body.get("error", "error"), body.get("reason", ""), e.code) from None
    return send


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kig")
    sub = ap.add_subparsers(dest="op", required=True)
    for name in ("init", "keygen"):
        p = sub.add_parser(name)
        p.add_argument("--user", required=True)
        p.add_argument("--device", required=True)
        p.add_argument("--out", required=True, help="where to write the device key file (mode 0600)")
        if name == "init":
            p.add_argument("--data", required=True)
    p = sub.add_parser("verify-log", help="verify the signed key-event log offline")
    p.add_argument("--data", required=True)
    p.add_argument("--expect-head", default=None, help="head hash recorded elsewhere; detects tail truncation")
    p = sub.add_parser("backup-key", help="split the backup private key into k-of-n shares, or combine shares")
    bk = p.add_subparsers(dest="bk", required=True)
    q = bk.add_parser("split")
    q.add_argument("--key", required=True, help="backup.key file (unsealed; split before you seal it elsewhere)")
    q.add_argument("-k", type=int, required=True)
    q.add_argument("-n", type=int, required=True)
    q.add_argument("--out-dir", required=True)
    q = bk.add_parser("combine")
    q.add_argument("--shares", nargs="+", required=True)
    q.add_argument("--out", required=True)
    p = sub.add_parser("doctor", help="check a data directory: state, audit chain, blobs, permissions")
    p.add_argument("--data", required=True)
    p = sub.add_parser("enroll", help="enrol a new device from its public-key JSON, after comparing its fingerprint")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True, help="the admin's own key file")
    p.add_argument("--pub", required=True, help="path to the JSON printed by `keygen` on the new device")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--expect-fingerprint", help="fingerprint read aloud or shown on the new device")
    g.add_argument("--unverified", action="store_true", help="enrol without comparing a fingerprint (recorded as unverified)")
    p = sub.add_parser("put", help="encrypt a local file and store it")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--file-id", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--acl", default="", help="comma-separated users besides yourself")
    p = sub.add_parser("get", help="fetch and decrypt a file; checks the signed manifest and pins")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--file-id", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("rotate-pending", help="re-key every file flagged needs_rotation that this device may rotate")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p = sub.add_parser("call")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("cmd")
    p.add_argument("args", nargs="?", default="{}")
    a = ap.parse_args(argv)

    if a.op == "backup-key":
        from . import threshold, vault
        try:
            if a.bk == "split":
                secret = Path(a.key).read_bytes()
                if vault.is_sealed(secret):
                    print("refused: the key file is passphrase-sealed; split the unsealed key", file=sys.stderr)
                    return 2
                out = Path(a.out_dir)
                out.mkdir(parents=True, exist_ok=True)
                for idx, sh in enumerate(threshold.split(secret, a.k, a.n), 1):
                    vault.write_atomic(out / f"share-{idx}.json", sh, 0o600)
                    print(f"share-{idx}.json  fingerprint {threshold.fingerprint(sh)}")
                print(f"{a.k} of {a.n} shares are needed. Record the fingerprints separately; give each share to a different holder.")
            else:
                key = threshold.combine([Path(x).read_bytes() for x in a.shares])
                vault.write_atomic(a.out, key, 0o600)
                print(f"recovered {len(key)} bytes to {a.out}")
        except threshold.ThresholdError as e:
            print(f"refused: {e}", file=sys.stderr)
            return 2
        return 0
    if a.op == "doctor":
        from .doctor import run
        return run(a.data)
    if a.op == "verify-log":
        from .audit import check_log, first_bad_seq
        d = Path(a.data)
        pub = (d / "server_sign.pub").read_bytes()
        try:
            entries = [json.loads(l) for l in (d / "audit.jsonl").read_bytes().split(b"\n") if l.strip()]
        except (ValueError, RecursionError):
            print("FAILED: unparseable line in log")
            return 1
        anchor = None
        if (d / "audit.head").exists():
            try:
                anchor = json.loads((d / "audit.head").read_text())
            except ValueError:
                anchor = {}
        ok, why = check_log(entries, anchor, pub, a.expect_head)
        bad = first_bad_seq(why)
        print(f"{'OK' if ok else 'FAILED'}: {why} ({len(entries)} entries)" + (f" first_bad_seq={bad}" if not ok and bad is not None else ""))
        return 0 if ok else 1
    if a.op in ("init", "keygen"):
        dev = Device.generate(a.device, a.user)
        dev.save(a.out)
        if a.op == "init":
            GuardService(a.data).bootstrap(a.user, a.device, dev.sign_pub, dev.kem_pub)
            print(f"bootstrapped admin {a.user} with device {a.device}; key file {a.out}")
        else:
            print(json.dumps(dev.public_args()))
            print(f"fingerprint (read this to the admin): {dev.fingerprint()}", file=sys.stderr)
        return 0
    # the rollback record and the pinned writer keys live next to the key file, so separate runs share them
    cl = Client(Device.load(a.key), _post(a.url), state_path=str(a.key) + ".state")
    if a.op == "put":
        try:
            r = cl.put_file(a.file_id, Path(a.path).read_bytes(), acl=[u for u in a.acl.split(",") if u])
        except Denied as e:
            print(f"denied: {e.code}: {e.reason}", file=sys.stderr)
            return 2
        print(json.dumps(r))
        return 0
    if a.op == "get":
        try:
            data = cl.fetch(a.file_id)
        except Denied as e:
            print(f"denied: {e.code}: {e.reason}", file=sys.stderr)
            return 2
        except c.CryptoError as e:
            print(f"refused: {e}", file=sys.stderr)
            return 3
        Path(a.out).write_bytes(data)
        print(f"wrote {len(data)} bytes to {a.out}")
        return 0
    if a.op == "enroll":
        raw = json.loads(Path(a.pub).read_text())
        allowed = {"device", "user", "sign_pub", "kem_pub"}
        if not isinstance(raw, dict) or set(raw) != allowed or not all(isinstance(raw[k], str) for k in allowed):
            print(f"refused: the pub file must hold exactly {sorted(allowed)} as strings", file=sys.stderr)
            return 2
        args = dict(raw)
        if a.expect_fingerprint is not None:
            if not a.expect_fingerprint.strip():
                print("refused: --expect-fingerprint is empty", file=sys.stderr)
                return 2
            args["expect_fingerprint"] = a.expect_fingerprint
        print(f"enrolling device {args['device']} for user {args['user']}", file=sys.stderr)
        try:
            r = cl.call("enroll_device", **args)
        except Denied as e:
            print(f"denied: {e.code}: {e.reason}", file=sys.stderr)
            return 2
        print(f"enrolled {args['device']} for {args['user']}; fingerprint {r.get('fingerprint')}"
              + ("" if r.get("verified") else " (UNVERIFIED)"))
        return 0
    if a.op == "rotate-pending":
        try:
            todo = [f for f in cl.call("list_files")["files"] if f["needs_rotation"]]
            skipped = [f["file_id"] for f in todo if not (f["can_rotate"] and f["has_key"])]
            done = []
            for f in todo:
                if f["can_rotate"] and f["has_key"]:
                    cl.fetch(f["file_id"])
                    done.append(f["file_id"])
        except Denied as e:
            print(f"denied: {e.code}: {e.reason}", file=sys.stderr)
            return 2
        print(json.dumps({"rotated": done, "needs_an_owner_or_admin_with_a_key": skipped,
                          "errors": cl.rotation_errors}, indent=2))
        return 0 if not skipped and not cl.rotation_errors else 3
    try:
        print(json.dumps(cl.call(a.cmd, **json.loads(a.args)), indent=2))
    except Denied as e:
        print(f"denied: {e.code}: {e.reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
