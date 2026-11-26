"""Operator and device command line.

  python -m kig.cli init --data ./data --user asha --device asha-laptop --out asha-laptop.json
  python -m kig.cli keygen --user ravi --device ravi-laptop --out ravi-laptop.json
  python -m kig.cli call --url http://127.0.0.1:8443 --key asha-laptop.json enroll_device '{...}'
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

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
    p = sub.add_parser("doctor", help="check a data directory: state, audit chain, blobs, permissions")
    p.add_argument("--data", required=True)
    p = sub.add_parser("rotate-pending", help="re-key every file flagged needs_rotation that this device may rotate")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p = sub.add_parser("call")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("cmd")
    p.add_argument("args", nargs="?", default="{}")
    a = ap.parse_args(argv)

    if a.op == "doctor":
        from .doctor import run
        return run(a.data)
    if a.op == "verify-log":
        from pathlib import Path
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
        return 0
    cl = Client(Device.load(a.key), _post(a.url))
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
