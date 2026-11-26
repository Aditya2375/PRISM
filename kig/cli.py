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
    p = sub.add_parser("call")
    p.add_argument("--url", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("cmd")
    p.add_argument("args", nargs="?", default="{}")
    a = ap.parse_args(argv)

    if a.op == "verify-log":
        from pathlib import Path
        from .audit import verify_chain
        entries = [json.loads(l) for l in (Path(a.data) / "audit.jsonl").read_text().splitlines() if l.strip()]
        ok, why = verify_chain(entries, (Path(a.data) / "server_sign.pub").read_bytes())
        print(f"{'OK' if ok else 'FAILED'}: {why} ({len(entries)} entries)")
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
    try:
        print(json.dumps(cl.call(a.cmd, **json.loads(a.args)), indent=2))
    except Denied as e:
        print(f"denied: {e.code}: {e.reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
