#!/usr/bin/env python3
"""Smoke test for a running PRISM deployment (the service, or the hosted demo). Standard library only.

    python scripts/smoke.py https://host [--operator-token T] [--session-token T]

Checks: /healthz answers 200 with ok; the console or API sends the security headers; a protected path refuses a request
without a token; with a token it answers. Exit 0 when every check passes, 1 otherwise. Tokens are read from the flags or
from SMOKE_OPERATOR_TOKEN and SMOKE_SESSION_TOKEN, and are never printed."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def get(url: str, headers: dict[str, str] | None = None, timeout: float = 20.0):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict((k.lower(), v) for k, v in r.headers.items()), r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, dict((k.lower(), v) for k, v in e.headers.items()), e.read(65536)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--operator-token", default=os.environ.get("SMOKE_OPERATOR_TOKEN", ""))
    ap.add_argument("--session-token", default=os.environ.get("SMOKE_SESSION_TOKEN", ""))
    a = ap.parse_args()
    base = a.url.rstrip("/")
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        results.append((name, ok, note))
        print(("PASS " if ok else "FAIL ") + name + (f"  ({note})" if note and not ok else ""))

    try:
        st, h, body = get(base + "/healthz")
        check("/healthz is 200 and ok", st == 200 and json.loads(body).get("ok") is True, f"status {st}")
        for name in ("x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy"):
            check(f"header {name} present", name in h)
        st, _, _ = get(base + "/v1/overview")
        check("/v1/overview refuses a request with no token", st in (401, 403), f"status {st}")
        if a.operator_token:
            st, _, body = get(base + "/v1/overview", {"X-KIG-Operator-Token": a.operator_token})
            check("/v1/overview answers with the operator token", st == 200 and "users" in json.loads(body), f"status {st}")
            st, _, _ = get(base + "/v1/overview", {"X-KIG-Operator-Token": a.operator_token + "x"})
            check("/v1/overview refuses a wrong token", st in (401, 403), f"status {st}")
        if a.session_token:
            st, _, _ = get(base + "/me", {"X-PRISM-Session": a.session_token})
            check("/me answers with the session token", st == 200, f"status {st}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        check("deployment reachable", False, type(e).__name__)
    bad = [r for r in results if not r[1]]
    print(f"{len(results) - len(bad)}/{len(results)} checks passed")
    return 1 if bad or not results else 0


if __name__ == "__main__":
    sys.exit(main())
