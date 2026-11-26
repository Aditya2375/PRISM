"""Start a throwaway PRISM demo on one public port, for a hosted review copy.

Creates fresh demo data under a temporary directory on every start (the same story as web-p3/run_demo.sh: Asha,
her limited phone, Ravi, three files, a lost phone and the alerts it causes), runs the PRISM service and the
local user backend on loopback only, and serves the console plus an allow-listed proxy on $PORT.
Tokens are random per start and printed once to the log. Demo data only. Nothing is kept across restarts.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
U = "http://127.0.0.1:8443"


def kig(*args: str, cwd: Path, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PY, "-m", "kig.cli", *args], cwd=cwd, env=env, capture_output=True, text=True, check=check)


def main() -> int:
    d = Path(tempfile.mkdtemp(prefix="prism-hosted-"))
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    r = kig("init", "--data", "./data", "--user", "asha", "--device", "asha-laptop", "--out", "asha-laptop.json", cwd=d, env=env)
    fp = re.search(r"^root fingerprint.*: (.+)$", r.stdout, re.M).group(1).strip()
    svc_env = {**env, "KIG_DATA": str(d / "data")}
    svc = subprocess.Popen([PY, "-m", "uvicorn", "--factory", "kig.server:app", "--host", "127.0.0.1", "--port", "8443"],
                           cwd=d, env=svc_env, stdout=open(d / "svc.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(80):
        try:
            urllib.request.urlopen(U + "/healthz", timeout=1); break
        except Exception:
            time.sleep(0.25)
    R = ["--root-fingerprint", fp]
    base = ["--url", U, *R]

    def keygen(user: str, device: str) -> str:
        out = kig("keygen", "--user", user, "--device", device, "--out", f"{device}.json", cwd=d, env=env)
        (d / f"{device}-pub.json").write_text(out.stdout)
        return re.search(r"^fingerprint.*: (.+)$", out.stderr, re.M).group(1).strip()

    pf = keygen("asha", "asha-phone")
    kig("enroll", *base, "--key", "asha-laptop.json", "--pub", "asha-phone-pub.json", "--expect-fingerprint", pf, "--limited", cwd=d, env=env)
    kig("call", *base, "--key", "asha-laptop.json", "create_user", '{"user":"ravi","role":"member"}', cwd=d, env=env)
    rf = keygen("ravi", "ravi-laptop")
    kig("enroll", *base, "--key", "asha-laptop.json", "--pub", "ravi-laptop-pub.json", "--expect-fingerprint", rf, cwd=d, env=env)
    for name, text in (("a.txt", "payroll for 2026"), ("b.txt", "launch plan"), ("c.txt", "ravi private note")):
        (d / name).write_text(text + "\n")
    kig("put", *base, "--key", "asha-laptop.json", "--file-id", "payroll-2026", "--path", "a.txt", "--acl", "ravi", cwd=d, env=env)
    kig("put", *base, "--key", "asha-laptop.json", "--file-id", "launch-plan", "--path", "b.txt", cwd=d, env=env)
    kig("put", *base, "--key", "ravi-laptop.json", "--file-id", "ravi-note", "--path", "c.txt", cwd=d, env=env)
    kig("get", *base, "--key", "asha-phone.json", "--file-id", "payroll-2026", "--out", "p.out", cwd=d, env=env)
    kig("call", *base, "--key", "asha-laptop.json", "report_lost", '{"device":"asha-phone","reason":"left in a taxi"}', cwd=d, env=env)
    kig("get", *base, "--key", "asha-phone.json", "--file-id", "payroll-2026", "--out", "p.out", cwd=d, check=False, env=env)
    kig("get", *base, "--key", "ravi-laptop.json", "--file-id", "payroll-2026", "--out", "r.out", cwd=d, env=env)
    wa_log = open(d / "wa.log", "w")
    wa = subprocess.Popen([PY, "-m", "kig.webapi", "--key", "asha-laptop.json", "--url", U, *R, "--port", "8788"],
                          cwd=d, env=env, stdout=wa_log, stderr=subprocess.STDOUT)
    st = ""
    for _ in range(80):
        m = re.search(r"token \(send as x-prism-session\): (\S+)", (d / "wa.log").read_text())
        if m:
            st = m.group(1); break
        time.sleep(0.25)
    ot = (d / "data" / "operator.token").read_text().strip()
    print("PRISM hosted demo ready. Demo data only. Tokens change on every restart.", flush=True)
    print("OPERATOR_TOKEN=" + ot, flush=True)
    print("SESSION_TOKEN=" + st, flush=True)
    import uvicorn
    from hosted.proxy import build_app
    static = os.environ.get("HOSTED_STATIC", str(ROOT / "web-p3" / "hosted-dist"))
    try:
        uvicorn.run(build_app(static), host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), proxy_headers=False,
                    timeout_keep_alive=5, h11_max_incomplete_event_size=8192, timeout_graceful_shutdown=3)
    finally:
        for p in (wa, svc):
            p.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
