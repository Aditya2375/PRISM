import ast
import json
import subprocess
import sys
from pathlib import Path

from kig import backup, crypto as c

V = Path(__file__).resolve().parent.parent / "verifier" / "prism_verify.py"


def run(*args):
    r = subprocess.run([sys.executable, str(V), *map(str, args)], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def test_verifier_does_not_import_the_service_code():
    tree = ast.parse(V.read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m and m.split(".")[0] == "kig" for m in mods)


def test_audit_log_ok_then_each_tamper_fails(w, tmp_path):
    d = w.svc.dir
    base = ["audit", "--log", d / "audit.jsonl", "--pub", d / "server_sign.pub", "--anchor", d / "audit.head"]
    assert run(*base)[0] == 0
    assert run(*base, "--expect-head", w.svc.audit.head)[0] == 0
    assert run(*base, "--expect-head", "0" * 64)[0] == 1
    lines = (d / "audit.jsonl").read_text().splitlines()
    e = json.loads(lines[3]); e["actor"] = "mallory"
    forged = tmp_path / "forged.jsonl"; forged.write_text("\n".join(lines[:3] + [json.dumps(e)] + lines[4:]) + "\n")
    assert run("audit", "--log", forged, "--pub", d / "server_sign.pub", "--anchor", d / "audit.head")[0] == 1
    short = tmp_path / "short.jsonl"; short.write_text("\n".join(lines[:-2]) + "\n")
    assert run("audit", "--log", short, "--pub", d / "server_sign.pub", "--anchor", d / "audit.head")[0] == 1
    swapped = tmp_path / "swap.jsonl"; swapped.write_text("\n".join(lines[:2] + [lines[3], lines[2]] + lines[4:]) + "\n")
    assert run("audit", "--log", swapped, "--pub", d / "server_sign.pub", "--anchor", d / "audit.head")[0] == 1
    assert run("audit", "--log", d / "audit.jsonl", "--pub", d / "server_sign.pub")[0] == 1   # no anchor: refuses


def test_wrong_service_key_fails(w, tmp_path):
    other = c.sig_keygen()[0]
    (tmp_path / "other.pub").write_bytes(other)
    assert run("audit", "--log", w.svc.dir / "audit.jsonl", "--pub", tmp_path / "other.pub")[0] == 1


def test_backup_and_state(w, tmp_path):
    pub, sec = c.kem_keygen()
    bk = tmp_path / "x.bak"; backup.create(w.svc, pub, bk)
    sp = w.svc.dir / "server_sign.pub"
    assert run("backup", "--file", bk, "--pub", sp)[0] == 0
    raw = bytearray(bk.read_bytes())
    import tarfile
    with tarfile.open(bk) as t:
        blob = next(m for m in t if m.name.startswith("blobs/"))
    raw[blob.offset_data + 3] ^= 1
    bad = tmp_path / "bad.bak"; bad.write_bytes(bytes(raw))
    code, out = run("backup", "--file", bad, "--pub", sp)
    assert code == 1 and "does not match its hash" in out
    w.svc._persist(); w.svc.store.snapshot() if hasattr(w.svc.store, "snapshot") else None
    assert run("state", "--file", w.svc.dir / "state.json", "--pub", sp)[0] == 0
