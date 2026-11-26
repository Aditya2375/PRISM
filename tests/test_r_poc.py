import json, subprocess, sys
from pathlib import Path
V = str(Path(__file__).parent.parent / "verifier" / "prism_verify.py")

def run(*a):
    p = subprocess.run([sys.executable, V, *a], capture_output=True, text=True)
    return p.returncode, p.stdout.strip()

def _log(w):
    d = w.svc.dir
    return d / "audit.jsonl", d / "audit.head", d / "server_sign.pub"

def test_R1_truncated_log_with_self_rewritten_anchor_is_not_OK(w, tmp_path):
    log, head, pub = _log(w)
    L = log.read_text().splitlines(keepends=True)
    (tmp_path / "audit.jsonl").write_text("".join(L[:-3]))
    last = json.loads(L[-4])
    (tmp_path / "audit.head").write_text(json.dumps({"seq": last["seq"], "hash": last["hash"], "sig": last["sig"]}))
    rc, out = run("audit", "--log", str(tmp_path / "audit.jsonl"), "--pub", str(pub), "--anchor", str(tmp_path / "audit.head"))
    assert rc != 0 or "NOT" in out or "cannot be excluded" in out, f"3 entries removed, verifier says: {out}"

def test_R2_anchor_with_seq_minus_one_accepts_an_empty_log(w, tmp_path):
    log, head, pub = _log(w)
    (tmp_path / "audit.jsonl").write_text("")
    (tmp_path / "audit.head").write_text(json.dumps({"seq": -1}))
    rc, out = run("audit", "--log", str(tmp_path / "audit.jsonl"), "--pub", str(pub), "--anchor", str(tmp_path / "audit.head"))
    assert rc != 0, f"entire log deleted, verifier says: {out}"

def test_R3_empty_log_without_anchor_is_OK(w, tmp_path):
    log, head, pub = _log(w)
    (tmp_path / "audit.jsonl").write_text("")
    rc, out = run("audit", "--log", str(tmp_path / "audit.jsonl"), "--pub", str(pub))
    assert rc != 0, f"empty log and no anchor, verifier says: {out}"

def test_R4_unsigned_extra_fields_in_entries_are_ignored_silently(w, tmp_path):
    log, head, pub = _log(w)
    L = [json.loads(x) for x in log.read_text().splitlines()]
    L[2]["note"] = "forged annotation, not covered by hash or signature"
    (tmp_path / "audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in L))
    rc, out = run("audit", "--log", str(tmp_path / "audit.jsonl"), "--pub", str(pub), "--anchor", str(head))
    assert rc != 0, "an entry carrying extra unsigned fields passes as OK"
