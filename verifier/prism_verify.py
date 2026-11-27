#!/usr/bin/env python3
"""Standalone verifier for P.R.I.S.M. evidence. It imports nothing from the `kig` package.

It needs Python 3.10+ and the `cryptography` package (for ML-DSA-65 signature checks) and nothing else, and it
reads only files. It never needs a private key and never writes. The format rules are re-implemented here
from docs/CORE.md and docs/CRYPTO.md, so a bug in the service's own checker cannot hide a bad log.

    python verifier/prism_verify.py audit  --log audit.jsonl --pub server_sign.pub [--anchor audit.head] [--expect-head HASH]
    python verifier/prism_verify.py backup --file x.bak     --pub server_sign.pub
    python verifier/prism_verify.py state  --file state.json --pub server_sign.pub

Exit code 0 only if every check passes and completeness is established; 1 if a check fails; 2 if everything
verified but completeness could not be established (audit without --expect-head, or state, which does not check the
journal). A script that tests only the exit code is therefore never told OK about a possibly truncated log. Each check prints one line, OK or FAIL, with a reason.

What it proves: the audit log is an unbroken, correctly signed chain (and, with --expect-head, that it ends where
you recorded it); a backup's manifest is signed by the service and every blob inside matches its hash; state.json
carries the service's signature. What it does not prove: that the service made the right decisions, or that nothing
newer was removed unless you give it a head or counter you recorded elsewhere.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import tarfile

from cryptography.hazmat.primitives.asymmetric import mldsa

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sig_ok(pub: bytes, purpose: str, msg: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
        mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(sig, b"kig/v1/" + purpose.encode("ascii") + b"\x00" + msg)
        return True
    except Exception:  # noqa: BLE001  any failure to verify is a failure
        return False


def verify_audit(lines: list[bytes], pub: bytes, anchor: dict | None, expect_head: str | None) -> tuple[bool, str]:
    entries = []
    for n, raw in enumerate(lines):
        if not raw.strip():
            continue
        try:
            entries.append(json.loads(raw))
        except ValueError:
            return False, f"line {n + 1} is not JSON"
    prev = GENESIS
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or set(e) != {"seq", "ts", "prev", "type", "actor", "data", "hash", "sig"}:
            return False, f"entry {i} is malformed or carries fields that are not covered by the signature"
        try:
            body = {k: e[k] for k in ("seq", "ts", "prev", "type", "actor", "data")}
        except (KeyError, TypeError):
            return False, f"entry {i} is malformed"
        if e["seq"] != i:
            return False, f"entry {i}: sequence gap or reorder"
        if e["prev"] != prev:
            return False, f"entry {i}: broken link to the previous entry"
        h = sha(canonical(body))
        if e.get("hash") != h:
            return False, f"entry {i}: content was changed (hash mismatch)"
        if not sig_ok(pub, "audit", h.encode("ascii"), e.get("sig", "")):
            return False, f"entry {i}: bad signature"
        prev = h
    if not entries:
        return False, "the log is empty: nothing to verify, and an emptied log cannot be told from a new one"
    if anchor is not None:
        sq, ah = anchor.get("seq"), anchor.get("hash")
        if not isinstance(sq, int) or isinstance(sq, bool) or sq < 0 or not isinstance(ah, str):
            return False, "head anchor is malformed"
        if len(entries) <= sq:
            return False, f"log is shorter than its head anchor ({len(entries)} entries, anchor at seq {sq})"
        if entries[sq]["hash"] != ah or not sig_ok(pub, "audit", ah.encode("ascii"), str(anchor.get("sig", ""))):
            return False, "head anchor does not match the log"
    if expect_head is not None and prev != expect_head:
        return False, "log ends at a different head than the one you recorded"
    msg = f"{len(entries)} entries, chain and signatures verify, head {prev}"
    if expect_head:
        return True, msg + ", head matches the one you recorded: tail removal is excluded"
    return True, msg + ("\nNOTE audit: completeness NOT established. An anchor stored beside the log is not independent; "
                        "entries could have been removed from the end. Compare the head above with one recorded "
                        "elsewhere, or pass --expect-head." + (" (anchor was read and matches)" if anchor else
                        " (no anchor given)"))


def verify_backup(path: str, pub: bytes) -> tuple[bool, str]:
    try:
        tf = tarfile.open(path, "r:")
    except (tarfile.TarError, OSError) as e:
        return False, f"not a readable archive: {e}"
    with tf:
        names = [m.name for m in tf]
        if len(names) != len(set(names)):
            return False, "archive contains duplicate member names"
        members = {m.name: m for m in tf if m.isfile()}
        bad = [m.name for m in tf if not m.isfile() or not (m.name in ("manifest.json", "meta.sealed.json")
                                                          or re.fullmatch(r"blobs/[0-9a-f]{64}", m.name))]
        if bad:
            return False, f"unexpected archive member(s): {bad[:3]}"
        if "manifest.json" not in members or members["manifest.json"].size > 1 << 26:
            return False, "manifest.json missing or too large"
        try:
            doc = json.loads(tf.extractfile(members["manifest.json"]).read())
            sig = doc.pop("sig")
            man = doc["manifest"]
        except Exception:  # noqa: BLE001
            return False, "manifest.json is unreadable"
        if not sig_ok(pub, "backup", canonical(doc), sig):
            return False, "manifest signature is not valid for this service key"
        if man.get("service_pub_sha256") != sha(pub):
            return False, "backup names a different service key"
        hashes = man.get("blobs")
        if not isinstance(hashes, list) or hashes != sorted(set(hashes)) or man.get("blobs_sha256") != sha(canonical(hashes)):
            return False, "blob list does not match its signed digest"
        if {n for n in members if n.startswith("blobs/")} != {f"blobs/{h}" for h in hashes}:
            return False, "blobs in the archive differ from the signed list"
        for h in hashes:
            ti = members[f"blobs/{h}"]
            d, fh = hashlib.sha256(), tf.extractfile(ti)
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                d.update(chunk)
            if d.hexdigest() != h:
                return False, f"blob {h[:12]} does not match its hash"
        sealed = tf.extractfile(members["meta.sealed.json"]).read() if "meta.sealed.json" in members else b""
        if sha(sealed) != man.get("meta_sha256"):
            return False, "sealed metadata does not match the manifest"
        return True, (f"manifest signed by the service, counter {man.get('counter')}, {len(hashes)} blobs match their "
                      f"hashes, audit head {str(man.get('audit_head'))[:16]} over {man.get('audit_len')} entries "
                      "(the sealed metadata needs the backup key and is not opened here)")


def verify_state(path: str, pub: bytes) -> tuple[bool, str]:
    try:
        st = json.loads(open(path, "rb").read())
        sig = st.pop("_sig")
    except Exception:  # noqa: BLE001
        return False, "state file is unreadable or unsigned"
    if not sig_ok(pub, "state", canonical(st), sig):
        return False, "state signature is not valid for this service key"
    w = st.get("_wal", {})
    return True, (f"signed snapshot, journal id {str(w.get('id'))[:8]}, seq {w.get('seq')}\nNOTE state: the journal "
                  "after the snapshot is NOT checked here, and an older signed snapshot also passes (rollback).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="prism_verify", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="what", required=True)
    for name in ("audit", "backup", "state"):
        p = sub.add_parser(name)
        p.add_argument("--pub", required=True, help="the service's public key file (server_sign.pub)")
        if name == "audit":
            p.add_argument("--log", required=True)
            p.add_argument("--anchor", help="audit.head next to the log")
            p.add_argument("--expect-head", help="head hash you recorded earlier")
        else:
            p.add_argument("--file", required=True)
    a = ap.parse_args(argv)
    pub = open(a.pub, "rb").read()
    if a.what == "audit":
        anchor = None
        if a.anchor:
            try:
                anchor = json.loads(open(a.anchor).read())
            except (OSError, ValueError):
                anchor = {}
        ok, why = verify_audit(open(a.log, "rb").read().split(b"\n"), pub, anchor, a.expect_head)
    elif a.what == "backup":
        ok, why = verify_backup(a.file, pub)
    else:
        ok, why = verify_state(a.file, pub)
    print(("OK   " if ok else "FAIL ") + a.what + ": " + why)
    return 1 if not ok else (2 if "\nNOTE" in why else 0)


if __name__ == "__main__":
    sys.exit(main())
