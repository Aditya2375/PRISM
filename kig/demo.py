"""End-to-end demo of the lost-device scenario. Run: python -m kig.demo"""
from __future__ import annotations

import json
import sys
import tempfile
import time

from .client import Client, Device
from .service import Denied, GuardService


def step(n: int, text: str) -> None:
    print(f"\n[{n}] {text}")


def main(story: bool = False) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        svc = GuardService(tmp)
        time.sleep(0.01)
        laptop = Device.generate("asha-laptop", "asha")
        svc.bootstrap("asha", "asha-laptop", laptop.sign_pub, laptop.kem_pub)
        admin = Client(laptop, svc.handle)
        admin.call("create_user", user="ravi", role="member")
        phone, rlap = Device.generate("asha-phone", "asha"), Device.generate("ravi-laptop", "ravi")
        for d in (phone, rlap):
            admin.call("enroll_device", **d.public_args())
        asha_phone, ravi = Client(phone, svc.handle), Client(rlap, svc.handle)

        step(1, "Normal operation: Asha stores a file shared with Ravi; both read it")
        admin.put_file("payroll-2026", b"salary table: confidential", acl=["asha", "ravi"])
        print("   ravi reads:", ravi.fetch("payroll-2026", auto_rotate=False).decode())
        print("   phone reads:", asha_phone.fetch("payroll-2026", auto_rotate=False).decode())

        step(2, "Security control: Asha's phone is reported lost")
        print("  ", json.dumps(admin.call("report_lost", device="asha-phone", reason="stolen")))

        step(3, "Whoever holds the phone tries again with a valid signature")
        try:
            asha_phone.fetch("payroll-2026")
        except Denied as e:
            print(f"   denied: {e.code} ({e.reason})")

        step(4, "Reliability: the next legitimate read rotates the file key automatically")
        print("   ravi reads:", ravi.fetch("payroll-2026").decode())
        print("   epoch now:", svc.overview()["files"]["payroll-2026"])

        step(5, "Verifiable outcome: alert, evidence and signed audit chain")
        for a in svc.alerts():
            print(f"   ALERT {a['rule']} [{a['severity']}] evidence={a['evidence']}\n     {a['explanation']}")
        ok, why = svc.audit.verify()
        print(f"   audit chain verifies: {ok} ({why}); entries={len(svc.audit.entries)}")
        for e in svc.audit.entries:
            if e["seq"] in {a2 for a in svc.alerts() for a2 in a["evidence"]}:
                print(f"   seq {e['seq']:>2} {e['type']:<26} actor={e['actor']}")
        if story:
            ok = _story(tmp, svc, admin, ravi) and ok
        return 0 if ok else 1


def _story(tmp: str, svc: GuardService, admin: Client, ravi: Client) -> bool:
    """Steps 6 to 8: tampering, a crash in the middle of a rotation, and the claim-to-evidence table."""
    from pathlib import Path
    from .doctor import check
    from .service import SimulatedCrash
    good = True

    step(6, "Tampering: a stored ciphertext is changed on disk, and an audit line is edited")
    h = next(iter(svc.blob_hashes()))
    bp = svc._blob_path(h)
    orig = bp.read_bytes()
    bp.write_bytes(orig[:-1] + bytes([orig[-1] ^ 1]))
    try:
        ravi.fetch("payroll-2026", auto_rotate=False)
        print("   UNEXPECTED: tampered blob was served")
        good = False
    except Denied as e:
        print(f"   read refused: {e.code}")
    print("   doctor:", "; ".join(f"{r[0]} {r[1]}" for r in check(tmp) if r[0] != "OK") or "nothing found")
    bp.write_bytes(orig)
    ap = Path(tmp) / "audit.jsonl"
    lines = ap.read_text().splitlines()
    saved = ap.read_text()
    e = json.loads(lines[3]); e["actor"] = "someone-else"; lines[3] = json.dumps(e, sort_keys=True)
    ap.write_text("\n".join(lines) + "\n")
    print("   doctor after the audit edit:", "; ".join(f"{r[0]} {r[1]}" for r in check(tmp) if r[0] != "OK") or "nothing found")
    good = good and any(r[0] == "FAIL" and r[1] in ("audit", "open") for r in check(tmp))
    ap.write_text(saved)

    step(7, "Crash in the middle of a key rotation, then restart")
    svc.crash_at = "rotate_mid_commit"
    try:
        admin.rotate("payroll-2026", acl=["asha", "ravi"])
        print("   no crash happened")
        good = False
    except SimulatedCrash as c_:
        print(f"   process killed at: {c_}")
    svc2 = GuardService(tmp)
    print("   after restart, ravi reads:", Client(ravi.dev, svc2.handle).fetch("payroll-2026", auto_rotate=False).decode())
    kinds = [e["type"] for e in svc2.audit.entries if e["type"].startswith("file.rotat")]
    print("   rotation records in the audit log:", ", ".join(kinds[-3:]))
    ok3, why = svc2.audit.verify()
    print(f"   audit chain after recovery: {ok3} ({why})")
    good = good and ok3

    step(8, "Claim to evidence")
    rows = [
        ("Lost device is cut off at once", "step 3: validly signed request denied, no key released"),
        ("Revocation is visible and explained", "step 5: alert R1 with the two audit entries as evidence"),
        ("A changed stored ciphertext is detected", "step 6: the one altered ciphertext is refused on read and doctor FAILs"),
        ("An edited audit line is detected", "step 6: one edited line on disk makes doctor FAIL"),
        ("A crash does not lose or half-apply a rotation", "step 7: restart recovers, file readable, chain valid"),
    ]
    for claim, ev in rows:
        print(f"   {claim:<48} {ev}")
    return good


if __name__ == "__main__":
    sys.exit(main(story="--story" in sys.argv[1:]))
