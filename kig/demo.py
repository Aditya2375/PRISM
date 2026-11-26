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


def main() -> int:
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
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
