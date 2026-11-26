import json
from kig.service import Denied
from test_webapi import world, web, H

def test_V3_thief_chosen_cmd_string_is_bounded_in_activity(tmp_path):
    svc, clock, tr, a, r, phone, adm, rav, pdev = world(tmp_path)
    a.call("report_lost", device="asha-phone", reason="stolen")
    evil = "<img src=x onerror=alert(1)>" + "A" * 200000
    try: phone.call(evil)
    except Exception as e: print("thief got", type(e).__name__, str(e)[:80])
    try: phone.call("whoami")
    except Exception as e: pass
    ents = web(a).get("/activity?limit=5", headers=H).json()["entries"]
    blob = json.dumps(ents)
    print(len(blob), [e["type"] for e in ents])
    assert len(blob) < 5000, len(blob)
    assert "<" not in blob

def test_V4_member_view_has_no_other_user_ids(tmp_path):
    svc, clock, tr, a, r, phone, adm, rav, pdev = world(tmp_path)
    a.put_file("asha-only", b"x", acl=["ravi"])
    r.fetch("asha-only")
    for _ in range(3):
        try: r.fetch("nope")
        except Exception: pass
    ents = web(r).get("/activity?limit=100", headers=H).json()["entries"]
    print(json.dumps(ents))
    assert "asha" not in json.dumps(ents).replace("asha-only", ""), [e for e in ents if "asha" in json.dumps(e)]
