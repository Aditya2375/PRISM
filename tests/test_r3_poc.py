import json, os, pytest
from kig import crypto as c, backup
from kig.client import Device
from kig.service import Denied, GuardService, SimulatedCrash
from conftest import World, Clock

def _junk(w, dev, src):
    env = w.bob.envelope("whoami"); env["device"] = dev
    try: w.svc.handle(env, source=src)
    except Denied: pass

def test_H1_junk_from_same_source_suppresses_replay_log(w):
    env = w.bob.envelope("whoami")
    w.svc.handle(env, source="1.1.1.1")               # original
    for i in range(3): _junk(w, f"g{i}", "2.2.2.2")   # attacker burns per-source quota (shared key anon|src)
    n0 = len(w.svc.audit.entries)
    with pytest.raises(Denied): w.svc.handle(env, source="2.2.2.2")   # replay from other source
    assert "auth.replay" in [e["type"] for e in w.svc.audit.entries[n0:]], "replay not logged: quota shared with pre-auth junk"

def test_H2_bad_hops_env_is_not_500(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from kig.api import create_app
    monkeypatch.setenv("KIG_PROXY_HOPS", "two")
    with pytest.raises(ValueError):      # misconfiguration fails at start-up, not per request
        create_app(tmp_path/"d", trust_proxy=True)

def test_H4_snapshot_after_primary_restore_is_accepted_by_replica(tmp_path):
    clock = Clock(); p = GuardService(tmp_path/"p", clock=clock); clock.tick(1)
    a = Device.generate("a-1","a"); p.bootstrap("a","a-1",a.sign_pub,a.kem_pub)
    rep = GuardService(tmp_path/"r", clock=clock, name="r", read_only=True)
    from kig.client import Client
    ad = Client(a, p.handle, clock)
    bp, bs = c.kem_keygen(); out = tmp_path/"b.bak"; backup.create(p, bp, out)
    for i in range(5): ad.call("create_user", user=f"u{i}")
    rep.install_snapshot(p.export_snapshot(), p.pub)
    backup.restore(out, tmp_path/"p2", bp, bs, p.dir/"server_sign.pub", p.dir/"server_sign.key", accept_rollback=True)
    p2 = GuardService(tmp_path/"p2", clock=clock)
    assert rep.install_snapshot(p2.export_snapshot(), p2.pub) is True   # replica must converge to restored primary

def test_H5_valid_traffic_unaffected_by_shared_source_junk(w):
    for i in range(1500): _junk(w, f"g{i}", "192.0.2.1")
    w.clock.tick(1)
    assert w.svc.handle(w.bob.envelope("whoami"), source="192.0.2.1")["user"] == "bob"
