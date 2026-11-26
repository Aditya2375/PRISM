import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from kig.api import create_app

ORIGIN = "http://localhost:5173"


def test_cors_is_off_by_default(tmp_path):
    tc = TestClient(create_app(tmp_path / "d"))
    r = tc.get("/healthz", headers={"Origin": ORIGIN})
    assert "access-control-allow-origin" not in r.headers
    r = tc.options("/v1/overview", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "GET",
                                           "Access-Control-Request-Headers": "x-kig-operator-token"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_allows_only_the_listed_origin_and_never_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("KIG_CORS_ORIGINS", ORIGIN)
    tc = TestClient(create_app(tmp_path / "d"))
    ok = tc.get("/healthz", headers={"Origin": ORIGIN})
    assert ok.headers["access-control-allow-origin"] == ORIGIN
    assert "access-control-allow-credentials" not in ok.headers
    other = tc.get("/healthz", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in other.headers
    pre = tc.options("/v1/overview", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "GET",
                                             "Access-Control-Request-Headers": "x-kig-operator-token"})
    assert pre.status_code == 200 and "x-kig-operator-token" in pre.headers["access-control-allow-headers"].lower()
    # CORS never replaces the token: an allowed origin without it is still refused
    assert tc.get("/v1/overview", headers={"Origin": ORIGIN}).status_code == 401


@pytest.mark.parametrize("bad", ["*", "http://*.example.com", "localhost:5173", "file://x"])
def test_wildcards_and_malformed_origins_refuse_to_start(tmp_path, bad):
    with pytest.raises(ValueError):
        create_app(tmp_path / "d", cors_origins=[bad])


def test_demo_json_is_the_three_node_scene_as_data():
    out = subprocess.run([sys.executable, "-m", "kig.demo", "--json"], capture_output=True, text=True, check=True).stdout
    d = json.loads(out)
    assert d["simulated"] is True and d["lease_s"] == 5.0
    assert [n["node"] for n in d["nodes"]] == ["node-a", "node-b", "node-c"]
    assert all(isinstance(n["ms"], float) for n in d["nodes"])
    assert d["partition"]["after_lease"] == "node_stale"
