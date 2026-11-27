"""A bad numeric setting falls back to its default and says so; it never crashes startup."""
import sys

import pytest

from kig.envcfg import env_num


@pytest.mark.parametrize("bad", ["abc", "", "-5", "0", "1e999", "nan", "12x"])
def test_bad_value_uses_default_and_warns(monkeypatch, capsys, bad):
    monkeypatch.setenv("X_SETTING", bad)
    assert env_num("X_SETTING", 7) == 7
    err = capsys.readouterr().err
    if bad.strip():
        assert "X_SETTING" in err and bad not in err or bad == "0"      # names the setting, does not echo the value


def test_good_value_and_float_and_max(monkeypatch):
    monkeypatch.setenv("X_SETTING", "42")
    assert env_num("X_SETTING", 7) == 42
    monkeypatch.setenv("X_SETTING", "2.5")
    assert env_num("X_SETTING", 1.0, 0.1, 10, float) == 2.5
    monkeypatch.setenv("X_SETTING", "99")
    assert env_num("X_SETTING", 7, 1, 50) == 7


def test_hosted_proxy_and_service_import_with_garbage_settings():
    """In a subprocess, so the module objects other tests hold are not replaced."""
    import os
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=root)
    for name in ("HOSTED_MAX_BODY", "HOSTED_RATE", "HOSTED_WINDOW_S", "HOSTED_GLOBAL_RATE", "KIG_MAX_DELETED_IDS"):
        env[name] = "not-a-number"
    code = ("import hosted.proxy as p, kig.service as s;"
            "assert p.RATE == 120 and p.MAX_BODY == 65536 and s.MAX_USER_TOMBS == 2000; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=root)
    assert r.returncode == 0 and "ok" in r.stdout, r.stderr
    assert "HOSTED_RATE" in r.stderr and "not-a-number" not in r.stderr
