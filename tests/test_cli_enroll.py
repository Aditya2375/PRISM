import json
import pytest
from kig import cli
from kig.client import Device


def _setup(w, tmp_path, monkeypatch):
    new = Device.generate("a-77", "alice")
    pub = tmp_path / "new.json"; pub.write_text(json.dumps(new.public_args()))
    adm = tmp_path / "admin.json"; w.admin.dev.save(adm)
    monkeypatch.setattr(cli, "_post", lambda url: w.svc.handle)
    from kig.client import Client
    monkeypatch.setattr(cli, "Client", lambda dev, tr, **kw: Client(dev, tr, w.clock, **kw))
    return new, pub, adm


def test_enroll_with_fingerprint(w, tmp_path, monkeypatch, capsys):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    fp = new.fingerprint().replace("-", " ").upper()      # typed by a person
    assert cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub), "--expect-fingerprint", fp]) == 0
    assert "UNVERIFIED" not in capsys.readouterr().out and "a-77" in w.svc.state["devices"]


def test_enroll_wrong_fingerprint_refused(w, tmp_path, monkeypatch):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    assert cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub), "--expect-fingerprint", "00" * 32]) == 2
    assert "a-77" not in w.svc.state["devices"]


def test_enroll_requires_a_choice(w, tmp_path, monkeypatch):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    with pytest.raises(SystemExit):
        cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub)])


def test_enroll_unverified_is_marked(w, tmp_path, monkeypatch, capsys):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    assert cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub), "--unverified"]) == 0
    assert "UNVERIFIED" in capsys.readouterr().out


def test_empty_fingerprint_refused(w, tmp_path, monkeypatch):
    new, pub, adm = _setup(w, tmp_path, monkeypatch)
    assert cli.main(["enroll", "--url", "x", "--key", str(adm), "--pub", str(pub), "--expect-fingerprint", ""]) == 2
    assert "a-77" not in w.svc.state["devices"]
