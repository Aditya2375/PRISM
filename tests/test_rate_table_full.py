"""When the rate table is full, new keys are still limited (in one shared bucket), not waved through."""
from kig import service as S
from kig.service import GuardService
from conftest import Clock


def test_full_table_does_not_switch_the_limit_off(tmp_path, monkeypatch):
    svc = GuardService(tmp_path / "d", clock=Clock())
    monkeypatch.setattr(GuardService, "RATE_TABLE_MAX", 50)
    now = 1_800_000_000.0
    for i in range(50):
        assert svc._rate_hit(f"dev:d{i}", 5, now) is False
    assert len(svc._rate) == 50
    hits = [svc._rate_hit(f"dev:new{i}", 5, now) for i in range(5 * GuardService.OVERFLOW_FACTOR + 10)]
    assert not any(hits[: 5 * GuardService.OVERFLOW_FACTOR])
    assert all(hits[5 * GuardService.OVERFLOW_FACTOR:])           # the shared bucket is exhausted: limited
    assert len(svc._rate) <= 51                                   # still bounded: one extra overflow key
    assert svc._rate_hit("dev:d3", 5, now) is False               # a tracked key keeps its own count


def test_table_resets_next_minute(tmp_path, monkeypatch):
    svc = GuardService(tmp_path / "d", clock=Clock())
    monkeypatch.setattr(GuardService, "RATE_TABLE_MAX", 10)
    now = 1_800_000_000.0
    for i in range(30):
        svc._rate_hit(f"dev:d{i}", 5, now)
    assert len(svc._rate) == 11                                   # 10 tracked keys + the shared overflow bucket
    svc._roll(now + 61)
    assert len(svc._rate) == 0
    assert svc._rate_hit("dev:x", 1, now + 61) is False and svc._rate_hit("dev:x", 1, now + 61) is True
