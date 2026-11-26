"""Tests for the anomaly detector."""

import pytest
from kig.detector import Alert, AnomalyDetector


def test_access_outside_hours():
    """Rule (a): access outside configured hours raises alert."""
    detector = AnomalyDetector(access_hour_cutoff=23)  # cutoff at 23:00

    # Event at hour 22 (before cutoff) - should not trigger
    alerts = detector.observe({
        "ts": "2024-01-01T22:00:00Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })
    assert len(alerts) == 0, f"Expected no alerts for hour 22, got {alerts}"

    # Event at hour 23 (at cutoff) - should trigger
    alerts = detector.observe({
        "ts": "2024-01-01T23:00:00Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })
    assert len(alerts) == 1, f"Expected 1 alert for hour 23, got {alerts}"
    assert alerts[0].rule == "access_outside_hours"

    # Event at hour 0 (midnight, also outside when cutoff >= 23) - should trigger
    # With cutoff=23, hour 0 is also considered outside
    alerts = detector.observe({
        "ts": "2024-01-02T00:00:00Z",
        "actor": "bob",
        "action": "key_fetch",
        "key_id": "key2",
        "result": "success",
    })
    assert len(alerts) == 1, f"Expected 1 alert for hour 0 with cutoff=23, got {alerts}"


def test_N_failed_fetches():
    """Rule (b): N failed fetches by one actor within W seconds raises alert."""
    detector = AnomalyDetector(
        failed_fetch_threshold=3,
        window_seconds=10,
    )

    # First two failed fetches - no alert
    alerts = detector.observe({
        "ts": "2024-01-01T00:00:00Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "failure",
    })
    assert len(alerts) == 0, f"Expected no alerts after 1st failed fetch, got {alerts}"

    alerts = detector.observe({
        "ts": "2024-01-01T00:00:01Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "failure",
    })
    assert len(alerts) == 0, f"Expected no alerts after 2nd failed fetch, got {alerts}"

    # Third failed fetch within window - should trigger
    alerts = detector.observe({
        "ts": "2024-01-01T00:00:02Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "failure",
    })
    assert len(alerts) == 1, f"Expected 1 alert after 3rd failed fetch, got {alerts}"
    assert alerts[0].rule == "N_failed_fetches"

    # Fourth failed fetch - should also trigger (count is now 4 >= 3)
    alerts = detector.observe({
        "ts": "2024-01-01T00:00:03Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "failure",
    })
    assert len(alerts) == 1, f"Expected 1 alert after 4th failed fetch, got {alerts}"


def test_burst_fetches():
    """Rule (c): burst of M fetches within W seconds raises alert."""
    detector = AnomalyDetector(
        burst_threshold=5,
        window_seconds=10,
    )

    # First 4 fetches - no alert (use proper ISO timestamps with two-digit seconds)
    for i in range(4):
        alerts = detector.observe({
            "ts": f"2024-01-01T00:00:{i*2:02d}Z",  # 0, 2, 4, 6 seconds
            "actor": "alice",
            "action": "key_fetch",
            "key_id": "key1",
            "result": "success",
        })
        assert len(alerts) == 0, f"Expected no alerts after {i+1}th fetch, got {alerts}"

    # 5th fetch - should trigger burst alert (at 08 seconds, within 10s window)
    alerts = detector.observe({
        "ts": "2024-01-01T00:00:08Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })
    assert len(alerts) == 1, f"Expected 1 alert after 5th fetch, got {alerts}"
    assert alerts[0].rule == "burst_fetches"


def test_benign_traffic_raises_zero_alerts():
    """Test that normal, non-anomalous traffic raises zero alerts."""
    detector = AnomalyDetector(
        access_hour_cutoff=23,
        failed_fetch_threshold=5,
        burst_threshold=10,
        window_seconds=60,
    )

    # Normal business hours access (9am-5pm)
    for hour in [9, 10, 11, 12, 14, 15, 16]:
        alerts = detector.observe({
            "ts": f"2024-01-01T{hour:02d}:00:00Z",
            "actor": "alice",
            "action": "key_fetch",
            "key_id": "key1",
            "result": "success",
        })
        assert len(alerts) == 0, f"Expected no alerts for hour {hour}, got {alerts}"

    # Some failed fetches but below threshold
    for i in range(4):
        alerts = detector.observe({
            "ts": "2024-01-01T10:00:00Z",
            "actor": "alice",
            "action": "key_fetch",
            "key_id": "key1",
            "result": "failure",
        })
        assert len(alerts) == 0, f"Expected no alerts after {i+1}th failed fetch, got {alerts}"

    # Some fetches but below burst threshold
    for i in range(9):
        alerts = detector.observe({
            "ts": f"2024-01-01T10:00:{i*2:02d}Z",  # 00, 02, 04, 06, 08, 10, 12, 14, 16 seconds
            "actor": "bob",
            "action": "key_fetch",
            "key_id": "key2",
            "result": "success",
        })
        assert len(alerts) == 0, f"Expected no alerts after {i+1}th fetch, got {alerts}"


def test_metrics():
    """Test detector.metrics() returns correct information."""
    detector = AnomalyDetector(access_hour_cutoff=23, failed_fetch_threshold=3, burst_threshold=5, window_seconds=10)

    # Observe 3 events at hour 23 - all should trigger access_outside_hours
    detector.observe({
        "ts": "2024-01-01T23:00:00Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })
    detector.observe({
        "ts": "2024-01-01T23:00:01Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })
    detector.observe({
        "ts": "2024-01-01T23:00:02Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })

    m = detector.metrics()
    assert m["total_events"] == 3
    # All 3 events at hour 23 with cutoff=23 trigger the rule
    assert m["alerts_per_rule"]["access_outside_hours"] == 3
    assert m["alerts_per_actor"]["alice"] == 3
    assert m["num_actors_tracked"] >= 1


def test_reset():
    """Test detector.reset() clears all state."""
    detector = AnomalyDetector(access_hour_cutoff=23)

    # Add some state
    detector.observe({
        "ts": "2024-01-01T23:00:00Z",
        "actor": "alice",
        "action": "key_fetch",
        "key_id": "key1",
        "result": "success",
    })

    assert detector.metrics()["total_events"] == 1

    detector.reset()

    assert detector.metrics()["total_events"] == 0
    assert detector.metrics()["alerts_per_rule"] == {}
    assert detector.metrics()["alerts_per_actor"] == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])