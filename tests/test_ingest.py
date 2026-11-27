

def test_non_finite_timestamps_are_rejected():
    import pytest
    from kig import ingest
    for bad in ("nan", "inf", "-inf", 1e300, "1e20"):
        with pytest.raises(ingest.LineError):
            ingest.parse_ts(bad, "auto")
