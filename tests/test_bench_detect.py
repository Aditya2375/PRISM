from kig import bench_detect as b


def test_bench_detect_reports_what_the_rules_do_and_do_not_catch():
    r = b.run(reps=1, benign_worlds=1, benign_cycles=20)
    assert r["false_alerts"]["benign_requests"] > 100
    assert r["false_alerts"]["alerts"] == 0
    caught = {s["scenario"]: s["detected"] for s in r["scenarios"]}
    built = {s["scenario"] for s in r["scenarios"] if s["built_to_be_caught"]}
    assert all(caught[n] == 1 for n in built)
    assert all(caught[n] == 0 for n in caught if n not in built)       # the misses are real and stay in the denominator
    assert r["true_positives"] == 9 and r["false_negatives"] == 2
    assert r["recall"] == round(9 / 11, 3) and r["precision"] == 1.0
    for s in r["scenarios"]:
        if s["detected"]:
            assert s["wall_ms"]["min"] <= s["wall_ms"]["median"] <= s["wall_ms"]["max"]
    assert next(s for s in r["scenarios"] if s["scenario"].startswith("lost device"))["service_clock_s"]["median"] == 0.0
    assert "not portable" in r["machine"]
