from kig import demo


def test_story_runs_and_every_check_holds(capsys):
    assert demo.main(story=True) == 0
    cap = capsys.readouterr(); out = cap.out
    assert "Traceback" not in cap.err
    assert "[9] Claim to evidence" in out and "storage_corrupt" in out and "rotate_recovered" in out
