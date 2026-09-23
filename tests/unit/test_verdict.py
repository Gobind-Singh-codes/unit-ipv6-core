import pytest

from common.verdict import Observation, TestResult, decide


def test_no_false_pass():
    r = decide(pass_evidence=False, fail_evidence=False)
    assert r.verdict == "INCONCLUSIVE"


def test_fail_beats_pass_priority():
    r = decide(pass_evidence=False, fail_evidence=True, fail_detail="got X")
    assert r.verdict == "FAIL" and r.deviation == "got X"


def test_error_never_becomes_fail():
    r = decide(pass_evidence=False, fail_evidence=True, harness_error="no iface")
    assert r.verdict == "ERROR"


def test_bad_verdict_rejected():
    with pytest.raises(ValueError):
        TestResult(test_id="X", verdict="MAYBE")


def test_observation_kinds():
    assert Observation("DIRECTLY_OBSERVED", "x").kind == "DIRECTLY_OBSERVED"
    with pytest.raises(ValueError):
        Observation("GUESSED", "x")
