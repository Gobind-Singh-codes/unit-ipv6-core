"""Verdict + observation model (PROJECT.md section 10, constraints.md section 13/27)."""
from __future__ import annotations

from dataclasses import dataclass, field

VALID_VERDICTS = ("PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE", "ERROR")
VALID_OBS = ("DIRECTLY_OBSERVED", "INFERRED", "UNKNOWN")


@dataclass
class Observation:
    kind: str  # DIRECTLY_OBSERVED | INFERRED | UNKNOWN
    detail: str

    def __post_init__(self) -> None:
        if self.kind not in VALID_OBS:
            raise ValueError(f"bad observation kind: {self.kind}")


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class
    test_id: str
    verdict: str
    observed: list[Observation] = field(default_factory=list)
    expected: str = ""
    deviation: str = ""
    evidence: dict = field(default_factory=dict)
    observability: str = "blackbox"  # blackbox | whitebox
    observability_reason: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(f"bad verdict: {self.verdict}")


def decide(pass_evidence: bool, fail_evidence: bool, fail_detail: str = "",
           precondition_missing: bool = False, not_applicable: bool = False,
           harness_error: str = "") -> TestResult:
    """No-false-PASS decision helper. Caller fills test_id/evidence after."""
    if harness_error:
        return TestResult(test_id="", verdict="ERROR", deviation=harness_error)
    if not_applicable:
        return TestResult(test_id="", verdict="NOT_APPLICABLE")
    if precondition_missing:
        return TestResult(test_id="", verdict="INCONCLUSIVE",
                          deviation="precondition cannot be established")
    if fail_evidence:
        return TestResult(test_id="", verdict="FAIL", deviation=fail_detail)
    if pass_evidence:
        return TestResult(test_id="", verdict="PASS")
    return TestResult(test_id="", verdict="INCONCLUSIVE",
                      deviation="evidence insufficient for PASS")
