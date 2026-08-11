import pytest

mlflow = pytest.importorskip("mlflow")

from drishti.evaluation.scorers import (  # noqa: E402
    benign_false_alarm_behavior,
    citation_validity,
    mitre_correctness,
    unsupported_high_impact_claims,
)


def _input(status="absent"):
    return {"evidence": {"evidence_node_ids": ["n1"], "permission_combos": [{"mitre": ["T1582"]}], "dynamic_evidence": {"status": status}}}


def test_deterministic_scorers_require_no_llm_calls():
    valid = {"summary": "The permissions could expose messages.", "behavioral_risk": .2, "attack_techniques": ["T1582"], "evidence_refs": ["n1"]}
    assert citation_validity.run(inputs=_input(), outputs=valid).value is True
    assert mitre_correctness.run(inputs=_input(), outputs=valid).value is True
    assert unsupported_high_impact_claims.run(inputs=_input(), outputs=valid).value is True


def test_high_impact_and_benign_false_alarm_fail_closed():
    bad = {"summary": "The app stole every OTP", "behavioral_risk": .9, "attack_techniques": [], "evidence_refs": ["n1"]}
    assert unsupported_high_impact_claims.run(inputs=_input(), outputs=bad).value is False
    assert benign_false_alarm_behavior.run(inputs=_input(), outputs=bad, expectations={"benign": True}).value is False
