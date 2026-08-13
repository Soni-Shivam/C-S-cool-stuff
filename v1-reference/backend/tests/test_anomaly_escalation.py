"""The escalator must catch novel threats that every familiarity-based signal misses."""
from drishti.scoring.anomaly import collect_anomaly_signals, escalate


def _novel_dropper_signals():
    """A brand-new dropper: unknown to intel, no signature, dangerous capability."""
    return collect_anomaly_signals(
        reputation_verdict="unknown", reputation_detections=None,
        p_cal=0.55, behavioral_risk=0.60,
        signature_severity=0.0,
        static_mitre=["T1582"], observed_mitre=["T1582", "T1407", "T1426"],
        dynamic_status="observed", dynamic_outcome="completed",
        packed_or_obfuscated=True, dangerous_capability_count=3,
        evidence_refs=["n1", "n2"],
    )


def test_zero_day_cannot_land_quietly_in_low():
    """The core guarantee: a novel sample scoring Low must not stay Low."""
    signals = _novel_dropper_signals()
    assert signals, "novel dropper produced no anomaly signals"
    result = escalate(score=31, band="Low", signals=signals)
    assert result.escalated_band != "Low"
    assert result.escalated_score >= 40
    assert result.requires_human_review is True
    assert result.user_warning is not None


def test_escalation_states_novelty_not_confirmed_detection():
    """We must never imply a novel sample matched a known malicious family."""
    result = escalate(score=31, band="Low", signals=_novel_dropper_signals())
    joined = " ".join(result.rationale).lower()
    assert "novelty" in joined
    assert "not a confirmed detection" in joined
    assert "unverified rather than safe" in result.user_warning


def test_escalation_is_monotonic_and_never_downgrades():
    """A confirmed Critical verdict must never be reduced by the escalator."""
    result = escalate(score=92, band="Critical", signals=_novel_dropper_signals())
    assert result.escalated_score >= 92
    assert result.escalated_band == "Critical"


def test_clean_known_sample_is_not_escalated():
    """A well-understood, well-covered sample should produce no escalation."""
    signals = collect_anomaly_signals(
        reputation_verdict="confirmed_bad", reputation_detections=39,
        p_cal=0.95, behavioral_risk=0.92,
        signature_severity=0.8,
        static_mitre=["T1582", "T1417"], observed_mitre=["T1582"],
        dynamic_status="observed", dynamic_outcome="completed",
        packed_or_obfuscated=False, dangerous_capability_count=2,
    )
    result = escalate(score=88, band="Critical", signals=signals)
    assert signals == []
    assert result.requires_human_review is False
    assert result.escalated is False
    assert result.user_warning is None


def test_absence_of_detections_is_not_treated_as_benign():
    """Zero engine detections must still raise novelty when capability is dangerous."""
    signals = collect_anomaly_signals(
        reputation_verdict="unknown", reputation_detections=0,
        p_cal=0.30, behavioral_risk=0.20,
        signature_severity=0.0,
        static_mitre=[], observed_mitre=[],
        dynamic_status="absent", dangerous_capability_count=2,
    )
    ids = {s.signal_id for s in signals}
    assert "unknown_hash_with_dangerous_capability" in ids


def test_stalling_under_instrumentation_is_inconclusive_not_benign():
    signals = collect_anomaly_signals(
        reputation_verdict="unknown", reputation_detections=None,
        p_cal=0.4, behavioral_risk=0.3, signature_severity=0.0,
        static_mitre=["T1582"], observed_mitre=[],
        dynamic_status="observed", dynamic_outcome="inconclusive",
        dangerous_capability_count=1,
    )
    assert "no_behaviour_under_instrumentation" in {s.signal_id for s in signals}


def test_unmodelled_runtime_behaviour_is_flagged():
    """Runtime techniques static analysis never predicted indicate a delivered payload."""
    signals = collect_anomaly_signals(
        reputation_verdict="confirmed_bad", reputation_detections=30,
        p_cal=0.9, behavioral_risk=0.9, signature_severity=0.8,
        static_mitre=["T1582"], observed_mitre=["T1582", "T1407"],
        dynamic_status="observed", dynamic_outcome="completed",
        dangerous_capability_count=2,
    )
    ids = {s.signal_id for s in signals}
    assert "unmodelled_runtime_behaviour" in ids


def test_anomaly_score_is_subadditive_and_capped():
    """Many weak signals must not manufacture certainty."""
    signals = _novel_dropper_signals()
    result = escalate(score=10, band="Low", signals=signals)
    assert 0.0 < result.anomaly_score <= 1.0
    # Sub-additive: strictly less than the raw sum of weights.
    assert result.anomaly_score < sum(s.weight for s in signals)
