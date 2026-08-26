"""Pure composite scoring invariants."""

from __future__ import annotations

from drishti.contracts.dynamic_trace import DynamicTrace, TraceSourceKind
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import MLPrediction, SeverityBand
from drishti.contracts.static_report import (
    CertificateInfo,
    PermissionCombo,
    Severity,
    StaticReport,
    ThreatIntel,
)
from drishti.m6_score.engine import rule_severity, score


def _static(*, drift: bool = False) -> StaticReport:
    return StaticReport(
        sha256="a" * 64,
        package="example",
        app_label="Example",
        version_name="1",
        version_code=1,
        min_sdk=26,
        target_sdk=35,
        certificate=CertificateInfo(
            sha256="0" * 64,
            subject="unknown",
            issuer="unknown",
            not_before="unknown",
            not_after="unknown",
            age_days=0,
            self_signed=False,
        ),
        used_not_declared=("android.permission.READ_SMS",) if drift else (),
        ledger_refs=("ev_static",),
    )


def _ml(*, probability: float = 0.7, anomaly: bool = False) -> MLPrediction:
    return MLPrediction(
        p_malicious_raw=probability,
        p_calibrated=probability,
        model_version="test",
        feature_schema_version="1",
        anomaly_escalate=anomaly,
        ledger_refs=("ev_ml",),
    )


def test_noisy_or_fusion() -> None:
    """Two partially-correlated detectors at 0.7 fuse to ~0.91, not 1.4 clipped to 1.0."""
    genai = GenAIVerdict(
        sha256="a" * 64,
        behavioural_risk_B=0.7,
        provider="groq",
        ledger_refs=("ev_ai",),
    )
    result = score(static=_static(), ml=_ml(), genai=genai, dynamic=None, intel=None)
    factor = next(item for item in result.factors if item.symbol == "F_AI")
    assert factor.raw == 0.91


def test_scorer_is_deterministic() -> None:
    """100 identical runs, 100 identical results.

    00_GUIDING_MAP.md §9.3 specifies this count explicitly. The scorer is the one
    component that must return the same answer for the same ledger every time — it is
    what makes "every score point traces to an artefact" checkable rather than a claim.
    Running it twice would pass even if a dict iteration order or a set had leaked in;
    100 runs is what makes an ordering bug actually surface.
    """
    genai = GenAIVerdict(
        sha256="a" * 64,
        behavioural_risk_B=0.7,
        provider="groq",
        ledger_refs=("ev_ai",),
    )
    baseline = score(static=_static(), ml=_ml(), genai=genai, dynamic=None, intel=None)
    for _ in range(100):
        assert score(static=_static(), ml=_ml(), genai=genai, dynamic=None, intel=None) == baseline


def test_scorer_uses_no_clock_and_no_randomness() -> None:
    """Purity, asserted against the source rather than trusted.

    M6 must do no I/O, call no LLM, and use no clock or randomness (CLAUDE.md rule 3).
    A drifting score would make the ledger attest something unreproducible.
    """
    import pathlib

    source = pathlib.Path("drishti/m6_score/engine.py").read_text()
    for forbidden in ("datetime.now", "time.time", "random.", "uuid", "requests", "open("):
        assert forbidden not in source, f"m6_score/engine.py must not use {forbidden}"


def test_known_bad_is_an_explicit_override() -> None:
    """Exact curated reputation forces the documented score override."""
    result = score(
        static=_static(),
        ml=_ml(probability=0.01),
        genai=None,
        dynamic=None,
        intel=ThreatIntel(sha256="a" * 64, known_bad_hash=True, verdict="confirmed_bad"),
    )
    assert (result.S, result.C, result.override_applied) == (100, 1.0, "known_bad_hash")


def test_clean_or_missing_reputation_cannot_reduce_ai_score() -> None:
    """No detections are absence of evidence, never benign evidence."""
    no_intel = score(static=_static(), ml=_ml(), genai=None, dynamic=None, intel=None)
    clean = score(
        static=_static(),
        ml=_ml(),
        genai=None,
        dynamic=None,
        intel=ThreatIntel(sha256="a" * 64, detections=0, total_engines=70, source="feed"),
    )
    assert clean.S == no_intel.S


def test_anomaly_escalates_band_without_changing_score() -> None:
    """Novelty is an escalator rather than an untraceable additive signal."""
    normal = score(static=_static(), ml=_ml(probability=0.1), genai=None, dynamic=None, intel=None)
    anomaly = score(
        static=_static(),
        ml=_ml(probability=0.1, anomaly=True),
        genai=None,
        dynamic=None,
        intel=None,
    )
    assert anomaly.S == normal.S
    # MEDIUM, not HIGH. HIGH is in the consumer surface's BLOCK bands, so escalating
    # there turned 'look at this' into 'do not install'. Measured on the shipped
    # model: 93 promotions with S unmoved, 84 of them BENIGN, while the detector's
    # own lift was negative (0.3560 malware vs 0.3983 benign).
    assert anomaly.band is SeverityBand.MEDIUM
    # This is the field that carries the escalator's actual intent.
    assert anomaly.requires_human_review


def test_static_drift_contributes_without_dynamic_data() -> None:
    """The static half of D works before the dynamic sandbox is available."""
    clean = score(static=_static(), ml=None, genai=None, dynamic=None, intel=None)
    drift = score(static=_static(drift=True), ml=None, genai=None, dynamic=None, intel=None)
    assert drift.S > clean.S


def test_limitations_follow_dynamic_provenance_flags() -> None:
    """A non-None placeholder trace must not make the final score claim live analysis."""
    unavailable = DynamicTrace(
        run_id="run_unavailable",
        source=TraceSourceKind.UNAVAILABLE,
        outcome="inconclusive",
        partial=True,
        synthetic=True,
    )
    result = score(static=_static(), ml=_ml(), genai=None, dynamic=unavailable, intel=None)
    assert "dynamic analysis unavailable" in result.limitations

    # …and says only that. The synthetic and containment lines describe a trace, so
    # emitting them for a placeholder tells a reader that something WAS executed and
    # then went wrong — "containment was not verified for the dynamic trace" reads as a
    # failed containment check on a real run, not as the absence of any run at all.
    # Nothing was executed here, so "unavailable" is the whole story.
    assert "dynamic trace is synthetic" not in result.limitations
    assert "containment was not verified for the dynamic trace" not in result.limitations
    # The property this test is named for: no claim of live or replayed analysis.
    assert not any("live" in item or "replayed" in item for item in result.limitations)


def test_replayed_trace_is_disclosed_even_when_captured_and_complete() -> None:
    replay = DynamicTrace(
        run_id="run_replay",
        source=TraceSourceKind.REPLAY,
        outcome="completed",
        containment_verified=True,
        synthetic=False,
    )
    result = score(static=_static(), ml=_ml(), genai=None, dynamic=replay, intel=None)
    assert "dynamic trace was replayed, not live" in result.limitations


def test_unavailable_placeholders_do_not_inflate_score_or_confidence() -> None:
    """Pipeline placeholders disclose absence and contribute no detector signal."""
    unavailable_ml = MLPrediction(
        p_malicious_raw=0.9,
        p_calibrated=0.9,
        model_version="none",
        feature_schema_version="1",
        partial=True,
    )
    mock_genai = GenAIVerdict(
        sha256="a" * 64,
        behavioural_risk_B=0.8,
        provider="mock",
    )
    unavailable_dynamic = DynamicTrace(
        run_id="run_unavailable",
        source=TraceSourceKind.UNAVAILABLE,
        outcome="inconclusive",
        detonated=True,
        synthetic=True,
        partial=True,
    )
    unavailable_intel = ThreatIntel(sha256="a" * 64, source="none")

    result = score(
        static=_static(),
        ml=unavailable_ml,
        genai=mock_genai,
        dynamic=unavailable_dynamic,
        intel=unavailable_intel,
    )

    assert result.S == 0
    assert result.gamma == 0.4
    assert result.C == 0.2
    assert "ML prediction unavailable" in result.limitations
    assert "behavioural analysis unavailable" in result.limitations


def test_partial_model_outputs_do_not_reach_fused_score() -> None:
    """A failed external analyser may return data, but partial data cannot score."""
    partial_ml = _ml(probability=0.9).model_copy(update={"partial": True})
    partial_genai = GenAIVerdict(
        sha256="a" * 64,
        behavioural_risk_B=0.8,
        provider="groq",
        partial=True,
    )

    result = score(
        static=_static(),
        ml=partial_ml,
        genai=partial_genai,
        dynamic=None,
        intel=None,
    )

    factor = next(item for item in result.factors if item.symbol == "F_AI")
    assert factor.raw == 0.0
    assert result.gamma == 0.4


# ── G: deterministic rule severity ───────────────────────────────────────────
# G had a declared 0.15 weight and NO caller ever supplied it, so it was permanently
# 0.0. With R absent (no intel) and D small, that capped a static-only triage at S=54 —
# HIGH (65) and CRITICAL (85) were unreachable however damning the manifest.
def _combo(rule_id: str, severity: Severity) -> PermissionCombo:
    return PermissionCombo(
        rule_id=rule_id,
        permissions=("android.permission.READ_SMS", "android.permission.INTERNET"),
        severity=severity,
        description="test rule",
    )


def test_rule_severity_is_zero_without_a_static_report() -> None:
    assert rule_severity(None) == 0.0


def test_rule_severity_is_zero_when_no_rule_fired() -> None:
    assert rule_severity(_static()) == 0.0


def test_the_worst_matched_rule_wins() -> None:
    """Volume must not outvote severity.

    Five MEDIUM combinations are not more damning than one CRITICAL one, so this is a
    max rather than a sum — otherwise a noisy manifest outranks a targeted one.
    """
    report = _static().model_copy(
        update={
            "permission_combos": (
                _combo("A", Severity.MEDIUM),
                _combo("B", Severity.CRITICAL),
                _combo("C", Severity.MEDIUM),
                _combo("D", Severity.MEDIUM),
            )
        }
    )
    assert rule_severity(report) == 1.0


def test_severity_ordering_is_monotonic() -> None:
    def sev(s: Severity) -> float:
        return rule_severity(_static().model_copy(update={"permission_combos": (_combo("X", s),)}))

    assert sev(Severity.CRITICAL) > sev(Severity.HIGH) > sev(Severity.MEDIUM) > sev(Severity.LOW)


def test_a_damning_manifest_can_now_reach_high_on_static_alone() -> None:
    """The defect this fixes, stated as the behaviour that was impossible before.

    With G dead, the best a static-only triage could do was 54 — MEDIUM — even with a
    CRITICAL permission combination and perfect behavioural risk.
    """
    report = _static(drift=True).model_copy(
        update={"permission_combos": (_combo("ACCESSIBILITY_ABUSE", Severity.CRITICAL),)}
    )
    genai = GenAIVerdict(sha256="a" * 64, provider="groq", behavioural_risk_B=1.0)

    without_g = score(static=report, ml=None, genai=genai, dynamic=None, intel=None)
    with_g = score(
        static=report,
        ml=None,
        genai=genai,
        dynamic=None,
        intel=None,
        yara_severity=rule_severity(report),
    )
    assert without_g.S == 54, "the old static-only ceiling"
    assert without_g.band is SeverityBand.MEDIUM
    assert with_g.S == 69
    assert with_g.band is SeverityBand.HIGH


def test_critical_still_requires_more_than_a_manifest() -> None:
    """A manifest alone must not reach CRITICAL.

    CRITICAL (85) should still demand intel, a trained model, or an actual detonation —
    otherwise every over-privileged app in the corpus becomes a five-alarm fire.
    """
    report = _static(drift=True).model_copy(
        update={"permission_combos": (_combo("X", Severity.CRITICAL),)}
    )
    genai = GenAIVerdict(sha256="a" * 64, provider="groq", behavioural_risk_B=1.0)
    result = score(
        static=report,
        ml=None,
        genai=genai,
        dynamic=None,
        intel=None,
        yara_severity=rule_severity(report),
    )
    assert result.band is not SeverityBand.CRITICAL


def test_the_scorer_stays_pure_with_g_wired() -> None:
    """Same inputs, same output, 50 times. G must not introduce state."""
    report = _static().model_copy(update={"permission_combos": (_combo("X", Severity.HIGH),)})
    calls = [
        score(
            static=report,
            ml=None,
            genai=None,
            dynamic=None,
            intel=None,
            yara_severity=rule_severity(report),
        ).S
        for _ in range(50)
    ]
    assert len(set(calls)) == 1


def test_the_escalator_never_reaches_a_blocking_band() -> None:
    """An anomaly score justifies a second look, never an accusation.

    `drishti.contracts.verdict` maps CRITICAL and HIGH to `BLOCK`, which the consumer
    screen renders as DO NOT INSTALL. The escalator must not be able to produce that on
    its own — its job is that a zero-day does not land quietly in LOW.
    """
    from drishti.contracts.verdict import _BLOCK_BANDS

    result = score(
        static=_static(),
        ml=_ml(probability=0.01, anomaly=True),
        genai=None,
        dynamic=None,
        intel=None,
    )
    assert result.band not in _BLOCK_BANDS
    assert result.requires_human_review


def test_the_escalator_cannot_demote() -> None:
    """It moves a verdict UP the ladder or leaves it alone. Never down.

    A sample already scoring HIGH on real evidence must not be pulled to MEDIUM just
    because the novelty detector also fired.
    """
    high = score(
        static=_static(drift=True).model_copy(
            update={"permission_combos": (_combo("X", Severity.CRITICAL),)}
        ),
        ml=_ml(probability=0.95, anomaly=True),
        genai=GenAIVerdict(sha256="a" * 64, provider="groq", behavioural_risk_B=1.0),
        dynamic=None,
        intel=None,
        yara_severity=1.0,
    )
    assert high.band in (SeverityBand.HIGH, SeverityBand.CRITICAL)
