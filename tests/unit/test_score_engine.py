"""Pure composite scoring invariants."""

from __future__ import annotations

from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import MLPrediction, SeverityBand
from drishti.contracts.static_report import CertificateInfo, StaticReport, ThreatIntel
from drishti.m6_score.engine import score


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


def test_noisy_or_and_determinism() -> None:
    """Identical evidence always produces identical score and noisy-OR fusion."""
    genai = GenAIVerdict(sha256="a" * 64, behavioural_risk_B=0.7, ledger_refs=("ev_ai",))
    first = score(static=_static(), ml=_ml(), genai=genai, dynamic=None, intel=None)
    assert first == score(static=_static(), ml=_ml(), genai=genai, dynamic=None, intel=None)
    factor = next(item for item in first.factors if item.symbol == "F_AI")
    assert factor.raw == 0.91


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
    assert anomaly.band is SeverityBand.HIGH
    assert anomaly.requires_human_review


def test_static_drift_contributes_without_dynamic_data() -> None:
    """The static half of D works before the dynamic sandbox is available."""
    clean = score(static=_static(), ml=None, genai=None, dynamic=None, intel=None)
    drift = score(static=_static(drift=True), ml=None, genai=None, dynamic=None, intel=None)
    assert drift.S > clean.S
