"""Pure, deterministic composite scoring.

This module intentionally performs no I/O. Persisting the returned factors as ledger
nodes belongs to the pipeline adapter, never to the score calculation itself.
"""

from __future__ import annotations

from typing import Literal, cast

from drishti.contracts.dynamic_trace import DynamicTrace, TraceSourceKind
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import (
    CompositeScore,
    MLPrediction,
    ProposedAction,
    ScoreFactor,
    SeverityBand,
)
from drishti.contracts.static_report import StaticReport, ThreatIntel


def score(
    *,
    static: StaticReport | None,
    ml: MLPrediction | None,
    genai: GenAIVerdict | None,
    dynamic: DynamicTrace | None,
    intel: ThreatIntel | None,
    yara_severity: float = 0.0,
) -> CompositeScore:
    """Fuse available evidence using the pinned formula without side effects."""
    has_ml = bool(ml and ml.model_version not in {"none", "stub"} and not ml.partial)
    has_behavioural = bool(genai and genai.provider != "mock" and not genai.partial)
    has_dynamic = bool(
        dynamic
        and dynamic.detonated
        and dynamic.source is not TraceSourceKind.UNAVAILABLE
        and not dynamic.synthetic
    )
    has_intel = bool(intel and intel.source not in {"none", "unavailable"} and not intel.partial)
    probability = ml.p_calibrated if ml and has_ml else None
    behavioural = genai.behavioural_risk_B if genai and has_behavioural else None
    fused = _noisy_or(probability, behavioural)
    reputation = 1.0 if intel and intel.known_bad_hash else 0.0
    drift = _drift(static, dynamic)
    factors = (
        _factor(
            "R",
            "Reputation",
            reputation,
            0.25,
            {"known_bad_hash": bool(intel and intel.known_bad_hash)},
            _refs(intel),
        ),
        _factor(
            "F_AI",
            "Fused AI intelligence",
            fused,
            0.50,
            {"p_calibrated": probability, "behavioural_risk_B": behavioural},
            _refs(ml, genai),
        ),
        _factor(
            "G",
            "Signature severity",
            _clamp(yara_severity),
            0.15,
            {"yara_severity": yara_severity},
            (),
        ),
        _factor(
            "D",
            "Static-dynamic drift",
            drift,
            0.10,
            {
                "static_drift": bool(static and static.used_not_declared),
                "runtime_dex_load": bool(
                    dynamic and any(not item.in_original_apk for item in dynamic.dex_loads)
                ),
            },
            _refs(static, dynamic),
        ),
    )
    raw_score = sum(factor.contribution for factor in factors)
    value = round(100 * min(1.0, raw_score))
    gamma = 0.4 * bool(static) + 0.3 * has_dynamic + 0.2 * has_ml + 0.1 * has_intel
    confidence = (
        gamma * (1 - abs(probability - behavioural))
        if probability is not None and behavioural is not None
        else gamma * 0.5
    )
    disagreement = bool(genai and genai.disagreement_flag)
    if disagreement:
        confidence *= 0.6
    if intel and intel.known_bad_hash:
        value, confidence, override = 100, 1.0, "known_bad_hash"
    else:
        override = None
    band = _band(value)
    anomaly = bool(ml and has_ml and ml.anomaly_escalate)
    if anomaly and band is SeverityBand.LOW:
        band = SeverityBand.HIGH
    review = anomaly or disagreement or confidence < 0.5
    limitations = _limitations(static=static, ml=ml, genai=genai, dynamic=dynamic)
    return CompositeScore(
        S=value,
        band=band,
        C=round(confidence, 6),
        gamma=round(gamma, 6),
        factors=factors,
        override_applied=override,
        requires_human_review=review,
        anomaly_escalated=anomaly,
        actions_proposed=_actions(band),
        explanation=f"Score {value} ({band.value}); fused AI signal contributes {fused:.2f}.",
        limitations=limitations,
        ledger_refs=tuple(ref for factor in factors for ref in factor.evidence_refs),
    )


def _noisy_or(probability: float | None, behavioural: float | None) -> float:
    if probability is None:
        return _clamp(behavioural or 0.0)
    if behavioural is None:
        return _clamp(probability)
    return round(_clamp(probability + behavioural - probability * behavioural), 6)


def _limitations(
    *,
    static: StaticReport | None,
    ml: MLPrediction | None,
    genai: GenAIVerdict | None,
    dynamic: DynamicTrace | None,
) -> tuple[str, ...]:
    """Derive disclosures from result provenance, never from presentation config."""
    items: list[str] = []
    if static is None:
        items.append("static analysis unavailable")
    elif static.partial:
        items.append("static analysis is partial")

    if ml is None or ml.model_version in {"none", "stub"}:
        items.append("ML prediction unavailable")
    elif ml.partial:
        items.append("ML prediction is partial")

    if genai is None or genai.provider == "mock":
        items.append("behavioural analysis unavailable")
    elif genai.partial:
        items.append("behavioural analysis is partial")

    if dynamic is None or dynamic.source is TraceSourceKind.UNAVAILABLE:
        items.append("dynamic analysis unavailable")
    else:
        if dynamic.source is TraceSourceKind.REPLAY:
            items.append("dynamic trace was replayed, not live")
        if dynamic.partial:
            items.append("dynamic analysis is partial")
    if dynamic is not None:
        if dynamic.synthetic:
            items.append("dynamic trace is synthetic")
        if not dynamic.containment_verified:
            items.append("containment was not verified for the dynamic trace")
    return tuple(dict.fromkeys(items))


def _drift(static: StaticReport | None, dynamic: DynamicTrace | None) -> float:
    static_drift = 0.4 if static and static.used_not_declared else 0.0
    runtime_dex = (
        0.2 if dynamic and any(not event.in_original_apk for event in dynamic.dex_loads) else 0.0
    )
    return static_drift + runtime_dex


def _factor(
    symbol: Literal["R", "F_AI", "G", "D"],
    label: str,
    raw: float,
    weight: float,
    inputs: dict,
    refs: tuple[str, ...],
) -> ScoreFactor:
    return ScoreFactor(
        symbol=symbol,
        label=label,
        raw=raw,
        weight=weight,
        contribution=raw * weight,
        inputs=inputs,
        evidence_refs=refs,
    )


def _refs(*items: object | None) -> tuple[str, ...]:
    return tuple(
        ref for item in items if item is not None for ref in getattr(item, "ledger_refs", ())
    )


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _band(value: int) -> SeverityBand:
    if value >= 85:
        return SeverityBand.CRITICAL
    if value >= 65:
        return SeverityBand.HIGH
    if value >= 40:
        return SeverityBand.MEDIUM
    return SeverityBand.LOW


def _actions(band: SeverityBand) -> tuple[ProposedAction, ...]:
    actions = {
        SeverityBand.CRITICAL: ("block", "push_ioc", "notify_customers"),
        SeverityBand.HIGH: ("quarantine", "fast_track_analyst"),
        SeverityBand.MEDIUM: ("analyst_review", "monitor"),
        SeverityBand.LOW: ("log",),
    }[band]
    return tuple(
        ProposedAction(
            action=cast(
                Literal[
                    "block",
                    "quarantine",
                    "notify_customers",
                    "push_ioc",
                    "fast_track_analyst",
                    "analyst_review",
                    "monitor",
                    "log",
                ],
                action,
            ),
            rationale=f"Score band is {band.value}.",
        )
        for action in actions
    )
