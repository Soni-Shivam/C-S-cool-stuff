"""Pure, deterministic composite scoring.

This module intentionally performs no I/O. Persisting the returned factors as ledger
nodes belongs to the pipeline adapter, never to the score calculation itself.
"""

from __future__ import annotations

import math
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

#: Severity of a matched deterministic rule, on the 0-1 scale `G` expects.
#: The worst match wins rather than the sum: five MEDIUM combos are not more damning
#: than one CRITICAL one, and summing would let volume outvote severity.
_RULE_SEVERITY: dict[str, float] = {
    "critical": 1.0,
    "high": 0.70,
    "medium": 0.40,
    "low": 0.15,
}


def rule_severity(static: StaticReport | None) -> float:
    """The severity of the worst deterministic rule that fired, for the `G` term.

    `G` is documented as "signature severity" and was specified around YARA family
    rules — which do not exist yet, so **no caller ever supplied it and G was
    permanently 0.0**, contributing nothing of its 0.15 weight. The consequence was
    structural rather than cosmetic: with R absent (no intel), G dead and D small, a
    static-only triage could not exceed **S=54** no matter how damning the manifest,
    so HIGH (65) and CRITICAL (85) were unreachable without ML or a detonation. An APK
    declaring an OTP-theft surface, an overlay-credential-theft surface, accessibility
    abuse at CRITICAL and dropper capability capped at MEDIUM.

    Permission combinations are the same category of evidence as a YARA hit: a
    deterministic, human-written rule matched, with a severity attached and no model in
    the path. `PHASE_1` and the paper's §4.2.1 both describe these combinations as
    primary features. So they feed `G`.

    Pure: no I/O, no clock, no randomness — the scorer's guarantee is unaffected, and
    this is a plain function of the report it is handed.
    """
    if static is None or not static.permission_combos:
        return 0.0
    return max(
        _RULE_SEVERITY.get(
            combo.severity.value if hasattr(combo.severity, "value") else str(combo.severity),
            0.0,
        )
        for combo in static.permission_combos
    )


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
    evidence = genai.behavioural_evidence if genai and has_behavioural else None
    fused = _fuse(probability, evidence=evidence, behavioural=behavioural)
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
            {
                "p_calibrated": probability,
                "behavioural_risk_B": behavioural,
                # Shown beside B so a reader can see which DIRECTION the behavioural
                # layer pushed, which the [0,1] display value cannot express.
                "behavioural_evidence": evidence,
            },
            _refs(ml, genai),
        ),
        _factor(
            "G",
            "Deterministic rule severity",
            _clamp(yara_severity),
            0.15,
            {"rule_severity": yara_severity},
            _refs(static),
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
        # LOW -> MEDIUM, deliberately NOT LOW -> HIGH.
        #
        # The escalator's job, in the paper's own words, is that "zero-days cannot land
        # quietly in LOW" — it forces a human to look. It is not a claim of malice, and
        # `requires_human_review` below is what actually carries that intent.
        #
        # Promoting to HIGH made it one: HIGH is in `_BLOCK_BANDS`, so the consumer
        # screen rendered "DO NOT INSTALL". Measured on the shipped model: 93 LOW rows
        # promoted WITHOUT `S` moving a single point, and **84 of them benign**. On the
        # same run the detector's lift was negative — anomaly 0.3560 for malware against
        # 0.3983 for benign — so it was ranking clean apps as the more unusual ones and
        # then blocking them.
        #
        # MEDIUM maps to REVIEW rather than BLOCK, which is what an anomaly score
        # actually justifies: a second look, not an accusation.
        band = SeverityBand.MEDIUM
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


#: Keeps `logit` finite at the edges. The calibrator emits exact 0.0 and 1.0 — its
#: isotonic fit has flat regions at both ends — and `log(0)` would make the whole score
#: NaN rather than merely wrong.
_EPS = 1e-6


def _logit(p: float) -> float:
    p = min(max(p, _EPS), 1.0 - _EPS)
    return math.log(p / (1.0 - p))


def _sigmoid(z: float) -> float:
    # Branch on the sign to avoid overflow in exp() for large |z|; both branches are the
    # same function, and the scorer must not raise on an extreme weight sum.
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _fuse(
    probability: float | None,
    *,
    evidence: float | None,
    behavioural: float | None = None,
) -> float:
    """Combine the classifier probability with the behavioural evidence, in log-odds.

        logit(F_AI) = logit(P_cal) + evidence

    **Why this replaced noisy-OR.** `P + B - P·B` is monotone increasing in `B` over
    `B >= 0`, so `F_AI >= P_cal` *always*: the GenAI layer could decline to add risk but
    could never subtract it. A legitimate app the classifier condemned was therefore
    unrescuable by construction — and rescuing exactly that app is the stated reason the
    behavioural layer exists.

    This form is not an ad-hoc fix. `BEHAVIOUR_WEIGHTS` and `CONTEXT_WEIGHTS` are measured
    log-likelihood ratios, so adding them to the classifier's log-odds is ordinary
    Bayesian evidence combination: the ML supplies the prior, the behavioural layer
    supplies a likelihood ratio, and the arithmetic is auditable line by line.

    `evidence is None` means the verdict predates the signed-evidence field, and falls
    back to noisy-OR so an old artefact keeps the meaning it was scored under. `evidence
    == 0.0` is different and deliberate: it means the layer ran and found nothing to say,
    which must leave the classifier untouched rather than nudging it.

    Pure: no I/O, no clock, no randomness (CLAUDE.md rule 3).
    """
    if evidence is None:
        return _noisy_or(probability, behavioural)
    if probability is None:
        # No prior to update. The behavioural belief is the whole signal.
        if behavioural is not None:
            return _clamp(behavioural)
        return round(_clamp(_sigmoid(evidence)), 6)
    return round(_clamp(_sigmoid(_logit(probability) + evidence)), 6)


def _noisy_or(probability: float | None, behavioural: float | None) -> float:
    """The pre-2026-08-26 fusion. Retained so old artefacts re-score identically."""
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
        # "unavailable" is the whole story, and the only honest one. The synthetic and
        # containment lines below describe a trace; when no sandbox ran there is no
        # trace for them to describe, and a reader shown "the dynamic trace is
        # synthetic" and "containment was not verified for the dynamic trace" will
        # reasonably infer that something was executed and then went wrong.
        items.append("dynamic analysis unavailable")
    else:
        if dynamic.source is TraceSourceKind.REPLAY:
            items.append("dynamic trace was replayed, not live")
        if dynamic.partial:
            items.append("dynamic analysis is partial")
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
