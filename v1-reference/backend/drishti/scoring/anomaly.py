"""Zero-day / novel-family escalation for M6 (paper 4.5).

THE PROBLEM THIS SOLVES
    Every other signal in DRISHTI rewards FAMILIARITY:
      * R (reputation)  -- a brand-new hash is unknown to every engine, so R sits at its
                           0.05 floor;
      * P_cal (M5 ML)   -- trained on families that existed before the cutoff, so a novel
                           family is out of distribution and often scores mid-range;
      * G (YARA)        -- signatures only match what someone already wrote a rule for.
    A genuinely novel threat can therefore be quiet on R, G and P_cal simultaneously and
    land in LOW, which is the exact failure the paper calls out: "ensuring zero-days cannot
    land quietly in LOW".

    The paper's answer is that the anomaly signal is an ESCALATOR, not an additive term:
    "a strong anomaly score forces human review and bumps the severity band regardless of
    the classifier's maliciousness probability". This module implements that.

DESIGN
    Escalation is driven by evidence that something is WRONG-SHAPED rather than
    known-bad:
      * capability/reputation mismatch -- dangerous capability combined with no reputation
        record at all (the classic freshly-minted dropper);
      * observed-but-unmodelled runtime behaviour -- the detonator saw MITRE techniques
        that static analysis never predicted;
      * signal disagreement -- ML and GenAI disagree sharply, which the paper already
        surfaces as low confidence but which should also prevent a quiet LOW;
      * evasion posture -- packing/obfuscation indicators, or a sample that refused to
        exhibit behaviour under instrumentation.

    Escalation NEVER lowers a score or band, never fabricates a maliciousness claim, and
    always states plainly that the reason is novelty rather than confirmed detection. It
    raises the floor and sets a review flag, so a human sees it and the user is warned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

#: Bands, lowest first. Escalation moves a verdict UP this ladder, never down.
_BAND_ORDER = ("Low", "Medium", "High", "Critical")
#: Minimum score implied by each band, so a bumped band and its score stay consistent.
_BAND_FLOOR = {"Low": 0, "Medium": 40, "High": 65, "Critical": 85}


@dataclass
class AnomalySignal:
    """One reason to suspect novelty rather than a known threat."""
    signal_id: str
    description: str
    weight: float
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class Escalation:
    """The outcome of the escalator: what changed and, crucially, why."""
    anomaly_score: float
    signals: list[AnomalySignal]
    original_score: int
    original_band: str
    escalated_score: int
    escalated_band: str
    requires_human_review: bool
    user_warning: str | None
    rationale: list[str]

    @property
    def escalated(self) -> bool:
        return (self.escalated_band != self.original_band
                or self.escalated_score != self.original_score)


def _bump(band: str, steps: int = 1) -> str:
    index = _BAND_ORDER.index(band)
    return _BAND_ORDER[min(len(_BAND_ORDER) - 1, index + steps)]


def collect_anomaly_signals(
    *,
    reputation_verdict: str,
    reputation_detections: int | None,
    p_cal: float,
    behavioral_risk: float,
    signature_severity: float,
    static_mitre: list[str],
    observed_mitre: list[str],
    dynamic_status: Literal["absent", "simulated", "observed"],
    dynamic_outcome: str | None = None,
    packed_or_obfuscated: bool = False,
    dangerous_capability_count: int = 0,
    evidence_refs: list[str] | None = None,
) -> list[AnomalySignal]:
    """Identify novelty indicators. Deliberately conservative and explainable."""
    refs = evidence_refs or []
    signals: list[AnomalySignal] = []

    unknown_reputation = reputation_verdict == "unknown" or reputation_detections is None

    # A file nobody has ever seen that nonetheless asks for dangerous capability is the
    # canonical shape of a freshly built dropper.
    if unknown_reputation and dangerous_capability_count >= 2:
        signals.append(AnomalySignal(
            "unknown_hash_with_dangerous_capability",
            f"No threat-intel record exists for this file, yet it declares "
            f"{dangerous_capability_count} high-risk capability combinations. Novel samples "
            f"are unknown to every engine by definition, so absence of detections is not "
            f"evidence of safety.",
            0.35, refs))

    # Runtime did something static analysis never predicted -> behaviour outside our model.
    unmodelled = sorted(set(observed_mitre) - set(static_mitre))
    if dynamic_status == "observed" and unmodelled:
        signals.append(AnomalySignal(
            "unmodelled_runtime_behaviour",
            f"The isolated detonator observed techniques that static analysis did not "
            f"predict: {', '.join(unmodelled)}. Behaviour outside the static model is a "
            f"hallmark of runtime-delivered payloads.",
            0.30, refs))

    # Signature layer silent while AI layers are alarmed -> nobody wrote a rule for this yet.
    if signature_severity <= 0.0 and max(p_cal, behavioral_risk) >= 0.6:
        signals.append(AnomalySignal(
            "no_signature_coverage",
            "No YARA signature matched, yet the statistical and reasoning layers flag this "
            "sample. Signature silence indicates lack of existing coverage, not safety.",
            0.20, refs))

    # Sharp disagreement between the statistical and semantic layers.
    if abs(p_cal - behavioral_risk) >= 0.45:
        signals.append(AnomalySignal(
            "detector_disagreement",
            f"The ML probability ({p_cal:.2f}) and the reasoned behavioural risk "
            f"({behavioral_risk:.2f}) disagree sharply, so neither layer alone should set "
            f"the outcome.",
            0.20, refs))

    if packed_or_obfuscated and unknown_reputation:
        signals.append(AnomalySignal(
            "unknown_and_evasive",
            "The sample shows packing/obfuscation indicators and has no reputation record.",
            0.25, refs))

    # Refusing to act under instrumentation is itself an evasion signal, not a clean bill.
    if dynamic_status == "observed" and dynamic_outcome == "inconclusive":
        signals.append(AnomalySignal(
            "no_behaviour_under_instrumentation",
            "The sample was successfully detonated but produced no observable behaviour. "
            "Environment-aware malware stalls deliberately; this is inconclusive, not benign.",
            0.25, refs))
    return signals


def escalate(
    *,
    score: int,
    band: str,
    signals: list[AnomalySignal],
    review_threshold: float = 0.30,
    critical_threshold: float = 0.60,
) -> Escalation:
    """Apply the escalator. Monotonic: the score and band can only rise.

    The anomaly score is capped at 1.0 and combines weights sub-additively so several weak
    signals cannot manufacture certainty.
    """
    anomaly = 0.0
    for signal in signals:
        # Sub-additive accumulation: each signal claims a fraction of what remains.
        anomaly += signal.weight * (1.0 - anomaly)
    anomaly = round(min(1.0, anomaly), 4)

    rationale: list[str] = []
    new_band = band
    if anomaly >= critical_threshold:
        new_band = _bump(band, 2)
        rationale.append(
            f"Anomaly score {anomaly:.2f} at or above {critical_threshold:.2f}: severity "
            f"raised two bands ({band} -> {new_band}) pending human review.")
    elif anomaly >= review_threshold:
        new_band = _bump(band, 1)
        rationale.append(
            f"Anomaly score {anomaly:.2f} at or above {review_threshold:.2f}: severity "
            f"raised one band ({band} -> {new_band}) pending human review.")

    # Keep score consistent with the bumped band without ever reducing it.
    new_score = max(score, _BAND_FLOOR[new_band]) if new_band != band else score
    if new_band == band and anomaly >= review_threshold:
        rationale.append("Severity already at the escalated level; review flag set.")

    requires_review = anomaly >= review_threshold
    warning = None
    if requires_review:
        reasons = "; ".join(s.description for s in signals[:3])
        warning = (
            "This app does not match any known threat on record, but its structure and "
            "behaviour are unusual in ways associated with new malware. Treat it as "
            f"unverified rather than safe. Reasons: {reasons}"
        )
        rationale.append(
            "Escalation reflects NOVELTY, not a confirmed detection: no claim is made that "
            "this sample matches a known malicious family.")
    return Escalation(
        anomaly_score=anomaly, signals=signals,
        original_score=score, original_band=band,
        escalated_score=new_score, escalated_band=new_band,
        requires_human_review=requires_review, user_warning=warning,
        rationale=rationale,
    )
