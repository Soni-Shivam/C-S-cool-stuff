"""M5 ML output and M6 composite score.

docs/01_DATA_CONTRACTS.md sections 5 and 6.

The formula is pinned in §6.1 and implemented by a pure function in
`m6_score/engine.py` — no I/O, no LLM, no clock, no randomness:

    F_AI = P_cal + B - (P_cal * B)              # noisy-OR, no double-count
    S    = 100 * min(1, 0.25R + 0.50F_AI + 0.15G + 0.10D)
    gamma= 0.4*has_static + 0.3*has_dynamic_detonation + 0.2*has_ml + 0.1*has_intel
    C    = gamma * (1 - |P_cal - B|)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from drishti.contracts.base import AnalyserResult, DrishtiModel


class SeverityBand(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


#: Inclusive lower bound per band. S>=85 CRITICAL | 65-84 HIGH | 40-64 MEDIUM | <40 LOW.
BAND_FLOOR: dict[SeverityBand, int] = {
    SeverityBand.LOW: 0,
    SeverityBand.MEDIUM: 40,
    SeverityBand.HIGH: 65,
    SeverityBand.CRITICAL: 85,
}

#: Lowest first. Anomaly escalation moves a verdict UP this ladder, never down.
BAND_ORDER: tuple[SeverityBand, ...] = (
    SeverityBand.LOW,
    SeverityBand.MEDIUM,
    SeverityBand.HIGH,
    SeverityBand.CRITICAL,
)


class FeatureAttribution(DrishtiModel):
    """One SHAP contribution, with a human-readable feature name.

    `feature` is a label like `perm:RECEIVE_SMS`, never `f_0142` — an explanation a
    reader cannot decode is not an explanation.
    """

    feature: str
    value: float
    shap: float
    direction: Literal["+", "-"]


class MLPrediction(AnalyserResult):
    """M5 output.

    `labels` uses independent sigmoids, never a softmax: a banking trojan genuinely
    IS dropper AND spyware AND overlay simultaneously, and a mutually-exclusive
    assignment would be factually wrong.

    `anomaly_escalate` is an ESCALATOR, not an additive term. Every other signal
    rewards familiarity — reputation is blind to a fresh hash, the classifier is out
    of distribution on a novel family, YARA only matches what someone already wrote a
    rule for — so a genuinely novel threat can be quiet on all three at once. This
    flag is what stops it landing quietly in LOW.
    """

    p_malicious_raw: float
    p_calibrated: float
    labels: dict[str, float] = Field(default_factory=dict)
    top_features: tuple[FeatureAttribution, ...] = ()
    anomaly_score: float = 0.0
    anomaly_escalate: bool = False
    model_version: str
    feature_schema_version: str
    ledger_refs: tuple[str, ...] = ()


class ScoreFactor(DrishtiModel):
    """One term of S, with its weight, inputs, and the evidence behind it.

    `evidence_refs` is the mechanism behind "every score point traces back to an
    artefact". Without it the claim is marketing; with it the UI can render
    F_AI 41.5 -> P_cal 0.71 -> the SHAP features -> the PERMISSION_COMBO node ->
    AndroidManifest.xml#L42.
    """

    symbol: Literal["R", "F_AI", "G", "D"]
    label: str
    raw: float
    weight: float
    contribution: float
    inputs: dict = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()


class ProposedAction(DrishtiModel):
    """A recommendation, never an execution.

    `requires_confirmation` defaults True and nothing in the codebase may set it
    False. Consequential actions are gated on a human, and the confirmation writes an
    `ANALYST_ACTION` ledger node naming who confirmed.
    """

    action: Literal[
        "block",
        "quarantine",
        "notify_customers",
        "push_ioc",
        "fast_track_analyst",
        "analyst_review",
        "monitor",
        "log",
    ]
    rationale: str
    requires_confirmation: bool = True
    confirmed_by: str | None = None
    confirmed_at: str | None = None


class CompositeScore(DrishtiModel):
    """M6 output. Deterministic given the same ledger.

    `explanation` is rendered from a template, not by an LLM: it must be fast, never
    hallucinate, and remain available when the model provider is down.
    """

    S: int
    band: SeverityBand
    C: float
    gamma: float
    factors: tuple[ScoreFactor, ...] = ()
    override_applied: str | None = None
    requires_human_review: bool = False
    anomaly_escalated: bool = False
    actions_proposed: tuple[ProposedAction, ...] = ()
    explanation: str = ""
    limitations: tuple[str, ...] = ()
    ledger_refs: tuple[str, ...] = ()
