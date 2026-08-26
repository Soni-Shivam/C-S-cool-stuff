"""Reconstruct the composite triage score `S` over corpus rows, with the real scorer.

docs/PHASE_2_ML_AND_SCORING.md T2.7.

The model's PR-AUC is not what an analyst sees. What reaches the queue is `S` and its
band, and `S` fuses the calibrated probability with the deterministic-rule term `G`, the
drift term `D` and the reputation term `R`. So a claim about triage precision has to be
measured over `S`, not over `p_calibrated` — and `S` moved when `G` acquired a caller.

Two rules hold this honest:

* **The scorer is not reimplemented here.** `m6_score.engine.score` is pure, so it can
  be called over corpus rows directly; every `S` below is the number the pipeline would
  produce. A local copy of the formula would drift from the shipped one silently.
* **Nothing is invented.** `R` is 0 because no threat-intel feed ran over the corpus,
  and a VT-derived feed would be circular against a VT-derived label anyway. `B` is
  absent because no GenAI verdict and no detonation exists for these rows. This is
  therefore the **static + ML** triage configuration, and it is labelled that way
  everywhere it is reported. It is the floor, not the full system.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import numpy as np

from drishti.contracts.score import MLPrediction, SeverityBand
from drishti.contracts.static_report import (
    CertificateInfo,
    PermissionCombo,
    StaticReport,
)
from drishti.m2_static.rules import load_permission_rules
from drishti.m5_ml.dataset import Sample
from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION
from drishti.m6_score import engine

#: The configuration these numbers are measured in. Stated in every artefact that
#: quotes them, because `S` from a full run with intel and a detonation is a different
#: number and must not be compared against this one.
CONFIGURATION = "static + ML only (no threat intel, no GenAI verdict, no detonation)"


@dataclass(frozen=True)
class TriageRow:
    """One corpus row scored the way the pipeline would score it.

    `S` and `band` can disagree, and the disagreement is the point: the novelty
    escalator promotes a LOW band to HIGH without moving `S` by a single point. A
    summary that reported only one of the two would hide either the escalator's cost or
    the scorer's ceiling.
    """

    sha256: str
    label: int
    p_calibrated: float
    rule_severity: float
    S: int
    band: str
    anomaly_escalated: bool = False


@lru_cache(maxsize=1)
def combo_severity_scale() -> dict[str, float]:
    """`combo:<rule_id>` -> the 0-1 severity `G` reads, from both owning modules.

    The rule ids and their severities come from M2's own YAML taxonomy and the 0-1
    mapping from M6's own table, so this cannot drift from either. Nothing is typed in.
    """
    return {
        rule.rule_id: engine._RULE_SEVERITY[rule.severity.value] for rule in load_permission_rules()
    }


def rule_severity_from_features(features: Mapping[str, float]) -> float:
    """`G` for a corpus row, recovered from its `combo:*` flags.

    Worst match wins, exactly as `engine.rule_severity` does over a live report: five
    MEDIUM combinations are not more damning than one CRITICAL, and summing would let a
    noisy manifest outrank a targeted one.
    """
    scale = combo_severity_scale()
    matched = [
        scale[name.removeprefix("combo:")]
        for name, value in features.items()
        if name.startswith("combo:") and value and name.removeprefix("combo:") in scale
    ]
    return max(matched) if matched else 0.0


def _static_from_features(sample: Sample) -> StaticReport:
    """The minimal real `StaticReport` the scorer needs for `G` and `D`.

    Only the two fields `S` actually reads are reconstructed — matched combinations and
    undeclared-permission use. Everything else is left at its contract default rather
    than filled with a plausible-looking value that no measurement supports.
    """
    scale = combo_severity_scale()
    severity_of = {rule.rule_id: rule.severity for rule in load_permission_rules()}
    combos = tuple(
        PermissionCombo(
            rule_id=rule_id,
            permissions=(),
            severity=severity_of[rule_id],
            description="reconstructed from the corpus feature row",
        )
        for name, value in sorted(sample.features.items())
        if name.startswith("combo:") and value and (rule_id := name.removeprefix("combo:")) in scale
    )
    return StaticReport(
        sha256=sample.sha256,
        package=sample.package,
        app_label="",
        version_name="",
        version_code=0,
        min_sdk=0,
        target_sdk=int(sample.features.get("manifest:target_sdk", 0)),
        permission_combos=combos,
        certificate=CertificateInfo(
            sha256="",
            subject="",
            issuer="",
            not_before="",
            not_after="",
            age_days=0,
            self_signed=True,
        ),
        # `D`'s static half is a boolean in the scorer, and the feature row records it.
        used_not_declared=("reconstructed",)
        if sample.features.get("drift:has_undeclared_use")
        else (),
        partial=sample.static_partial,
    )


def triage_scores(
    samples: Sequence[Sample],
    p_calibrated: np.ndarray,
    *,
    model_version: str,
    anomaly_escalate: np.ndarray | None = None,
) -> list[TriageRow]:
    """Score every row through the real pure scorer. No intel, no behaviour, no trace."""
    if len(samples) != len(p_calibrated):
        raise ValueError("one calibrated probability per sample is required")
    escalate = (
        anomaly_escalate if anomaly_escalate is not None else np.zeros(len(samples), dtype=bool)
    )
    rows: list[TriageRow] = []
    for i, sample in enumerate(samples):
        static = _static_from_features(sample)
        probability = float(p_calibrated[i])
        result = engine.score(
            static=static,
            ml=MLPrediction(
                p_malicious_raw=probability,
                p_calibrated=probability,
                anomaly_escalate=bool(escalate[i]),
                model_version=model_version,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
            ),
            genai=None,
            dynamic=None,
            intel=None,
            yara_severity=engine.rule_severity(static),
        )
        rows.append(
            TriageRow(
                sha256=sample.sha256,
                label=sample.label,
                p_calibrated=probability,
                rule_severity=engine.rule_severity(static),
                S=result.S,
                band=result.band.value,
                anomaly_escalated=result.anomaly_escalated,
            )
        )
    return rows


def reachable_ceiling() -> int:
    """The highest `S` this configuration can produce, computed rather than asserted.

    Measured by scoring a row that maxes every term available to a static+ML triage:
    `p_calibrated = 1.0`, a CRITICAL rule match, and undeclared-permission use. `R`
    stays 0 because there is no intel and the dynamic half of `D` stays 0 because
    nothing was detonated — which is exactly why CRITICAL is out of reach here.
    """
    worst = max(combo_severity_scale().values(), default=0.0)
    static = StaticReport(
        sha256="0" * 64,
        package="ceiling.probe",
        app_label="",
        version_name="",
        version_code=0,
        min_sdk=0,
        target_sdk=0,
        certificate=CertificateInfo(
            sha256="",
            subject="",
            issuer="",
            not_before="",
            not_after="",
            age_days=0,
            self_signed=True,
        ),
        used_not_declared=("probe",),
    )
    return engine.score(
        static=static,
        ml=MLPrediction(
            p_malicious_raw=1.0,
            p_calibrated=1.0,
            model_version="ceiling-probe",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
        ),
        genai=None,
        dynamic=None,
        intel=None,
        yara_severity=worst,
    ).S


def band_metrics(rows: Sequence[TriageRow], band: SeverityBand) -> dict[str, Any]:
    """Precision/recall of "flag at this band or above", the queue an analyst works.

    Reported per band rather than at one threshold because the band is the unit the UI,
    the report and the proposed actions are all keyed on.
    """
    floor = {
        SeverityBand.CRITICAL: 85,
        SeverityBand.HIGH: 65,
        SeverityBand.MEDIUM: 40,
        SeverityBand.LOW: 0,
    }[band]
    # SIM300 below is a false positive: `row.S` is an attribute, and ruff reads the
    # capital letter as a constant.
    flagged = [row for row in rows if row.S >= floor]  # noqa: SIM300
    positives = [row for row in rows if row.label == 1]
    true_positives = sum(1 for row in flagged if row.label == 1)
    return {
        "band": band.value,
        "floor": floor,
        "n": len(rows),
        "n_malware": len(positives),
        "flagged": len(flagged),
        "true_positives": true_positives,
        "false_positives": len(flagged) - true_positives,
        "precision": round(true_positives / len(flagged), 4) if flagged else None,
        "recall": round(true_positives / len(positives), 4) if positives else None,
    }


def _distribution(rows: Sequence[TriageRow], key: Any) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        entry = counts.setdefault(key(row), {"n": 0, "malware": 0})
        entry["n"] += 1
        entry["malware"] += row.label
    return counts


def _band_of(value: int) -> str:
    if value >= 85:
        return SeverityBand.CRITICAL.value
    if value >= 65:
        return SeverityBand.HIGH.value
    if value >= 40:
        return SeverityBand.MEDIUM.value
    return SeverityBand.LOW.value


def escalation_effect(rows: Sequence[TriageRow]) -> dict[str, Any]:
    """What the novelty escalator does to the queue, separated from what `S` does.

    The escalator forces a **LOW** band to HIGH without moving `S`, so a band histogram
    and an `S` histogram legitimately disagree. Quantified here because the promoted
    rows are a real analyst cost and get charged to the escalator, not to the score.

    Only rows whose `S` puts them in LOW are counted as promoted. The flag is also set
    on MEDIUM and HIGH rows, where it changes nothing — counting those would inflate the
    escalator's apparent effect by every row it merely agreed with.
    """
    flagged = [row for row in rows if row.anomaly_escalated]
    promoted = [row for row in flagged if _band_of(row.S) == SeverityBand.LOW.value]
    return {
        "flagged": len(flagged),
        "promoted_to_high": len(promoted),
        "promoted_malware": sum(row.label for row in promoted),
        "promoted_benign": sum(1 for row in promoted if row.label == 0),
    }


def summarise(rows: Sequence[TriageRow]) -> dict[str, Any]:
    """Everything a reader needs to judge a composite claim from this run."""
    return {
        "configuration": CONFIGURATION,
        "n": len(rows),
        "n_malware": sum(row.label for row in rows),
        "reachable_ceiling": reachable_ceiling(),
        "max_S_observed": max((row.S for row in rows), default=0),
        # Two histograms, deliberately: one over `S` alone, one over the band the
        # pipeline actually emits after the escalator has had its say.
        "band_distribution": _distribution(rows, lambda row: _band_of(row.S)),
        "band_distribution_after_escalation": _distribution(rows, lambda row: row.band),
        "escalation": escalation_effect(rows),
        "bands": [
            band_metrics(rows, band)
            for band in (SeverityBand.MEDIUM, SeverityBand.HIGH, SeverityBand.CRITICAL)
        ],
        "rule_severity_fired": sum(1 for row in rows if row.rule_severity > 0.0),
    }
