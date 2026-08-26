"""Probability calibration on the held-out calib split. Never on test.

docs/PHASE_2_ML_AND_SCORING.md T2.4.

`P_cal` is fed straight into the noisy-OR that produces half of the composite score, so a
model that is merely well-ranked is not enough — the number has to mean what it says. A
classifier reporting 0.8 for a bucket of samples that turn out to be 40% malicious will
push a whole band of verdicts into the wrong bucket, and the ranking metrics will not
notice.

Two methods are fitted and compared, because the right answer depends on how much
calibration data actually arrived:

  * **Isotonic** — non-parametric, strictly monotone, the better fit when there are
    enough positives. With a handful it degenerates into a step function that looks
    supremely confident and encodes nothing.
  * **Platt / sigmoid** — two parameters, robust on tiny splits, cannot represent a
    non-sigmoid distortion.

`select` picks between them on Brier score measured on the calibration split itself
(via cross-validation), never on test — choosing the method by its test Brier would be
the same leak as calibrating on test, one level of indirection away.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any

import numpy as np

from drishti.m5_ml.dataset import SEED

#: Below this many positives in the calib split, isotonic is not offered at all.
#: PHASE_2 T2.4 says to fall back to sigmoid on a small calibration set; this is that
#: rule, expressed as a number rather than as a judgement call at 3am.
MIN_POSITIVES_FOR_ISOTONIC = 25

#: Below this many positives, NO calibrator is shipped at all.
#:
#: Measured on the first 331 extracted samples: Platt fitted on a calibration split with
#: one malware row moved the test Brier from 0.130 to 0.595 — it made the probability
#: worse, confidently. A calibrator is a claim that a number means what it says, and eight
#: samples cannot support that claim. Refusing is the honest outcome; `infer` then labels
#: the probability uncalibrated and the report says so.
#:
#: This is an a-priori rule on the calibration split's own size. Deciding by the test
#: Brier instead would be the same leak as calibrating on test.
MIN_POSITIVES_FOR_ANY_CALIBRATION = 10

#: Reliability-diagram bins. Ten is the roadmap's figure and enough to see a distortion
#: without inventing structure out of five samples per bin.
RELIABILITY_BINS = 10


class NotEnoughCalibrationDataError(ValueError):
    """The calibration split cannot support a calibrator, and pretending otherwise lies."""


@dataclass
class CalibrationResult:
    """A fitted calibrator plus every measurement used to justify choosing it."""

    method: str
    calibrator: Any
    n_calib: int
    n_calib_pos: int
    n_calib_neg: int
    brier_calib_cv: float
    available_methods: list[str]
    rejected: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "n_calib": self.n_calib,
            "n_calib_pos": self.n_calib_pos,
            "n_calib_neg": self.n_calib_neg,
            "brier_on_calib_cv": self.brier_calib_cv,
            "methods_considered": self.available_methods,
            "methods_rejected": self.rejected,
        }


def _frozen(model: Any) -> Any:
    """Wrap a fitted estimator so `CalibratedClassifierCV` will not refit it.

    `cv="prefit"` was removed in recent scikit-learn; `FrozenEstimator` is the
    replacement and carries the same guarantee — the base model is not touched, so no
    calibration-split row ever influences the classifier itself.
    """
    from sklearn.frozen import FrozenEstimator

    return FrozenEstimator(model)


def fit_one(model: Any, features: np.ndarray, labels: np.ndarray, method: str) -> Any:
    """Fit one calibrator over a frozen base model."""
    from sklearn.calibration import CalibratedClassifierCV

    calibrator = CalibratedClassifierCV(_frozen(model), method=method)
    calibrator.fit(features, labels)
    return calibrator


def _cv_brier(model: Any, features: np.ndarray, labels: np.ndarray, method: str) -> float:
    """Brier of a calibrator fitted and scored by cross-validation WITHIN the calib split.

    This is how the method is chosen. Fitting on all of calib and scoring on all of calib
    would reward isotonic for memorising, which is precisely the failure mode being
    guarded against.
    """
    from sklearn.metrics import brier_score_loss
    from sklearn.model_selection import StratifiedKFold

    positives = int((labels == 1).sum())
    folds = min(5, positives, int((labels == 0).sum()))
    if folds < 2:
        return float("nan")
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    predictions = np.zeros(len(labels), dtype=float)
    for train_index, test_index in splitter.split(features, labels):
        fold = fit_one(model, features[train_index], labels[train_index], method)
        predictions[test_index] = fold.predict_proba(features[test_index])[:, 1]
    return float(brier_score_loss(labels, predictions))


def select(model: Any, features: np.ndarray, labels: np.ndarray) -> CalibrationResult:
    """Fit isotonic and Platt on the calib split and return the better-supported one.

    Raises `NotEnoughCalibrationDataError` rather than returning a calibrator nobody should
    trust. A caller that catches it must ship the raw probability and label it so.
    """
    labels = np.asarray(labels, dtype=int)
    positives, negatives = int((labels == 1).sum()), int((labels == 0).sum())
    if positives < MIN_POSITIVES_FOR_ANY_CALIBRATION or negatives < 2:
        raise NotEnoughCalibrationDataError(
            f"the calibration split holds {positives} malware and {negatives} benign rows; "
            f"{MIN_POSITIVES_FOR_ANY_CALIBRATION} positives are the minimum. A calibrator "
            "fitted on fewer has been measured to make the probability worse, confidently. "
            "Ship the raw probability and label it uncalibrated."
        )
    rejected: dict[str, str] = {}
    candidates = ["sigmoid"]
    if positives >= MIN_POSITIVES_FOR_ISOTONIC:
        candidates.insert(0, "isotonic")
    else:
        rejected["isotonic"] = (
            f"{positives} positives in the calibration split, below the "
            f"{MIN_POSITIVES_FOR_ISOTONIC} needed; isotonic on this many collapses to a "
            "step function that looks confident and encodes nothing"
        )

    scored: dict[str, float] = {}
    for method in candidates:
        value = _cv_brier(model, features, labels, method)
        if not np.isnan(value):
            scored[method] = value

    if scored:
        method = min(scored, key=lambda m: scored[m])
        brier = round(scored[method], 6)
        for other, value in scored.items():
            if other != method:
                rejected[other] = f"higher cross-validated Brier on calib ({value:.6f})"
    else:
        method = candidates[0]
        brier = float("nan")
        rejected["_cv"] = "calibration split too small to cross-validate; method chosen by rule"

    return CalibrationResult(
        method=method,
        calibrator=fit_one(model, features, labels, method),
        n_calib=len(labels),
        n_calib_pos=positives,
        n_calib_neg=negatives,
        brier_calib_cv=brier,
        available_methods=candidates,
        rejected=rejected,
    )


def fit_all(model: Any, features: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    """Fit BOTH methods, for the side-by-side the report shows. Returns {method: calibrator}."""
    out: dict[str, Any] = {}
    for method in ("isotonic", "sigmoid"):
        try:
            out[method] = fit_one(model, features, labels, method)
        except Exception:
            continue
    return out


def reliability(
    labels: np.ndarray, probabilities: np.ndarray, bins: int = RELIABILITY_BINS
) -> list[dict[str, float]]:
    """Observed frequency per predicted-probability bin, with the count behind each point.

    Bins holding fewer than three samples are returned with their count so the plot can
    drop them: a bin of one sample is either 0.0 or 1.0 and tells a reader nothing except
    a misleading shape.
    """
    labels = np.asarray(labels, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    out: list[dict[str, float]] = []
    for low, high in itertools.pairwise(edges):
        mask = (probabilities >= low) & (
            probabilities < high if high < 1.0 else probabilities <= 1.0
        )
        count = int(mask.sum())
        out.append(
            {
                "bin_low": float(low),
                "bin_high": float(high),
                "n": count,
                "mean_predicted": float(probabilities[mask].mean()) if count else float("nan"),
                "observed_frequency": float(labels[mask].mean()) if count else float("nan"),
            }
        )
    return out


def expected_calibration_error(
    labels: np.ndarray, probabilities: np.ndarray, bins: int = RELIABILITY_BINS
) -> float:
    """Weighted mean gap between predicted and observed, over populated bins only."""
    rows = [row for row in reliability(labels, probabilities, bins) if row["n"] > 0]
    total = sum(row["n"] for row in rows)
    if not total:
        return float("nan")
    return round(
        sum(row["n"] * abs(row["mean_predicted"] - row["observed_frequency"]) for row in rows)
        / total,
        6,
    )


def brier(labels: np.ndarray, probabilities: np.ndarray) -> float:
    from sklearn.metrics import brier_score_loss

    return round(float(brier_score_loss(np.asarray(labels, dtype=int), probabilities)), 6)
