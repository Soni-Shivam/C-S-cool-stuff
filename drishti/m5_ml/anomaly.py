"""IsolationForest novelty escalator, fitted on benign training samples only.

docs/PHASE_2_ML_AND_SCORING.md T2.5.

Its role is architectural, not numeric. **It is an escalator, not an additive term.**
Every other signal in the system rewards familiarity: reputation is blind to a fresh
hash, the classifier is out of distribution on a family it has never seen, and YARA only
matches rules somebody already wrote. A genuinely novel threat can therefore be quiet on
all three at once, and land in LOW. This flag is what stops that.

Fitted on **benign train rows only** so "unusual" means "unlike a normal app", not
"unlike the average of everything we happen to have downloaded". Malware in the fit set
would teach the detector that malware is normal.

The raw `decision_function` is unbounded and its scale depends on the training set, so it
cannot be compared against a fixed 0.85 threshold. `AnomalyDetector` freezes the benign
score distribution at fit time and normalises against it: the published score is the
fraction of benign training apps that look *more* normal than this sample. That makes the
threshold mean something stable — "in the top 15% most unusual relative to the benign
corpus this model was fitted on" — and it travels with the pickle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from drishti.m5_ml.dataset import SEED

#: Above this normalised score the band is forced to at least HIGH and a human is
#: required. PHASE_2 T2.5 pins the value; the scorer reads `anomaly_escalate`, not this.
ESCALATE_AT = 0.85

#: IsolationForest's own assumption about how much of the benign fit set is contaminated.
CONTAMINATION = 0.05


@dataclass
class AnomalyDetector:
    """A fitted IsolationForest plus the benign score distribution it is read against."""

    forest: Any
    #: Sorted `decision_function` values over the benign fit set. Higher = more normal.
    benign_reference: np.ndarray
    n_fit: int
    feature_count: int

    def raw(self, features: np.ndarray) -> np.ndarray:
        return np.asarray(self.forest.decision_function(features), dtype=float)

    def score(self, features: np.ndarray) -> np.ndarray:
        """Normalised novelty in [0, 1]. 1.0 = more unusual than every benign fit sample.

        Defined as the fraction of the benign reference distribution that this sample is
        *below* on the normality axis — a percentile, so it is invariant to the raw
        score's arbitrary scale and comparable across retrainings.
        """
        values = self.raw(features)
        if self.benign_reference.size == 0:
            return np.zeros_like(values)
        # searchsorted gives how many benign apps are at least as normal-looking.
        rank = np.searchsorted(self.benign_reference, values, side="left")
        return 1.0 - (rank / self.benign_reference.size)

    def escalates(self, features: np.ndarray) -> np.ndarray:
        return self.score(features) >= ESCALATE_AT


def fit(features: np.ndarray, labels: np.ndarray) -> AnomalyDetector:
    """Fit on the benign rows of the supplied matrix. Raises if there are none.

    Raising rather than falling back to "fit on everything": a detector silently fitted
    on a mixed corpus reports plausible numbers and answers a different question, which
    is worse than not having one.
    """
    from sklearn.ensemble import IsolationForest

    labels = np.asarray(labels, dtype=int)
    benign = features[labels == 0]
    if len(benign) == 0:
        raise ValueError(
            "no benign rows to fit the anomaly detector on — fitting on malware would "
            "teach it that malware is normal"
        )
    forest = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=-1,
    )
    forest.fit(benign)
    reference = np.sort(np.asarray(forest.decision_function(benign), dtype=float))
    return AnomalyDetector(
        forest=forest,
        benign_reference=reference,
        n_fit=len(benign),
        feature_count=features.shape[1],
    )


def summarise(
    detector: AnomalyDetector, features: np.ndarray, labels: np.ndarray
) -> dict[str, Any]:
    """What the escalator would actually do on a split. Measured, not assumed.

    Reported so a reader can see the cost: the escalation rate on benign samples is the
    extra analyst load this flag creates, and it belongs next to the claim it supports.
    """
    labels = np.asarray(labels, dtype=int)
    scores = detector.score(features)
    escalated = scores >= ESCALATE_AT
    benign_mask = labels == 0
    malware_mask = labels == 1
    return {
        "escalate_at": ESCALATE_AT,
        "n_fit_benign": detector.n_fit,
        "n_scored": len(labels),
        "escalated_total": int(escalated.sum()),
        "escalated_benign": int((escalated & benign_mask).sum()),
        "escalated_malware": int((escalated & malware_mask).sum()),
        "benign_escalation_rate": round(
            float((escalated & benign_mask).sum() / benign_mask.sum()), 6
        )
        if benign_mask.sum()
        else None,
        "malware_escalation_rate": round(
            float((escalated & malware_mask).sum() / malware_mask.sum()), 6
        )
        if malware_mask.sum()
        else None,
        "mean_score_benign": round(float(scores[benign_mask].mean()), 6)
        if benign_mask.sum()
        else None,
        "mean_score_malware": round(float(scores[malware_mask].mean()), 6)
        if malware_mask.sum()
        else None,
    }
