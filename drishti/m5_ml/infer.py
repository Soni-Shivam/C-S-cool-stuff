"""M5 inference: load the trained bundle and score one StaticReport.

docs/PHASE_2_ML_AND_SCORING.md T2.1, T2.3, T2.4, T2.5, T2.6.

Uses `features.extract` — the same function training calls — and the vocabulary frozen
at training time. That is the whole of the R3 defence: one extractor, one vocabulary, no
second code path.

**Absence of a model is reported, never faked.** When `models/` holds no trained
artefact this returns `partial=True` with `p_calibrated=0.0` and says why, so the scorer
drops it out of the fused term and `gamma` falls. A pipeline that silently substituted a
0.5 prior would be inventing evidence, which is precisely what the ledger exists to
prevent.

The same rule governs everything else the bundle can carry. An uncalibrated probability
is labelled uncalibrated. An anomaly score is only emitted when a detector was actually
fitted. `top_features` is populated only when real SHAP values were computed — when the
attribution fell back to global importance the field stays empty and the reason lands in
`errors`, because a bar chart captioned "SHAP" that is really coefficient magnitude is
the kind of small lie that discredits the parts of the report that are true.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from drishti.contracts.score import FeatureAttribution, MLPrediction
from drishti.contracts.static_report import StaticReport
from drishti.logging import get_logger
from drishti.m5_ml.bundle import (
    ANOMALY_FILE,
    BACKGROUND_FILE,
    CALIBRATOR_FILE,
    MODEL_FILE,
    VOCAB_FILE,
    ModelCard,
    load_card,
)
from drishti.m5_ml.features import (
    FEATURE_SCHEMA_VERSION,
    extract,
    load_vocabulary,
    project,
)

log = get_logger(__name__)


class ModelBundle:
    """A trained model plus the vocabulary it was trained against.

    The two are inseparable: a model applied to a vector built from a different
    vocabulary is reading the wrong column for every feature, and nothing would raise.
    """

    def __init__(
        self,
        model: Any,
        vocabulary: list[str],
        calibrator: Any | None,
        detector: Any | None = None,
        card: ModelCard | None = None,
        background: Any | None = None,
    ) -> None:
        self.model = model
        self.vocabulary = vocabulary
        self.calibrator = calibrator
        self.detector = detector
        self.card = card
        #: Reference distribution retained from training, so SHAP has something to
        #: compare against. Without it a model-agnostic explainer compares the sample to
        #: itself and returns a row of zeros — valid, and useless.
        self.background = background
        self._explainer: Any | None = None
        self._explainer_built = False

    @property
    def version(self) -> str:
        """Names the model that actually ran, from the card written when it was trained."""
        if self.card is not None:
            return self.card.version
        return f"unknown-{len(self.vocabulary)}f-{FEATURE_SCHEMA_VERSION}"

    def explainer(self, row: list[float]) -> Any | None:
        """Build the SHAP explainer lazily, against the training background if there is one.

        Lazy because most jobs never need it and constructing an explainer costs more
        than the prediction does.
        """
        if self._explainer_built:
            return self._explainer
        self._explainer_built = True
        try:
            import numpy as np

            from drishti.m5_ml.explain import Explainer

            background = (
                np.asarray(self.background, dtype=float)
                if self.background is not None and len(self.background)
                else np.asarray([row], dtype=float)
            )
            self._explainer = Explainer(self.model, background, self.vocabulary)
        except Exception as exc:
            log.warning("explainer_unavailable", error=str(exc))
            self._explainer = None
        return self._explainer


def _unpickle(path: Path) -> Any:
    import pickle

    return pickle.loads(path.read_bytes())


def load_bundle(models_dir: Path) -> ModelBundle | None:
    """Load the trained bundle, or None if this build has no model.

    Returns None rather than raising: shipping without a model is a legitimate state
    for this project, and the honest response is a partial prediction, not a crash.
    """
    models_dir = Path(models_dir)
    model_path = models_dir / MODEL_FILE
    vocab_path = models_dir / VOCAB_FILE
    if not model_path.exists() or not vocab_path.exists():
        return None
    try:
        model = _unpickle(model_path)
        vocabulary = load_vocabulary(vocab_path)
    except Exception as exc:
        log.error("model_load_failed", error=str(exc))
        return None

    calibrator = None
    calibrator_path = models_dir / CALIBRATOR_FILE
    if calibrator_path.exists():
        try:
            calibrator = _unpickle(calibrator_path)
        except Exception as exc:
            log.warning("calibrator_load_failed", error=str(exc))

    detector = None
    anomaly_path = models_dir / ANOMALY_FILE
    if anomaly_path.exists():
        try:
            detector = _unpickle(anomaly_path)
        except Exception as exc:
            log.warning("anomaly_load_failed", error=str(exc))

    background = None
    background_path = models_dir / BACKGROUND_FILE
    if background_path.exists():
        try:
            import numpy as np

            background = np.load(background_path)
        except Exception as exc:
            log.warning("background_load_failed", error=str(exc))

    return ModelBundle(model, vocabulary, calibrator, detector, load_card(models_dir), background)


def predict(static: StaticReport, models_dir: Path) -> MLPrediction:
    """Score one report. Reports absence of a model rather than inventing a number."""
    bundle = load_bundle(models_dir)
    if bundle is None:
        return MLPrediction(
            p_malicious_raw=0.0,
            p_calibrated=0.0,
            model_version="none",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            partial=True,
            errors=(
                "no trained model in models/ — P_cal is unavailable, not zero-risk. "
                "The fused term falls back to the GenAI half alone and gamma drops.",
            ),
        )

    vector = project(extract(static), bundle.vocabulary)
    raw = float(bundle.model.predict_proba([vector])[0][1])
    calibrated = raw
    errors: list[str] = []
    # A pickle written by one scikit-learn and unpickled by another loads happily and can
    # then behave differently, with nothing raising. Say so rather than let the number
    # pass as though the bundle and the runtime agreed.
    if bundle.card is not None and (mismatch := bundle.card.runtime_mismatch()):
        errors.append(
            "the runtime does not match the one that trained this model, so the "
            f"probability may not be the one it was validated at — {'; '.join(mismatch)}"
        )
    if bundle.calibrator is not None:
        try:
            calibrated = float(bundle.calibrator.predict_proba([vector])[0][1])
        except Exception as exc:
            errors.append(f"calibration failed, reporting the raw probability: {exc}")
    else:
        errors.append("no calibrator: this probability is uncalibrated and must be labelled so")

    anomaly_score = 0.0
    anomaly_escalate = False
    if bundle.detector is not None:
        try:
            import numpy as np

            anomaly_score = float(bundle.detector.score(np.asarray([vector], dtype=float))[0])
            anomaly_escalate = bool(anomaly_score >= _escalate_at())
        except Exception as exc:
            errors.append(f"anomaly detector failed: {exc}")
    else:
        errors.append(
            "no anomaly detector: novelty escalation is unavailable, so a family unlike "
            "anything in training will not be flagged as such"
        )

    attributions: tuple[FeatureAttribution, ...] = ()
    explainer = bundle.explainer(vector)
    if explainer is not None and explainer.method.startswith("shap"):
        attributions = tuple(
            FeatureAttribution(
                feature=item.feature,
                value=item.value,
                shap=item.weight,
                direction=item.direction,
            )
            for item in explainer.explain(vector)
        )
    else:
        method = explainer.method if explainer is not None else "unavailable"
        errors.append(
            f"per-sample SHAP attribution unavailable ({method}); top_features is left "
            "empty rather than filled with a global importance labelled as SHAP"
        )

    return MLPrediction(
        p_malicious_raw=round(raw, 6),
        p_calibrated=round(calibrated, 6),
        top_features=attributions,
        anomaly_score=round(anomaly_score, 6),
        anomaly_escalate=anomaly_escalate,
        model_version=bundle.version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        partial=bool(errors),
        errors=tuple(errors),
    )


def _escalate_at() -> float:
    from drishti.m5_ml.anomaly import ESCALATE_AT

    return ESCALATE_AT
