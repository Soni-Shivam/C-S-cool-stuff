"""M5 inference: load the trained model and score one StaticReport.

docs/PHASE_2_ML_AND_SCORING.md T2.1, T2.3.

Uses `features.extract` — the same function training calls — and the vocabulary frozen
at training time. That is the whole of the R3 defence: one extractor, one vocabulary, no
second code path.

**Absence of a model is reported, never faked.** When `models/` holds no trained
artefact this returns `partial=True` with `p_calibrated=0.0` and says why, so the scorer
drops it out of the fused term and `gamma` falls. A pipeline that silently substituted a
0.5 prior would be inventing evidence, which is precisely what the ledger exists to
prevent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from drishti.contracts.score import MLPrediction
from drishti.contracts.static_report import StaticReport
from drishti.logging import get_logger
from drishti.m5_ml.features import (
    FEATURE_SCHEMA_VERSION,
    extract,
    load_vocabulary,
    project,
)

log = get_logger(__name__)

MODEL_FILE = "classifier_v1.pkl"
CALIBRATOR_FILE = "calibrator_v1.pkl"
VOCAB_FILE = "vocab_v1.json"


class ModelBundle:
    """A trained model plus the vocabulary it was trained against.

    The two are inseparable: a model applied to a vector built from a different
    vocabulary is reading the wrong column for every feature, and nothing would raise.
    """

    def __init__(self, model: Any, vocabulary: list[str], calibrator: Any | None) -> None:
        self.model = model
        self.vocabulary = vocabulary
        self.calibrator = calibrator

    @property
    def version(self) -> str:
        return f"xgboost-{len(self.vocabulary)}feat"


def load_bundle(models_dir: Path) -> ModelBundle | None:
    """Load the trained bundle, or None if this build has no model.

    Returns None rather than raising: shipping without a model is a legitimate state
    for this project, and the honest response is a partial prediction, not a crash.
    """
    model_path = Path(models_dir) / MODEL_FILE
    vocab_path = Path(models_dir) / VOCAB_FILE
    if not model_path.exists() or not vocab_path.exists():
        return None
    try:
        import pickle

        # The fitted sklearn wrapper, not a raw Booster: predict_proba lives on the
        # wrapper, and xgboost's save_model refuses the wrapper on this version pairing.
        model = pickle.loads(model_path.read_bytes())
        vocabulary = load_vocabulary(vocab_path)
    except Exception as exc:
        log.error("model_load_failed", error=str(exc))
        return None

    calibrator = None
    calibrator_path = Path(models_dir) / CALIBRATOR_FILE
    if calibrator_path.exists():
        try:
            import pickle

            calibrator = pickle.loads(calibrator_path.read_bytes())
        except Exception as exc:
            log.warning("calibrator_load_failed", error=str(exc))
    return ModelBundle(model, vocabulary, calibrator)


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
    errors: tuple[str, ...] = ()
    if bundle.calibrator is not None:
        try:
            calibrated = float(bundle.calibrator.predict_proba([vector])[0][1])
        except Exception as exc:
            errors = (f"calibration failed, reporting the raw probability: {exc}",)
    else:
        errors = ("no calibrator: this probability is uncalibrated and must be labelled so",)

    return MLPrediction(
        p_malicious_raw=round(raw, 6),
        p_calibrated=round(calibrated, 6),
        model_version=bundle.version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        partial=bool(errors),
        errors=errors,
    )
