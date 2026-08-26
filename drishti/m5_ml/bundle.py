"""On-disk layout of a trained M5 bundle, and the card that says where it came from.

docs/PHASE_2_ML_AND_SCORING.md T2.3/T2.4/T2.5.

A model, its vocabulary, its calibrator and its anomaly detector are one artefact, not
four. A model applied to a vector built from a different vocabulary reads the wrong
column for every feature and nothing raises; a probability read through the wrong
calibrator is confidently wrong. So they are written together, versioned together, and
`load` refuses a mismatched set.

`model_card.json` exists so that anything the UI or the report says about the model is
traceable to a measurement rather than to someone's memory: which model won, on how many
samples, with what time-split PR-AUC, from which corpus file, on which date.
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION, load_vocabulary

MODEL_FILE = "classifier_v1.pkl"
CALIBRATOR_FILE = "calibrator_v1.pkl"
ANOMALY_FILE = "anomaly_v1.pkl"
VOCAB_FILE = "vocab_v1.json"
CARD_FILE = "model_card.json"
METRICS_FILE = "metrics.json"
#: A subsample of the TRAINING feature matrix, kept so SHAP has a reference distribution
#: at inference time. Without it the model-agnostic explainers compare a sample against
#: itself and return a row of zeros — an explanation that is technically valid and
#: completely useless. Feature vectors only; no APK bytes and no hashes.
BACKGROUND_FILE = "background_v1.npy"

#: Rows retained as that reference. Enough for a stable expectation, small enough that
#: the file stays a few hundred kilobytes.
BACKGROUND_ROWS = 128


@dataclass
class ModelCard:
    """Provenance and headline measurements for the shipped model.

    Every field is written by `scripts/train_and_report.py` from a measurement it made in
    that run. Nothing here is a target, an estimate, or a number carried over from a
    previous build.
    """

    model_name: str
    feature_schema_version: str
    n_features: int
    trained_at: str
    corpus_sources: list[str]
    n_train: int
    n_train_malware: int
    n_calib: int
    n_calib_malware: int
    n_test: int
    n_test_malware: int
    calibration_method: str
    operating_threshold: float
    threshold_source: str
    time_split_pr_auc: float
    time_split_pr_auc_ci: list[float]
    random_split_pr_auc: float
    random_split_pr_auc_ci: list[float]
    generalisation_gap: float
    attribution_method: str = "unknown"
    notes: list[str] = field(default_factory=list)

    @property
    def version(self) -> str:
        """The string that appears in the ledger and the UI badge."""
        return f"{self.model_name}-{self.n_features}f-{FEATURE_SCHEMA_VERSION}"

    def as_dict(self) -> dict[str, Any]:
        payload = self.__dict__.copy()
        payload["model_version"] = self.version
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ModelCard:
        known = {k: v for k, v in payload.items() if k in cls.__dataclass_fields__}
        return cls(**known)


def save(
    models_dir: Path,
    *,
    model: Any,
    vocabulary: list[str],
    calibrator: Any | None,
    detector: Any | None,
    card: ModelCard,
    metrics: dict[str, Any] | None = None,
    background: Any | None = None,
) -> None:
    """Write the whole bundle atomically enough that a half-written model is not loadable."""
    models_dir = Path(models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    # The vocabulary lands first and the model last: `load` keys off the model file, so a
    # crash mid-write leaves a directory that reports "no model" rather than a mismatch.
    (models_dir / VOCAB_FILE).write_text(
        json.dumps(
            {"schema_version": FEATURE_SCHEMA_VERSION, "features": list(vocabulary)}, indent=2
        )
        + "\n"
    )
    if calibrator is not None:
        (models_dir / CALIBRATOR_FILE).write_bytes(pickle.dumps(calibrator))
    if detector is not None:
        (models_dir / ANOMALY_FILE).write_bytes(pickle.dumps(detector))
    (models_dir / CARD_FILE).write_text(json.dumps(card.as_dict(), indent=2, default=str) + "\n")
    if metrics is not None:
        (models_dir / METRICS_FILE).write_text(json.dumps(metrics, indent=2, default=str) + "\n")
    if background is not None:
        import numpy as np

        rows = np.asarray(background, dtype=float)
        if len(rows) > BACKGROUND_ROWS:
            rng = np.random.default_rng(0)
            rows = rows[rng.choice(len(rows), BACKGROUND_ROWS, replace=False)]
        np.save(models_dir / BACKGROUND_FILE, rows)
    # Pickled rather than xgboost's save_model: `infer` needs the fitted sklearn wrapper
    # (predict_proba lives there), and save_model refuses the wrapper on this pairing.
    (models_dir / MODEL_FILE).write_bytes(pickle.dumps(model))


def load_card(models_dir: Path) -> ModelCard | None:
    path = Path(models_dir) / CARD_FILE
    if not path.exists():
        return None
    try:
        return ModelCard.from_dict(json.loads(path.read_text()))
    except Exception:
        return None


def load_vocab(models_dir: Path) -> list[str]:
    """Load the pinned vocabulary. Raises if it was built for a different extractor."""
    return load_vocabulary(Path(models_dir) / VOCAB_FILE)
