"""M5 inference must report the absence of a model, never fake a probability."""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse
from drishti.m5_ml.infer import load_bundle, predict

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"


@pytest.fixture
def report(tmp_path: Path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_infer")
    try:
        yield analyse(CANARY, store)
    finally:
        store.close()


def test_no_model_directory_yields_no_bundle(tmp_path: Path) -> None:
    assert load_bundle(tmp_path / "does-not-exist") is None


def test_absence_of_a_model_is_declared_not_faked(report, tmp_path: Path) -> None:
    """A silent 0.5 prior would be inventing evidence.

    The scorer must be able to tell "no model" apart from "the model says zero risk",
    because the first should lower gamma and the second should not.
    """
    result = predict(report, tmp_path)
    assert result.model_version == "none"
    assert result.partial is True
    assert result.errors and "no trained model" in result.errors[0]
    assert result.p_calibrated == 0.0


def test_a_corrupt_model_degrades_rather_than_crashing(report, tmp_path: Path) -> None:
    """A broken artefact must not take a job down with it."""
    (tmp_path / "classifier_v1.json").write_text("this is not a model")
    (tmp_path / "vocab_v1.json").write_text('{"schema_version": "1.1.0", "features": ["a"]}')
    assert load_bundle(tmp_path) is None
    assert predict(report, tmp_path).model_version == "none"


def test_inference_uses_the_shared_extractor(report, tmp_path: Path) -> None:
    """R3: there must be no second feature path. Same function, same schema version."""
    from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION

    assert predict(report, tmp_path).feature_schema_version == FEATURE_SCHEMA_VERSION
