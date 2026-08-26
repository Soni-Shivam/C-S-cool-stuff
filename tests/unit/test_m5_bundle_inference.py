"""A saved bundle must actually reach inference — anomaly and attribution included.

docs/PHASE_2_ML_AND_SCORING.md T2.5, T2.6.

STATUS.md recorded `anomaly_escalate` as a **dead branch**: the contract field existed,
`m6_score/engine.py` escalated a LOW band on it, the escalation was unit-tested, and
nothing in a real run ever set it. The paper's claim that a novel family cannot land
quietly in LOW was therefore not true in code. These tests fix that by asserting the
whole path — train, persist, load, predict — rather than the contract in isolation.

The model here is fitted on a handful of synthetic rows. That is fine and deliberate:
these tests check the WIRING, not a metric. Nothing they produce is reported anywhere.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse
from drishti.m5_ml import anomaly, bundle, calibrate, models
from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION, extract
from drishti.m5_ml.infer import load_bundle, predict

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"


@pytest.fixture(scope="module")
def canary_report():
    """One real StaticReport. Local static parsing only — nothing is installed or run."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
        store.open("job_bundle")
        try:
            yield analyse(CANARY, store)
        finally:
            store.close()


def _card(name: str, n_features: int) -> bundle.ModelCard:
    return bundle.ModelCard(
        model_name=name,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        n_features=n_features,
        trained_at="2026-08-26T00:00:00+00:00",
        corpus_sources=["synthetic wiring fixture"],
        n_train=200,
        n_train_malware=100,
        n_calib=60,
        n_calib_malware=6,
        n_test=60,
        n_test_malware=6,
        calibration_method="sigmoid",
        operating_threshold=0.5,
        threshold_source="fixture",
        time_split_pr_auc=0.0,
        time_split_pr_auc_ci=[0.0, 0.0],
        random_split_pr_auc=0.0,
        random_split_pr_auc_ci=[0.0, 0.0],
        generalisation_gap=0.0,
        library_versions=bundle.library_versions(),
        notes=["synthetic wiring fixture — not a measurement"],
    )


@pytest.fixture
def trained_bundle(canary_report, tmp_path: Path) -> Path:
    """Persist a real bundle whose vocabulary is the canary's own feature names."""
    vocabulary = sorted(extract(canary_report).values)
    rng = np.random.default_rng(11)
    width = len(vocabulary)
    features = np.vstack([rng.normal(0, 1, (150, width)), rng.normal(3, 1, (150, width))])
    labels = np.array([0] * 150 + [1] * 150)

    model = models.fit("xgboost", features, labels)
    detector = anomaly.fit(features, labels)
    calibrator = calibrate.fit_one(model, features, labels, "sigmoid")
    bundle.save(
        tmp_path,
        model=model,
        vocabulary=vocabulary,
        calibrator=calibrator,
        detector=detector,
        card=_card("xgboost", width),
        background=features[labels == 0],
    )
    return tmp_path


def test_a_saved_bundle_loads_with_every_part(trained_bundle: Path) -> None:
    loaded = load_bundle(trained_bundle)
    assert loaded is not None
    assert loaded.calibrator is not None
    assert loaded.detector is not None
    assert loaded.background is not None
    assert loaded.card is not None


def test_model_version_names_the_model_that_actually_ran(
    trained_bundle: Path, canary_report
) -> None:
    """`unavailable` and `stub` must both disappear once a real bundle is shipped."""
    result = predict(canary_report, trained_bundle)
    assert result.model_version.startswith("xgboost-")
    assert result.model_version not in ("none", "stub")
    assert result.feature_schema_version == FEATURE_SCHEMA_VERSION


def test_the_anomaly_branch_is_reachable_from_a_real_prediction(
    trained_bundle: Path, canary_report
) -> None:
    """T2.5 was a dead branch: the field existed and no real run ever set it."""
    result = predict(canary_report, trained_bundle)
    assert 0.0 <= result.anomaly_score <= 1.0
    assert result.anomaly_escalate is (result.anomaly_score >= anomaly.ESCALATE_AT)


def test_missing_anomaly_detector_is_declared_rather_than_reported_as_zero_risk(
    trained_bundle: Path, canary_report
) -> None:
    """A 0.0 novelty score from an absent detector reads as 'nothing unusual'. It isn't."""
    (trained_bundle / bundle.ANOMALY_FILE).unlink()
    result = predict(canary_report, trained_bundle)
    assert result.anomaly_escalate is False
    assert result.partial is True
    assert any("no anomaly detector" in error for error in result.errors)


def test_shap_attributions_are_named_and_non_degenerate(
    trained_bundle: Path, canary_report
) -> None:
    """Named features, real background, at least one non-zero contribution.

    A background of the sample itself yields a row of zeros — technically valid and
    entirely useless — which is why the training background travels in the bundle.
    """
    result = predict(canary_report, trained_bundle)
    assert result.top_features, "no attribution reached the prediction"
    assert all(":" in item.feature for item in result.top_features)
    assert any(item.shap != 0.0 for item in result.top_features)
    assert all(item.direction in ("+", "-") for item in result.top_features)


def test_attribution_is_left_empty_rather_than_mislabelled_when_shap_is_unavailable(
    trained_bundle: Path, canary_report, monkeypatch
) -> None:
    """A bar chart captioned SHAP that is really coefficient magnitude is a small lie."""
    import builtins

    real_import = builtins.__import__

    def refuse_shap(name, *args, **kwargs):
        if name == "shap" or name.startswith("shap."):
            raise ImportError("shap unavailable in this environment")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_shap)
    result = predict(canary_report, trained_bundle)
    assert result.top_features == ()
    assert any("SHAP attribution unavailable" in error for error in result.errors)


def test_an_incompatible_shap_is_named_rather_than_reported_as_merely_unavailable(
    trained_bundle: Path, canary_report, monkeypatch
) -> None:
    """The version is the whole diagnosis, so the error has to carry it.

    shap 0.46 raises at IMPORT under numpy>=2.3, the `except` swallowed it, and the job
    reported only "SHAP unavailable" — which reads as "shap is not installed" and hides
    the one-line fix. This is what shipped a permanently empty attribution panel.
    """
    import builtins

    from drishti.m5_ml import explain

    real_import = builtins.__import__

    def broken_shap(name, *args, **kwargs):
        if name == "shap" or name.startswith("shap."):
            raise TypeError("Converting `np.inexact` to a dtype not allowed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken_shap)
    monkeypatch.setattr(explain, "_installed_shap_version", lambda: "0.46.0")

    result = predict(canary_report, trained_bundle)
    assert result.top_features == ()
    assert any("0.46.0" in error and "shap>=0.48" in error for error in result.errors)


def test_a_shap_old_enough_to_be_wrong_is_refused_even_when_it_imports(
    trained_bundle: Path, canary_report, monkeypatch
) -> None:
    """Importing is not the bar — being the version the pipeline was validated on is."""
    from drishti.m5_ml import explain

    monkeypatch.setattr(explain, "_installed_shap_version", lambda: "0.46.0")
    monkeypatch.setattr(
        explain, "_import_shap", lambda: (None, "shap 0.46.0 is installed but shap>=0.48")
    )
    result = predict(canary_report, trained_bundle)
    assert result.top_features == ()
    assert any("0.46.0" in error for error in result.errors)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("0.46.0", (0, 46, 0)),
        ("0.51.0", (0, 51, 0)),
        ("0.48", (0, 48)),
        ("1.0.0rc1", (1, 0, 0)),
    ],
)
def test_the_shap_version_gate_parses_what_pypi_actually_publishes(version, expected) -> None:
    from drishti.m5_ml.explain import SHAP_MIN_VERSION, _version_tuple

    assert _version_tuple(version) == expected
    # An unreadable version must not silently disable the whole explainer.
    assert _version_tuple(None) >= SHAP_MIN_VERSION


def test_a_bundle_without_a_calibrator_labels_its_probability_uncalibrated(
    trained_bundle: Path, canary_report
) -> None:
    (trained_bundle / bundle.CALIBRATOR_FILE).unlink()
    result = predict(canary_report, trained_bundle)
    assert result.p_calibrated == result.p_malicious_raw
    assert any("uncalibrated" in error for error in result.errors)


def test_a_vocabulary_from_a_different_schema_is_refused(trained_bundle: Path) -> None:
    """A model reading the wrong column for every feature raises nothing on its own."""
    (trained_bundle / bundle.VOCAB_FILE).write_text(
        '{"schema_version": "0.0.1", "features": ["a"]}'
    )
    assert load_bundle(trained_bundle) is None


def test_the_model_card_records_the_counts_it_was_trained_on(trained_bundle: Path) -> None:
    card = bundle.load_card(trained_bundle)
    assert card is not None
    assert card.n_train == 200 and card.n_test_malware == 6
    assert card.version.endswith(FEATURE_SCHEMA_VERSION)


def test_a_runtime_that_does_not_match_the_training_one_is_declared(
    trained_bundle: Path, canary_report
) -> None:
    """A pickle from a different scikit-learn loads happily and may behave differently.

    Nothing raises, so the only defence is to notice and say so.
    """
    import json

    card = json.loads((trained_bundle / bundle.CARD_FILE).read_text())
    card["library_versions"] = {"scikit-learn": "0.0.0-not-installed"}
    (trained_bundle / bundle.CARD_FILE).write_text(json.dumps(card))

    result = predict(canary_report, trained_bundle)
    assert result.partial is True
    assert any("does not match the one that trained this model" in e for e in result.errors)


def test_a_matching_runtime_raises_no_mismatch(trained_bundle: Path) -> None:
    card = bundle.load_card(trained_bundle)
    assert card is not None
    card.library_versions = bundle.library_versions()
    assert card.runtime_mismatch() == []
    assert "scikit-learn" in card.library_versions
