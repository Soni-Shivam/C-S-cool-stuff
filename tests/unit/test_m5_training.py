"""The training harness's guard rails, tested rather than trusted.

docs/PHASE_2_ML_AND_SCORING.md T2.3-T2.6.

Every test here covers a failure that would still produce a plausible-looking number:
a label-derived feature, a vocabulary built over the test split, a calibrator fitted on
too few positives, an anomaly detector fitted on malware. None of those raise on their
own, and all of them make the reported metrics wrong in a direction that flatters us.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from drishti.m5_ml import anomaly, calibrate, dataset, evaluate, models
from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION


def _sample(sha: str, label: int, split: str, band: str, **features: float) -> dataset.Sample:
    return dataset.Sample(
        sha256=sha,
        label=label,
        split=split,
        time_band=band,
        dex_date="2021-01-01",
        features=dict(features),
    )


# ── label leakage ────────────────────────────────────────────────────────────
def test_label_derived_feature_is_refused() -> None:
    """AndroZoo's label IS thresholded vt_detection; training on it is circular."""
    with pytest.raises(dataset.LabelLeakError, match="circular"):
        dataset.assert_no_label_leak(["perm:INTERNET", "vt:detection_count"])


@pytest.mark.parametrize(
    "name",
    ["vt:detections", "vt_detection", "virustotal_score", "avclass:family", "detection_ratio"],
)
def test_every_label_derived_prefix_is_caught(name: str) -> None:
    with pytest.raises(dataset.LabelLeakError):
        dataset.assert_no_label_leak([name])


def test_ordinary_features_pass_the_leak_guard() -> None:
    dataset.assert_no_label_leak(["perm:SEND_SMS", "sink:sms.send", "cert:age_days"])


# ── vocabulary and projection ────────────────────────────────────────────────
def test_vocabulary_is_frozen_from_training_rows_only() -> None:
    """A test-only feature name in the vocabulary is a leak no exception would announce."""
    train = [_sample("a" * 64, 0, "train", "<=2017", **{"perm:INTERNET": 1.0})]
    vocabulary = dataset.freeze_vocabulary(train)
    assert vocabulary == ["perm:INTERNET"]
    assert "perm:SEND_SMS" not in vocabulary


def test_unseen_feature_is_dropped_and_missing_one_is_zero_filled() -> None:
    """R3: appending an unseen column would shift every later column silently."""
    vocabulary = ["perm:INTERNET", "perm:SEND_SMS"]
    rows = [
        _sample("a" * 64, 1, "test", "2024-2026", **{"perm:SEND_SMS": 1.0, "perm:NEW": 1.0}),
    ]
    features, labels = dataset.matrix(rows, vocabulary)
    assert features.shape == (1, 2)
    assert features[0].tolist() == [0.0, 1.0]
    assert labels.tolist() == [1]


def test_matrix_of_no_samples_keeps_the_vocabulary_width() -> None:
    features, labels = dataset.matrix([], ["a", "b", "c"])
    assert features.shape == (0, 3)
    assert labels.shape == (0,)


# ── corpus loading ───────────────────────────────────────────────────────────
def test_failed_extractions_are_dropped_not_zero_filled(tmp_path: Path) -> None:
    """A sample androguard could not parse is missing data.

    Zero-filling it would teach the model that "unparseable" looks like "harmless",
    which is exactly backwards for a packed sample.
    """
    path = tmp_path / "c.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                {
                    "sha256": "a" * 64,
                    "label": 0,
                    "split": "train",
                    "time_band": "<=2017",
                    "ok": True,
                    "features": {"perm:INTERNET": 1.0},
                },
                {
                    "sha256": "b" * 64,
                    "label": 1,
                    "split": "train",
                    "time_band": "<=2017",
                    "ok": False,
                    "error": "boom",
                    "features": {},
                },
                {
                    "sha256": "c" * 64,
                    "label": 1,
                    "split": "train",
                    "time_band": "<=2017",
                    "ok": True,
                    "features": {},
                },
            )
        )
    )
    corpus = dataset.load_jsonl(path)
    assert len(corpus) == 1
    assert corpus.skipped_failed == 1
    assert corpus.skipped_empty == 1


def test_resumed_batches_do_not_double_count_a_sample(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    row = {
        "sha256": "a" * 64,
        "label": 0,
        "split": "train",
        "time_band": "<=2017",
        "ok": True,
        "features": {"perm:INTERNET": 1.0},
    }
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")
    assert len(dataset.load_jsonl(path)) == 1


def test_overlapping_time_bands_are_reported_as_not_a_time_split() -> None:
    corpus = dataset.Corpus(
        samples=[
            _sample("a" * 64, 0, "train", "2024-2026", **{"x": 1.0}),
            _sample("b" * 64, 1, "test", "2024-2026", **{"x": 1.0}),
        ]
    )
    ok, detail = dataset.time_split_is_honest(corpus)
    assert ok is False
    assert "2024-2026" in detail


# ── metrics ──────────────────────────────────────────────────────────────────
def test_fp_rate_at_recall_matches_a_hand_computed_case() -> None:
    """Four positives, six negatives, a ranking with one negative above the last positive."""
    labels = np.array([1, 1, 0, 1, 1, 0, 0, 0, 0, 0])
    scores = np.array([0.99, 0.95, 0.90, 0.85, 0.80, 0.7, 0.6, 0.5, 0.4, 0.3])
    fpr, precision, threshold = evaluate.fp_rate_at_recall(labels, scores, target=1.0)
    # All four positives are within the top five; one negative rides along.
    assert fpr == pytest.approx(1 / 6, abs=1e-5)  # the implementation rounds to 6 dp
    assert precision == pytest.approx(4 / 5)
    assert threshold == pytest.approx(0.80)


def test_fp_rate_is_none_when_the_target_recall_is_unreachable() -> None:
    """Better an honest None than a fabricated 1.0 claiming a capability we lack."""
    labels = np.array([1, 0, 0])
    scores = np.array([0.1, 0.9, 0.8])
    assert evaluate.fp_rate_at_recall(labels, scores, target=1.5) == (None, None, None)


def test_metrics_carry_n_and_flag_a_small_positive_count() -> None:
    labels = np.array([1] * 4 + [0] * 40)
    scores = np.concatenate([np.linspace(0.9, 0.7, 4), np.linspace(0.6, 0.1, 40)])
    result = evaluate.evaluate(
        model_name="m",
        split_name="time",
        labels=labels,
        probabilities=scores,
        threshold=0.65,
        threshold_source="test",
        with_ci=False,
    )
    assert result.n == 44 and result.n_pos == 4 and result.n_neg == 40
    assert result.tp == 4 and result.fp == 0
    assert any("4 positive rows" in note for note in result.notes)


def test_threshold_is_defaulted_and_says_so_when_positives_are_too_few() -> None:
    """The calibration split can be nearly all benign. A default must not read as a choice."""
    labels = np.array([0] * 30 + [1] * 3)
    scores = np.linspace(0, 1, 33)
    threshold, source = evaluate.choose_threshold(labels, scores)
    assert threshold == 0.5
    assert "too few to tune" in source


def test_markdown_table_states_n_for_every_row() -> None:
    labels = np.array([1] * 10 + [0] * 30)
    scores = np.concatenate([np.linspace(0.9, 0.6, 10), np.linspace(0.5, 0.0, 30)])
    row = evaluate.evaluate(
        model_name="m",
        split_name="time",
        labels=labels,
        probabilities=scores,
        threshold=0.55,
        threshold_source="test",
        with_ci=False,
    )
    table = evaluate.markdown_table([row])
    assert "| n |" in table and "| 40 | 10 | 30 |" in table


# ── calibration ──────────────────────────────────────────────────────────────
def _tiny_model(seed: int = 0) -> tuple[object, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    features = rng.normal(size=(300, 6))
    labels = (features[:, 0] + rng.normal(scale=0.5, size=300) > 0).astype(int)
    return models.fit("logreg_l2", features, labels), features, labels


def test_isotonic_is_refused_on_a_small_calibration_split() -> None:
    """PHASE_2 T2.4: fall back to sigmoid when calib is small. Enforced, not remembered."""
    model, _, _ = _tiny_model()
    rng = np.random.default_rng(1)
    calib_features = rng.normal(size=(120, 6))
    # Enough positives to fit anything at all, too few for isotonic to be meaningful.
    calib_labels = np.array([1] * 12 + [0] * 108)
    result = calibrate.select(model, calib_features, calib_labels)
    assert result.method == "sigmoid"
    assert "isotonic" in result.rejected
    assert str(calibrate.MIN_POSITIVES_FOR_ISOTONIC) in result.rejected["isotonic"]


def test_no_calibrator_at_all_below_the_hard_floor() -> None:
    """Measured on real data: Platt on one positive moved test Brier 0.130 -> 0.595.

    A calibrator is a claim that a probability means what it says. Eight samples cannot
    support that claim, and shipping one anyway is worse than shipping none.
    """
    model, _, _ = _tiny_model()
    rng = np.random.default_rng(2)
    with pytest.raises(calibrate.NotEnoughCalibrationDataError, match="uncalibrated"):
        calibrate.select(model, rng.normal(size=(60, 6)), np.array([1] * 3 + [0] * 57))


def test_calibration_reports_the_split_it_was_fitted_on() -> None:
    model, features, labels = _tiny_model()
    result = calibrate.select(model, features[:150], labels[:150])
    assert result.n_calib == 150
    assert result.n_calib_pos + result.n_calib_neg == 150


def test_reliability_bins_carry_their_own_sample_count() -> None:
    """A bin of one sample is 0.0 or 1.0 and means nothing; the count is what says so."""
    labels = np.array([0, 1, 1, 1])
    probabilities = np.array([0.05, 0.85, 0.86, 0.87])
    rows = calibrate.reliability(labels, probabilities, bins=10)
    populated = [row for row in rows if row["n"]]
    assert {row["n"] for row in populated} == {1, 3}


def test_expected_calibration_error_is_zero_for_a_perfect_predictor() -> None:
    labels = np.array([0] * 50 + [1] * 50)
    probabilities = np.array([0.0] * 50 + [1.0] * 50)
    assert calibrate.expected_calibration_error(labels, probabilities) == pytest.approx(0.0)


# ── anomaly escalator ────────────────────────────────────────────────────────
def test_anomaly_detector_refuses_to_fit_on_malware_only() -> None:
    """Fitting on a mixed or malicious corpus teaches it that malware is normal."""
    with pytest.raises(ValueError, match="benign"):
        anomaly.fit(np.ones((10, 4)), np.ones(10, dtype=int))


def test_a_clear_outlier_escalates_and_a_typical_sample_does_not() -> None:
    rng = np.random.default_rng(3)
    benign = rng.normal(size=(400, 5))
    detector = anomaly.fit(benign, np.zeros(400, dtype=int))
    outlier = np.full((1, 5), 40.0)
    typical = np.zeros((1, 5))
    assert bool(detector.escalates(outlier)[0]) is True
    assert bool(detector.escalates(typical)[0]) is False


def test_anomaly_score_is_bounded_and_normalised() -> None:
    rng = np.random.default_rng(4)
    benign = rng.normal(size=(200, 5))
    detector = anomaly.fit(benign, np.zeros(200, dtype=int))
    scores = detector.score(rng.normal(size=(50, 5)))
    assert scores.min() >= 0.0 and scores.max() <= 1.0


def test_anomaly_summary_reports_the_benign_escalation_cost() -> None:
    """The benign escalation rate is the analyst load this flag creates. Always reported."""
    rng = np.random.default_rng(5)
    benign = rng.normal(size=(300, 5))
    detector = anomaly.fit(benign, np.zeros(300, dtype=int))
    features = np.vstack([rng.normal(size=(50, 5)), np.full((5, 5), 30.0)])
    labels = np.array([0] * 50 + [1] * 5)
    summary = anomaly.summarise(detector, features, labels)
    assert summary["benign_escalation_rate"] is not None
    assert summary["escalated_malware"] == 5


# ── model zoo ────────────────────────────────────────────────────────────────
def test_every_model_in_the_zoo_produces_probabilities() -> None:
    """Evaluation must never branch on model type, or one family gets scored differently."""
    rng = np.random.default_rng(6)
    features = rng.normal(size=(200, 8))
    labels = (features[:, 0] > 0).astype(int)
    for name in models.MODEL_NAMES:
        model = models.fit(name, features, labels)
        probabilities = models.scores(model, features[:10])
        assert probabilities.shape == (10,)
        assert probabilities.min() >= 0.0 and probabilities.max() <= 1.0


def test_build_returns_a_fresh_estimator_each_time() -> None:
    """A refitted estimator would make 'the random split scored higher' partly mean
    'it was fitted second'."""
    labels = np.array([0, 1])
    assert models.build("xgboost", labels) is not models.build("xgboost", labels)


def test_unknown_model_name_is_an_error_not_a_silent_default() -> None:
    with pytest.raises(ValueError, match="unknown model"):
        models.build("magic", np.array([0, 1]))


def test_vocabulary_file_round_trips_through_the_schema_check(tmp_path: Path) -> None:
    path = tmp_path / "vocab_v1.json"
    dataset.write_vocabulary(path, ["perm:INTERNET", "sink:sms.send"])
    payload = json.loads(path.read_text())
    assert payload["schema_version"] == FEATURE_SCHEMA_VERSION
    assert payload["features"] == ["perm:INTERNET", "sink:sms.send"]


# ── attribution ──────────────────────────────────────────────────────────────
def test_permutation_importance_finds_only_the_columns_that_carry_signal() -> None:
    """The batched loop restores each permuted column before moving to the next.

    Without the restore, every column after the first would be measured against an
    already-degraded matrix and its importance silently understated — a bug that leaves
    a plausible-looking ranking rather than an error.
    """
    from drishti.m5_ml import explain

    rng = np.random.default_rng(0)
    features = (rng.random((300, 80)) < 0.2).astype(float)
    labels = ((features[:, 0] + features[:, 1]) > 0.5).astype(int)
    model = models.fit("random_forest", features, labels)

    rows = explain.permutation_importance(
        model, features, labels, [f"f{i}" for i in range(80)], repeats=3, top_k=5, max_columns=20
    )
    assert {rows[0].feature, rows[1].feature} == {"f0", "f1"}
    assert rows[0].weight > 0.01
    assert all(row.weight == 0.0 for row in rows[2:])


def test_permutation_importance_discloses_that_it_shortlisted() -> None:
    """A figure must not claim to have ranked features it never shuffled."""
    from drishti.m5_ml import explain

    rng = np.random.default_rng(1)
    features = (rng.random((120, 50)) < 0.3).astype(float)
    labels = (features[:, 0] > 0).astype(int)
    model = models.fit("random_forest", features, labels)

    rows = explain.permutation_importance(
        model, features, labels, [f"f{i}" for i in range(50)], repeats=2, top_k=3, max_columns=10
    )
    assert "shortlisted to the 10 highest-ranked of 50 columns" in rows[0].method


def test_feature_labels_are_readable_and_never_invented() -> None:
    from drishti.m5_ml import explain

    assert explain.label_for("perm:RECEIVE_SMS") == "permission: RECEIVE_SMS"
    assert explain.label_for("reach:sms.send") == "sink reachable from lifecycle: sms.send"
    # An unmapped family is returned untouched rather than given a made-up description.
    assert explain.label_for("mystery:thing") == "mystery:thing"
    assert explain.label_for("bare") == "bare"


def test_bin_agreement_measures_the_bucket_the_roadmap_names() -> None:
    """PHASE_2 T2.4: of the samples scored ~0.8, roughly 0.8 should be malware."""
    probabilities = np.array([0.80] * 10 + [0.1] * 10)
    labels = np.array([1] * 8 + [0] * 2 + [0] * 10)
    result = calibrate.bin_agreement(labels, probabilities)
    assert result["n"] == 10
    assert result["observed_rate"] == pytest.approx(0.8)
    assert result["within_tolerance"] is True


def test_bin_agreement_flags_a_bucket_that_lies() -> None:
    probabilities = np.array([0.80] * 10)
    labels = np.array([1] * 3 + [0] * 7)
    result = calibrate.bin_agreement(labels, probabilities)
    assert result["observed_rate"] == pytest.approx(0.3)
    assert result["within_tolerance"] is False


def test_bin_agreement_says_when_it_cannot_tell() -> None:
    """An empty or tiny bucket must not report a quiet pass."""
    empty = calibrate.bin_agreement(np.array([1, 0]), np.array([0.1, 0.2]))
    assert empty["n"] == 0 and empty["within_tolerance"] is None
    tiny = calibrate.bin_agreement(np.array([1, 0]), np.array([0.8, 0.8]))
    assert tiny["n"] == 2 and "not informative" in tiny["note"]
