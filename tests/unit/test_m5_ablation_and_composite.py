"""Guards for the two measurements added when the two-epoch leak was removed.

docs/PHASE_2_ML_AND_SCORING.md T2.6, T2.7.

Both of these produce a *plausible number* when they are wrong, which is the only kind
of bug worth a test here:

* A group ablation that reports a positive delta for a column of pure noise turns
  "re-admitted" into "proven useful" without any evidence, which is the exact mistake the
  certificate features were re-extracted to avoid.
* A composite reconstruction that reimplements the scoring formula instead of calling it
  will agree with the pipeline today and disagree silently after the next weight change.
"""

from __future__ import annotations

import numpy as np
import pytest

from drishti.contracts.score import MLPrediction, SeverityBand
from drishti.contracts.static_report import CertificateInfo, StaticReport
from drishti.m5_ml import ablation, composite, dataset
from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION
from drishti.m6_score import engine


def _sample(sha: str, label: int, **features: float) -> dataset.Sample:
    return dataset.Sample(
        sha256=sha,
        label=label,
        split="test",
        time_band="2024-2026",
        dex_date="2024-01-01",
        features=dict(features),
    )


def _planted(n: int, informative: int, noise: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """A matrix whose signal lives in exactly the first `informative` columns."""
    rng = np.random.default_rng(seed)
    labels = np.array([i % 2 for i in range(n)], dtype=int)
    signal = labels[:, None] + rng.normal(0, 0.35, size=(n, informative))
    return np.hstack([signal, rng.normal(0, 1.0, size=(n, noise))]), labels


# ── ablation ─────────────────────────────────────────────────────────────────
def test_ablating_the_only_informative_columns_shows_a_measurable_loss() -> None:
    """Remove the columns that carry the label and the refit must get worse."""
    vocabulary = ["sig:0", "sig:1"] + [f"noise:{i}" for i in range(8)]
    x_train, y_train = _planted(300, 2, 8, seed=1)
    x_test, y_test = _planted(200, 2, 8, seed=2)
    result = ablation.ablate_group(
        "logreg_l2",
        group="sig",
        members=ablation.members_of(vocabulary, "sig:"),
        vocabulary=vocabulary,
        x_train=x_train,
        y_train=y_train,
        x_test=x_test,
        y_test=y_test,
    )
    assert result.pr_auc_with > result.pr_auc_without
    assert result.carries_signal, result.as_dict()


def test_ablating_pure_noise_does_not_claim_signal() -> None:
    """The failure that matters: noise columns must not read as useful.

    `carries_signal` keys on the paired interval, so a delta that is positive by luck
    still reports False — which is the whole point of measuring rather than eyeballing.
    """
    vocabulary = ["sig:0", "sig:1"] + [f"noise:{i}" for i in range(8)]
    x_train, y_train = _planted(300, 2, 8, seed=1)
    x_test, y_test = _planted(200, 2, 8, seed=2)
    result = ablation.ablate_group(
        "logreg_l2",
        group="noise",
        members=ablation.members_of(vocabulary, "noise:"),
        vocabulary=vocabulary,
        x_train=x_train,
        y_train=y_train,
        x_test=x_test,
        y_test=y_test,
    )
    assert not result.carries_signal, result.as_dict()


def test_a_constant_column_is_named_as_constant() -> None:
    """A column that never varies cannot carry signal, and the report must say so."""
    vocabulary = ["sig:0", "sig:1", "flat:always_zero"]
    x_train, y_train = _planted(200, 2, 0, seed=3)
    x_test, y_test = _planted(120, 2, 0, seed=4)
    x_train = np.hstack([x_train, np.zeros((len(x_train), 1))])
    x_test = np.hstack([x_test, np.zeros((len(x_test), 1))])
    result = ablation.ablate_group(
        "logreg_l2",
        group="flat",
        members=["flat:always_zero"],
        vocabulary=vocabulary,
        x_train=x_train,
        y_train=y_train,
        x_test=x_test,
        y_test=y_test,
    )
    assert result.constant_in_train == ["flat:always_zero"]
    assert result.varying_in_train == []
    assert not result.carries_signal


def test_permutation_restores_the_column_it_shuffled() -> None:
    """F3: a loop that forgets to restore measures every later column against a ruin."""
    vocabulary = ["sig:0", "sig:1", "noise:0"]
    x_train, y_train = _planted(200, 2, 1, seed=5)
    x_test, y_test = _planted(150, 2, 1, seed=6)
    before = x_test.copy()
    ablation.ablate_group(
        "logreg_l2",
        group="sig",
        members=["sig:0", "sig:1"],
        vocabulary=vocabulary,
        x_train=x_train,
        y_train=y_train,
        x_test=x_test,
        y_test=y_test,
    )
    assert np.array_equal(before, x_test)


# ── composite reconstruction ─────────────────────────────────────────────────
def test_rule_severity_is_worst_match_not_sum() -> None:
    """Five MEDIUM combinations are not more damning than one CRITICAL one."""
    many_medium = {
        "combo:PERSISTENT_BOOT": 1.0,
        "combo:LOCATION_TRACKING": 1.0,
        "combo:EXTERNAL_STORAGE_EXFIL": 1.0,
    }
    one_critical = {"combo:ACCESSIBILITY_ABUSE": 1.0}
    assert composite.rule_severity_from_features(many_medium) == pytest.approx(0.40)
    assert composite.rule_severity_from_features(one_critical) == pytest.approx(1.0)
    assert composite.rule_severity_from_features({}) == 0.0


def test_reconstructed_g_matches_the_scorers_own_function() -> None:
    """The feature-row path and the StaticReport path must agree, or S is fiction."""
    sample = _sample(
        "a" * 64,
        1,
        **{"combo:OTP_THEFT_SURFACE": 1.0, "combo:ACCESSIBILITY_ABUSE": 1.0},
    )
    static = composite._static_from_features(sample)
    assert engine.rule_severity(static) == composite.rule_severity_from_features(sample.features)
    assert engine.rule_severity(static) == pytest.approx(1.0)


def test_triage_score_equals_the_pure_scorer_on_the_same_inputs() -> None:
    """No local copy of the formula: the row must equal `engine.score` exactly."""
    sample = _sample(
        "b" * 64,
        1,
        **{"combo:OTP_THEFT_SURFACE": 1.0, "drift:has_undeclared_use": 1.0},
    )
    rows = composite.triage_scores([sample], np.array([0.9]), model_version="probe-1")
    static = composite._static_from_features(sample)
    expected = engine.score(
        static=static,
        ml=MLPrediction(
            p_malicious_raw=0.9,
            p_calibrated=0.9,
            model_version="probe-1",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
        ),
        genai=None,
        dynamic=None,
        intel=None,
        yara_severity=engine.rule_severity(static),
    )
    assert rows[0].S == expected.S
    assert rows[0].band == expected.band.value


def test_reachable_ceiling_is_computed_and_leaves_critical_out_of_reach() -> None:
    """G made HIGH reachable on static evidence; CRITICAL still needs more than this.

    The number is computed from the shipped weights rather than written down, so a
    weight change moves it here instead of leaving a stale claim in the paper.
    """
    ceiling = composite.reachable_ceiling()
    assert ceiling >= 65, "HIGH must be reachable from static+ML evidence alone"
    assert ceiling < 85, "CRITICAL must still require intel, behaviour or a detonation"


def test_nothing_is_invented_for_reputation_or_behaviour() -> None:
    """R and B stay absent: no intel ran over the corpus, and no sample was detonated."""
    sample = _sample("c" * 64, 1, **{"combo:ACCESSIBILITY_ABUSE": 1.0})
    rows = composite.triage_scores([sample], np.array([1.0]), model_version="probe-1")
    # 100 * (0.50 * 1.0 + 0.15 * 1.0) with R and D both zero.
    assert rows[0].S == 65
    assert rows[0].band == SeverityBand.HIGH.value


def test_band_metrics_count_the_queue_an_analyst_actually_works() -> None:
    rows = [
        composite.TriageRow("a" * 64, 1, 0.9, 1.0, 90, "CRITICAL"),
        composite.TriageRow("b" * 64, 1, 0.8, 0.7, 70, "HIGH"),
        composite.TriageRow("c" * 64, 0, 0.7, 0.4, 66, "HIGH"),
        composite.TriageRow("d" * 64, 0, 0.1, 0.0, 5, "LOW"),
    ]
    high = composite.band_metrics(rows, SeverityBand.HIGH)
    assert high["flagged"] == 3
    assert high["true_positives"] == 2
    assert high["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert high["recall"] == pytest.approx(1.0)


def test_combo_severity_scale_is_read_from_the_owning_modules() -> None:
    """Every id comes from M2's YAML and every value from M6's table; nothing typed in."""
    scale = composite.combo_severity_scale()
    assert scale["ACCESSIBILITY_ABUSE"] == engine._RULE_SEVERITY["critical"]
    assert set(scale.values()) <= set(engine._RULE_SEVERITY.values())


def test_a_row_with_no_combos_and_no_drift_is_the_probability_alone() -> None:
    """Sanity: with G and D at zero, S is just half the calibrated probability."""
    static = StaticReport(
        sha256="0" * 64,
        package="p",
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
    )
    assert engine.rule_severity(static) == 0.0
    rows = composite.triage_scores([_sample("d" * 64, 0)], np.array([0.6]), model_version="probe-1")
    assert rows[0].S == 30


def test_the_escalators_promotions_are_counted_separately_from_S() -> None:
    """The escalator moves the BAND without moving `S`; the two must not be conflated.

    A summary that reported only the emitted band would charge the escalator's promoted
    benign rows to the score, and one that reported only `S` would hide them entirely.
    """
    rows = [
        composite.TriageRow("a" * 64, 1, 0.9, 1.0, 65, "HIGH", anomaly_escalated=False),
        composite.TriageRow("b" * 64, 0, 0.1, 0.0, 5, "HIGH", anomaly_escalated=True),
        composite.TriageRow("c" * 64, 1, 0.1, 0.0, 5, "HIGH", anomaly_escalated=True),
        composite.TriageRow("d" * 64, 0, 0.1, 0.0, 5, "LOW", anomaly_escalated=False),
        # Flagged, but already MEDIUM on `S` alone — the escalator changed nothing here,
        # and counting it would inflate the escalator's apparent effect.
        composite.TriageRow("e" * 64, 1, 0.9, 0.0, 45, "MEDIUM", anomaly_escalated=True),
    ]
    effect = composite.escalation_effect(rows)
    assert effect == {
        "flagged": 3,
        "promoted_to_high": 2,
        "promoted_malware": 1,
        "promoted_benign": 1,
    }

    summary = composite.summarise(rows)
    # From `S` alone only one row is HIGH; the pipeline emits three.
    assert summary["band_distribution"]["HIGH"]["n"] == 1
    assert summary["band_distribution_after_escalation"]["HIGH"]["n"] == 3
    assert summary["bands"][1]["band"] == "HIGH"
    assert summary["bands"][1]["flagged"] == 1
