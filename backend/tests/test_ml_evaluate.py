"""Verify the real-data training + time-split evaluation path works, using a synthetic
features table shaped exactly like the extractor's output CSV (no APKs, no network)."""
import numpy as np
import pandas as pd
import pytest

from drishti.ml.evaluate import calibration_table, evaluate_time_split
from drishti.ml.features import FEATURE_NAMES
from drishti.ml.train import _sample_feature_dict
from drishti.ml.features import to_vector


def _features_table(n_per_class=120) -> pd.DataFrame:
    rng = np.random.default_rng(7)
    rows = []
    for split in ("train", "test"):
        for label in (1, 0):
            for _ in range(n_per_class):
                feats = _sample_feature_dict(rng, malicious=bool(label))
                row = dict(zip(FEATURE_NAMES, to_vector(feats)))
                row["label"] = label
                row["split"] = split
                rows.append(row)
    return pd.DataFrame(rows)


def test_evaluate_time_split_produces_metrics():
    m = evaluate_time_split(_features_table())
    assert m["n_train"] > 0 and m["n_test"] > 0
    for k in ("precision_malicious", "recall_malicious", "pr_auc", "roc_auc"):
        assert 0.0 <= m[k] <= 1.0
    # signal is learnable, so this must beat coin-flipping
    assert m["roc_auc"] > 0.7
    assert set(m["confusion"]) == {"tn", "fp", "fn", "tp"}
    assert m["calibration"]


def test_evaluate_requires_split_column():
    df = _features_table(20).drop(columns=["split"])
    with pytest.raises(ValueError, match="split"):
        evaluate_time_split(df)


def test_calibration_table_tracks_truth():
    # perfectly calibrated toy input: predictions equal the true rate
    y = np.array([0, 0, 1, 1, 1, 1])
    p = np.array([0.1, 0.1, 0.9, 0.9, 0.9, 0.9])
    rows = calibration_table(y, p)
    lo = next(r for r in rows if r["bucket"].startswith("0.0"))
    hi = next(r for r in rows if r["bucket"].startswith("0.8"))
    assert lo["empirical_positive_rate"] == 0.0
    assert hi["empirical_positive_rate"] == 1.0
