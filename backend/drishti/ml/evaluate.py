"""M5 evaluation — produces the real metrics the paper's §9 asks for.

Given a features CSV (from the isolated extractor) with a `split` column, this trains
on `split == "train"` and evaluates on `split == "test"`, where test samples are strictly
NEWER than train samples. That measures time-split generalisation to unseen malware
families rather than memorisation.

Reported metrics (paper §9.1 priority order):
  precision (malicious), recall (malicious), F1, PR-AUC, ROC-AUC, false-positive rate,
  plus a calibration check (does P_cal=0.8 really mean ~80% precision?).
"""
import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from drishti.ml.features import FEATURE_NAMES
from drishti.ml.train import train_from_dataframe


def calibration_table(y_true, p, bins=5) -> list[dict]:
    """Empirical precision per predicted-probability bucket. If calibration holds,
    `mean_predicted` should track `empirical_positive_rate` (paper §4.6.2)."""
    edges = np.linspace(0.0, 1.0, bins + 1)
    out = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi if hi < 1.0 else p <= 1.0)
        if not m.any():
            continue
        out.append({
            "bucket": f"{lo:.1f}-{hi:.1f}",
            "n": int(m.sum()),
            "mean_predicted": round(float(p[m].mean()), 3),
            "empirical_positive_rate": round(float(np.asarray(y_true)[m].mean()), 3),
        })
    return out


def evaluate_time_split(df, threshold: float = 0.5) -> dict:
    if "split" not in df.columns:
        raise ValueError("features CSV has no `split` column; rebuild the sample list "
                         "with scripts/build_sample_list.py")
    train_df = df[df["split"] == "train"]
    test_df = df[df["split"] == "test"]
    if train_df.empty or test_df.empty:
        raise ValueError(f"need both splits (train={len(train_df)}, test={len(test_df)})")

    clf = train_from_dataframe(train_df)
    X_test = test_df[FEATURE_NAMES].to_numpy(dtype=float)
    y_test = test_df["label"].to_numpy(dtype=int)
    p = clf.model.predict_proba(X_test)[:, 1]
    y_pred = (p >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()

    return {
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "threshold": threshold,
        "precision_malicious": round(float(precision), 4),
        "recall_malicious": round(float(recall), 4),
        "f1_malicious": round(float(f1), 4),
        "pr_auc": round(float(average_precision_score(y_test, p)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, p)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "calibration": calibration_table(y_test, p),
        "classifier": clf,
    }


def format_report(m: dict) -> str:
    lines = [
        "DRISHTI M5 — time-split evaluation on real AndroZoo samples",
        f"  train n={m['n_train']}   test n={m['n_test']} (strictly newer samples)",
        f"  Precision (malicious) : {m['precision_malicious']:.3f}",
        f"  Recall    (malicious) : {m['recall_malicious']:.3f}",
        f"  F1                    : {m['f1_malicious']:.3f}",
        f"  PR-AUC                : {m['pr_auc']:.3f}",
        f"  ROC-AUC               : {m['roc_auc']:.3f}",
        f"  False-positive rate   : {m['false_positive_rate']:.3f}",
        f"  Confusion             : {m['confusion']}",
        "  Calibration (mean_predicted should track empirical rate):",
    ]
    for row in m["calibration"]:
        lines.append(f"    {row['bucket']}  n={row['n']:5d}  "
                     f"pred={row['mean_predicted']:.3f}  actual={row['empirical_positive_rate']:.3f}")
    return "\n".join(lines)
