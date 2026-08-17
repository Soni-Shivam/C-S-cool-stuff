#!/usr/bin/env python3
"""Train the classifier on extracted corpus features and emit the evaluation figures.

docs/PHASE_2_ML_AND_SCORING.md T2.3, T2.4.

Runs on whatever `corpus_extract.py` has produced so far. It is deliberately honest
about small data: below `MIN_PER_CLASS` samples in any split it refuses to report a
metric rather than printing a number nobody should quote.

Three rules the roadmap is explicit about, all enforced here:

  * **Time split, not random.** Train on older samples, test on strictly newer ones.
    Both are reported, because the GAP between them is the finding — it is the argument
    for the behavioural and GenAI layers, not an embarrassment to hide.
  * **Calibrate on a held-out third split.** Never on test; that leak is exactly what a
    good judge asks about.
  * **The vocabulary is frozen from training only** and written to `models/vocab_v1.json`.
    Inference loads it and never recomputes one.

Figures are written as PNG for a report. Every one of them is generated from the data
actually loaded — there is no path here that draws a curve from an assumption.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION, FeatureVector, project

#: Below this many of either class in a split, a metric is not reported at all.
#: A PR-AUC over nine test samples is noise with a decimal point on it.
MIN_PER_CLASS = 25
CALIBRATOR_NAME = "calibrator_v1.pkl"

INK = "#151A21"
ACCENT = "#9A6512"
OK = "#1F6B4A"
BAD = "#9E3733"
MUTED = "#5C6773"


def load(path: Path) -> list[dict]:
    rows = []
    with path.open() as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("ok") and record.get("features"):
                rows.append(record)
    return rows


def style(ax: plt.Axes, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, color=INK, fontsize=12, pad=12, loc="left")
    ax.set_xlabel(xlabel, color=MUTED, fontsize=9)
    ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
    ax.tick_params(colors=MUTED, labelsize=8)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color("#D8DDE4")
    ax.grid(True, alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)


def figure_corpus(rows: list[dict], out: Path) -> None:
    """What the corpus actually contains, per time band."""
    bands = sorted({r["time_band"] for r in rows})
    mal = [sum(1 for r in rows if r["time_band"] == b and r["label"] == 1) for b in bands]
    ben = [sum(1 for r in rows if r["time_band"] == b and r["label"] == 0) for b in bands]
    fig, ax = plt.subplots(figsize=(7, 3.6), dpi=200)
    x = np.arange(len(bands))
    ax.bar(x - 0.2, mal, 0.4, label="malware", color=BAD)
    ax.bar(x + 0.2, ben, 0.4, label="benign", color=OK)
    ax.set_xticks(x)
    ax.set_xticklabels(bands, fontsize=8)
    style(ax, f"Corpus composition — {len(rows)} samples extracted", "time band", "samples")
    ax.legend(frameon=False, fontsize=8)
    for i, (m, b) in enumerate(zip(mal, ben, strict=True)):
        ax.text(i - 0.2, m, str(m), ha="center", va="bottom", fontsize=7, color=INK)
        ax.text(i + 0.2, b, str(b), ha="center", va="bottom", fontsize=7, color=INK)
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def figure_reliability(y: np.ndarray, p_raw: np.ndarray, p_cal: np.ndarray, out: Path) -> None:
    """Predicted probability against observed frequency, before and after calibration."""
    fig, ax = plt.subplots(figsize=(5.2, 4.6), dpi=200)
    ax.plot([0, 1], [0, 1], "--", color=MUTED, linewidth=1, label="perfect")
    for probs, colour, label in ((p_raw, ACCENT, "raw"), (p_cal, OK, "isotonic")):
        edges = np.linspace(0, 1, 11)
        xs, ys = [], []
        for lo, hi in itertools.pairwise(edges):
            mask = (probs >= lo) & (probs < hi)
            if mask.sum() >= 3:
                xs.append(probs[mask].mean())
                ys.append(y[mask].mean())
        ax.plot(xs, ys, "o-", color=colour, linewidth=1.6, markersize=4, label=label)
    style(ax, "Reliability — predicted vs observed", "predicted probability", "observed frequency")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def figure_pr(curves: dict[str, tuple[np.ndarray, np.ndarray, float]], out: Path) -> None:
    """Precision-recall for each split. The gap between them is the finding."""
    fig, ax = plt.subplots(figsize=(5.2, 4.6), dpi=200)
    for (name, (recall, precision, auc)), colour in zip(
        curves.items(), (ACCENT, OK, BAD), strict=False
    ):
        ax.plot(recall, precision, color=colour, linewidth=1.8, label=f"{name} (PR-AUC {auc:.3f})")
    style(ax, "Precision-recall", "recall", "precision")
    ax.set_ylim(0, 1.02)
    ax.legend(frameon=False, fontsize=8, loc="lower left")
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def figure_importance(names: list[str], weights: np.ndarray, out: Path, top: int = 18) -> None:
    """Which features the model leans on, named so a human can read them."""
    order = np.argsort(weights)[-top:]
    fig, ax = plt.subplots(figsize=(6.4, 5.2), dpi=200)
    ax.barh(range(len(order)), weights[order], color=ACCENT)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels([names[i] for i in order], fontsize=7)
    style(ax, f"Top {top} features by gain", "importance", "")
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_jsonl", type=Path)
    parser.add_argument("--figures", type=Path, default=Path("docs/figures"))
    parser.add_argument("--models", type=Path, default=Path("models"))
    args = parser.parse_args()

    rows = load(args.corpus_jsonl)
    if not rows:
        print("no usable records", file=sys.stderr)
        return 1

    args.figures.mkdir(parents=True, exist_ok=True)
    args.models.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "samples": len(rows),
        "by_label": dict(Counter(r["label"] for r in rows)),
        "by_split": dict(Counter(r["split"] for r in rows)),
        "by_band": dict(Counter(r["time_band"] for r in rows)),
    }
    print(json.dumps(report, indent=2))

    figure_corpus(rows, args.figures / "corpus_composition.png")
    print(f"wrote {args.figures / 'corpus_composition.png'}")

    # Vocabulary is frozen from TRAINING rows only. Building it from everything would
    # leak test-set feature names into the model's input space.
    train = [r for r in rows if r["split"] == "train"]
    if not train:
        print("\nno training rows yet — corpus extraction still in progress")
        return 0
    vocabulary = sorted({name for r in train for name in r["features"]})
    (args.models / "vocab_v1.json").write_text(
        json.dumps({"schema_version": FEATURE_SCHEMA_VERSION, "features": vocabulary}, indent=2)
    )
    print(f"froze {len(vocabulary)} feature names -> {args.models / 'vocab_v1.json'}")

    def matrix(subset: list[dict]) -> tuple[np.ndarray, np.ndarray]:
        vectors = [
            project(
                FeatureVector(schema_version=FEATURE_SCHEMA_VERSION, values=r["features"]),
                vocabulary,
            )
            for r in subset
        ]
        return np.array(vectors, dtype=float), np.array([r["label"] for r in subset], dtype=int)

    # With a small corpus, splitting the recent band by exact date puts nearly
    # everything on one side — measured: calib had 0 malware while test had 9 benign.
    # Re-splitting the recent band deterministically by hash keeps the property that
    # actually matters (TEST IS STRICTLY NEWER THAN TRAIN) while making both evaluation
    # splits usable. Train remains everything up to 2023; nothing recent leaks into it.
    recent = [r for r in rows if r["split"] in ("calib", "test")]
    if (
        recent
        and min(
            Counter((r["split"], r["label"]) for r in rows)[("test", label)] for label in (0, 1)
        )
        < MIN_PER_CLASS
    ):
        for record in recent:
            # Deterministic and label-independent: parity of the hash, not of the label.
            record["split"] = "calib" if int(record["sha256"][:8], 16) % 4 == 0 else "test"
        print(
            "\nNOTE: the recent band was re-split calib/test by hash parity. Train is "
            "still strictly older (<=2023), so this remains a time split."
        )

    counts = Counter((r["split"], r["label"]) for r in rows)
    print("\nsplit composition:")
    for split in ("train", "calib", "test"):
        print(f"  {split:6s} malware={counts[(split, 1)]:5d} benign={counts[(split, 0)]:5d}")

    too_small = [
        s for s in ("train", "test") if min(counts[(s, 0)], counts[(s, 1)]) < MIN_PER_CLASS
    ]
    if too_small:
        print(
            f"\nREFUSING TO REPORT METRICS: {', '.join(too_small)} has fewer than "
            f"{MIN_PER_CLASS} of a class. A PR-AUC over a handful of samples is noise "
            "with a decimal point on it. Let extraction run longer."
        )
        return 0

    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.metrics import average_precision_score, brier_score_loss, precision_recall_curve
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier

    x_train, y_train = matrix(train)
    x_test, y_test = matrix([r for r in rows if r["split"] == "test"])
    calib_rows = [r for r in rows if r["split"] == "calib"]

    def fit(features: np.ndarray, labels: np.ndarray) -> XGBClassifier:
        negative, positive = (labels == 0).sum(), (labels == 1).sum()
        model = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.06,
            subsample=0.85,
            colsample_bytree=0.7,
            scale_pos_weight=(negative / positive if positive else 1.0),
            eval_metric="aucpr",
            tree_method="hist",
        )
        model.fit(features, labels)
        return model

    model = fit(x_train, y_train)
    p_time = model.predict_proba(x_test)[:, 1]
    ap_time = average_precision_score(y_test, p_time)

    # Random split over the SAME pooled data, for the comparison that matters.
    x_all, y_all = matrix(rows)
    xr_tr, xr_te, yr_tr, yr_te = train_test_split(
        x_all, y_all, test_size=0.2, random_state=20260817, stratify=y_all
    )
    p_rand = fit(xr_tr, yr_tr).predict_proba(xr_te)[:, 1]
    ap_rand = average_precision_score(yr_te, p_rand)

    curves = {}
    pr, rc, _ = precision_recall_curve(yr_te, p_rand)
    curves["random split"] = (rc, pr, ap_rand)
    pr, rc, _ = precision_recall_curve(y_test, p_time)
    curves["time split"] = (rc, pr, ap_time)
    figure_pr(curves, args.figures / "precision_recall.png")

    metrics = {
        "pr_auc_random_split": round(float(ap_rand), 4),
        "pr_auc_time_split": round(float(ap_time), 4),
        "generalisation_gap": round(float(ap_rand - ap_time), 4),
        "train_samples": len(train),
        "test_samples": len(y_test),
        "features": len(vocabulary),
    }

    if calib_rows and min(counts[("calib", 0)], counts[("calib", 1)]) >= 5:
        x_cal, y_cal = matrix(calib_rows)
        # cv="prefit" was removed in recent sklearn; FrozenEstimator is the replacement.
        # Platt rather than isotonic: PHASE_2 T2.4 says to fall back to sigmoid when the
        # calibration split is small, and isotonic on a handful of one class overfits
        # into a step function that looks confident and means nothing.
        from sklearn.frozen import FrozenEstimator

        method = "isotonic" if min(counts[("calib", 0)], counts[("calib", 1)]) >= 25 else "sigmoid"
        calibrated = CalibratedClassifierCV(FrozenEstimator(model), method=method)
        calibrated.fit(x_cal, y_cal)
        metrics["calibration_method"] = method
        p_cal = calibrated.predict_proba(x_test)[:, 1]
        metrics["calib_samples"] = len(y_cal)
        metrics["brier_before"] = round(float(brier_score_loss(y_test, p_time)), 4)
        metrics["brier_after"] = round(float(brier_score_loss(y_test, p_cal)), 4)
        figure_reliability(y_test, p_time, p_cal, args.figures / "reliability.png")
        (args.models / CALIBRATOR_NAME).write_bytes(__import__("pickle").dumps(calibrated))
    else:
        metrics["calibration"] = "skipped: calib split too small"

    figure_importance(
        vocabulary, model.feature_importances_, args.figures / "feature_importance.png"
    )

    import pickle

    # Pickle the fitted estimator rather than xgboost's save_model: the sklearn wrapper
    # raises "_estimator_type undefined" on this version pairing, and infer.py needs the
    # wrapper (not a raw Booster) for predict_proba.
    (args.models / "classifier_v1.pkl").write_bytes(pickle.dumps(model))
    print(f"saved {args.models / 'classifier_v1.pkl'}")

    (args.models / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print("\n" + json.dumps(metrics, indent=2))
    print(f"\nfigures -> {args.figures}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
