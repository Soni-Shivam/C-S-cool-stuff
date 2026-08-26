"""Metrics that state their own sample size, and never hide a small one.

docs/PHASE_2_ML_AND_SCORING.md T2.3.

Every number this module produces carries `n`, `n_pos` and `n_neg`, and the two ranking
metrics carry a bootstrap 95% interval. That is not decoration: the honest time-split
test set for this corpus has fewer than a hundred malware rows, and a PR-AUC over ninety
positives has an interval wide enough to change the conclusion. A point estimate printed
without it would be the single most misleading thing in the report.

PR-AUC is primary. ROC-AUC is reported because everyone asks for it, but on a test split
that is ~9% positive it flatters every model roughly equally and discriminates between
them poorly — precision-recall does not.

**Thresholds are never chosen on test.** `choose_threshold` runs on the calibration
split; test only ever sees a threshold that was already fixed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np

from drishti.m5_ml.dataset import SEED

#: The operating point the report quotes. 90% recall is the triage-desk framing: "if we
#: insist on catching nine in ten, how much benign traffic must an analyst wade through?"
TARGET_RECALL = 0.90

#: Bootstrap resamples for the confidence intervals. 2000 is enough for a 95% interval to
#: be stable to ~0.005 and cheap enough to run for every model on every split.
BOOTSTRAP_RESAMPLES = 2000


@dataclass
class Metrics:
    """One model, one split, one threshold — with the n that makes it interpretable."""

    split: str
    model: str
    n: int
    n_pos: int
    n_neg: int
    prevalence: float
    pr_auc: float
    pr_auc_ci: tuple[float, float]
    roc_auc: float
    roc_auc_ci: tuple[float, float]
    threshold: float
    threshold_source: str
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    tn: int
    fn: int
    fp_rate_at_target_recall: float | None
    precision_at_target_recall: float | None
    threshold_at_target_recall: float | None
    target_recall: float = TARGET_RECALL
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def baseline_pr_auc(self) -> float:
        """A random ranker's PR-AUC is the positive prevalence. Quote a lift, not an AUC."""
        return self.prevalence


def _bootstrap_ci(
    labels: np.ndarray,
    probabilities: np.ndarray,
    metric: Any,
    *,
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = SEED,
) -> tuple[float, float]:
    """Percentile bootstrap over samples, stratified implicitly by resampling rows.

    Resamples that lose an entire class are skipped rather than scored: the metric is
    undefined there, and substituting 0 or 1 would drag the interval toward whichever
    end happened to be degenerate.
    """
    if len(labels) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    values: list[float] = []
    size = len(labels)
    for _ in range(resamples):
        index = rng.integers(0, size, size)
        y = labels[index]
        if y.min() == y.max():
            continue
        try:
            values.append(float(metric(y, probabilities[index])))
        except ValueError:
            continue
    if not values:
        return (float("nan"), float("nan"))
    return (
        round(float(np.percentile(values, 2.5)), 4),
        round(float(np.percentile(values, 97.5)), 4),
    )


def fp_rate_at_recall(
    labels: np.ndarray, probabilities: np.ndarray, target: float = TARGET_RECALL
) -> tuple[float | None, float | None, float | None]:
    """(false-positive rate, precision, threshold) at the lowest threshold reaching `target`.

    Returns `(None, None, None)` when no threshold reaches the target recall — which
    happens, and printing a fabricated 1.0 instead would claim a capability the model
    does not have.
    """
    positives = labels == 1
    negatives = ~positives
    n_pos, n_neg = int(positives.sum()), int(negatives.sum())
    if n_pos == 0 or n_neg == 0:
        return (None, None, None)
    # Walk thresholds from permissive to strict; the first that still meets the target
    # recall is the one an operator would pick.
    order = np.argsort(-probabilities, kind="stable")
    sorted_labels = labels[order]
    sorted_probabilities = probabilities[order]
    true_positives = np.cumsum(sorted_labels == 1)
    false_positives = np.cumsum(sorted_labels == 0)
    recalls = true_positives / n_pos
    reached = np.flatnonzero(recalls >= target)
    if reached.size == 0:
        return (None, None, None)
    cut = int(reached[0])
    # Extend across ties. An operator sets a THRESHOLD, not a row count: everything
    # scoring at least that value is flagged, including rows the sort happened to place
    # after the cut. Stopping mid-tie reports a false-positive rate the deployed
    # threshold would never actually achieve — always an optimistic one.
    threshold = float(sorted_probabilities[cut])
    flagged = int(np.count_nonzero(sorted_probabilities >= threshold))
    cut = max(cut, flagged - 1)
    fp_rate = float(false_positives[cut] / n_neg)
    predicted_positive = cut + 1
    precision = float(true_positives[cut] / predicted_positive)
    return (
        round(fp_rate, 6),
        round(precision, 6),
        round(threshold, 6),
    )


def choose_threshold(labels: np.ndarray, probabilities: np.ndarray) -> tuple[float, str]:
    """Pick an operating threshold on a NON-TEST split, by maximising F1.

    Falls back to 0.5 when the split has one class or too few positives to mean anything;
    the fallback is reported in `threshold_source` so nobody reads a default as a choice.
    """
    positives = int((labels == 1).sum())
    if positives < 5 or positives == len(labels):
        return 0.5, f"default 0.5 (calibration split had {positives} positives — too few to tune)"
    from sklearn.metrics import precision_recall_curve

    precision, recall, thresholds = precision_recall_curve(labels, probabilities)
    # precision_recall_curve returns one more point than thresholds; drop the last.
    f1 = np.divide(
        2 * precision[:-1] * recall[:-1],
        precision[:-1] + recall[:-1],
        out=np.zeros_like(precision[:-1]),
        where=(precision[:-1] + recall[:-1]) > 0,
    )
    if f1.size == 0:
        return 0.5, "default 0.5 (empty PR curve)"
    best = int(np.argmax(f1))
    return float(thresholds[best]), f"max-F1 on the calibration split (n={len(labels)})"


def evaluate(
    *,
    model_name: str,
    split_name: str,
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
    threshold_source: str,
    with_ci: bool = True,
) -> Metrics:
    """Score one model on one split. Never selects anything — selection happens elsewhere."""
    from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

    labels = np.asarray(labels, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    n_pos, n_neg = int((labels == 1).sum()), int((labels == 0).sum())
    notes: list[str] = []
    if n_pos == 0 or n_neg == 0:
        notes.append("split contains a single class — ranking metrics are undefined")
        pr_auc = roc_auc = float("nan")
        pr_ci = roc_ci = (float("nan"), float("nan"))
    else:
        pr_auc = float(average_precision_score(labels, probabilities))
        roc_auc = float(roc_auc_score(labels, probabilities))
        pr_ci = (
            _bootstrap_ci(labels, probabilities, average_precision_score)
            if with_ci
            else (
                float("nan"),
                float("nan"),
            )
        )
        roc_ci = (
            _bootstrap_ci(labels, probabilities, roc_auc_score)
            if with_ci
            else (
                float("nan"),
                float("nan"),
            )
        )
    if 0 < n_pos < 30:
        notes.append(f"only {n_pos} positive rows: read the interval, not the point estimate")

    predicted = (probabilities >= threshold).astype(int)
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in matrix.ravel())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr_at_target, precision_at_target, threshold_at_target = fp_rate_at_recall(
        labels, probabilities
    )

    return Metrics(
        split=split_name,
        model=model_name,
        n=len(labels),
        n_pos=n_pos,
        n_neg=n_neg,
        prevalence=round(n_pos / len(labels), 6) if len(labels) else 0.0,
        pr_auc=round(pr_auc, 4),
        pr_auc_ci=pr_ci,
        roc_auc=round(roc_auc, 4),
        roc_auc_ci=roc_ci,
        threshold=round(float(threshold), 6),
        threshold_source=threshold_source,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        fp_rate_at_target_recall=fpr_at_target,
        precision_at_target_recall=precision_at_target,
        threshold_at_target_recall=threshold_at_target,
        notes=notes,
    )


def markdown_table(rows: list[Metrics]) -> str:
    """The comparison table, exactly as it appears in ML_RESULTS.md.

    `n` is a column, not a footnote, because the whole point is that the time-split
    numbers rest on far fewer positives than the random-split ones.
    """
    header = (
        "| model | split | n | n_pos | n_neg | PR-AUC | PR-AUC 95% CI | ROC-AUC | "
        "ROC-AUC 95% CI | P | R | F1 | TP | FP | TN | FN | FPR@90%R |\n"
        "|---|---|---:|---:|---:|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    )
    lines = []
    for row in rows:
        fpr = (
            f"{row.fp_rate_at_target_recall:.4f}"
            if row.fp_rate_at_target_recall is not None
            else "n/a"
        )
        lines.append(
            f"| `{row.model}` | {row.split} | {row.n} | {row.n_pos} | {row.n_neg} | "
            f"{row.pr_auc:.4f} | [{row.pr_auc_ci[0]:.4f}, {row.pr_auc_ci[1]:.4f}] | "
            f"{row.roc_auc:.4f} | [{row.roc_auc_ci[0]:.4f}, {row.roc_auc_ci[1]:.4f}] | "
            f"{row.precision:.4f} | {row.recall:.4f} | {row.f1:.4f} | "
            f"{row.tp} | {row.fp} | {row.tn} | {row.fn} | {fpr} |"
        )
    return header + "\n".join(lines) + "\n"
