"""Evaluation figures. Every curve is drawn from an array that was actually measured.

docs/PHASE_2_ML_AND_SCORING.md T2.3/T2.4/T2.6.

There is no code path here that draws a shape from an assumption, a target, or a
remembered number. If the caller has no data for a panel, the panel is not drawn.

Sample sizes are rendered *into* the figures — the legend on the PR curves carries `n`
and the reliability diagram sizes its markers by bin count — because these plots end up
on a slide, detached from the table that would otherwise carry the caveat.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

INK = "#151A21"
MUTED = "#5C6773"
GRID = "#D8DDE4"
#: One stable colour per model, so `xgboost` is the same colour in every figure.
PALETTE: dict[str, str] = {
    "logreg_l2": "#2F6DB5",
    "linear_svm": "#7A4FA3",
    "random_forest": "#1F6B4A",
    "xgboost": "#9A6512",
    "mlp": "#9E3733",
}
ACCENT = "#9A6512"
OK = "#1F6B4A"
BAD = "#9E3733"


def _style(ax: Any, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, color=INK, fontsize=11, pad=10, loc="left")
    ax.set_xlabel(xlabel, color=MUTED, fontsize=9)
    ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
    ax.tick_params(colors=MUTED, labelsize=8)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(GRID)
    ax.grid(True, alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)


def _save(fig: Any, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight", dpi=200)
    plt.close(fig)
    return out


def pr_curves(
    panels: dict[str, list[tuple[str, np.ndarray, np.ndarray, float, int, int]]],
    out: Path,
) -> Path:
    """One panel per split; one curve per model.

    Each panel draws the no-skill baseline at the split's positive prevalence, because a
    PR-AUC of 0.6 is excellent at 9% prevalence and worthless at 50%, and a curve without
    that line invites the reader to compare the two panels directly and be wrong.
    """
    from sklearn.metrics import precision_recall_curve

    fig, axes = plt.subplots(1, len(panels), figsize=(5.4 * len(panels), 4.6), dpi=200)
    if len(panels) == 1:
        axes = [axes]
    for ax, (split, entries) in zip(axes, panels.items(), strict=True):
        prevalence = 0.0
        for name, labels, probabilities, pr_auc, n, n_pos in entries:
            precision, recall, _ = precision_recall_curve(labels, probabilities)
            prevalence = n_pos / n if n else 0.0
            ax.plot(
                recall,
                precision,
                color=PALETTE.get(name, MUTED),
                linewidth=1.7,
                label=f"{name} — PR-AUC {pr_auc:.3f}",
            )
        ax.axhline(
            prevalence,
            color=MUTED,
            linestyle="--",
            linewidth=1,
            label=f"no-skill baseline ({prevalence:.3f})",
        )
        n = entries[0][4] if entries else 0
        n_pos = entries[0][5] if entries else 0
        _style(
            ax,
            f"{split} — n={n} ({n_pos} malware, {n - n_pos} benign)",
            "recall",
            "precision",
        )
        ax.set_ylim(0, 1.02)
        ax.set_xlim(0, 1.0)
        ax.legend(frameon=False, fontsize=7.5, loc="lower left")
    return _save(fig, out)


#: (model name, random PR-AUC, random 95% CI, time PR-AUC, time 95% CI)
SplitGapRow = tuple[str, float, tuple[float, float], float, tuple[float, float]]


def split_gap(
    rows: list[SplitGapRow],
    out: Path,
    *,
    n_random: int,
    n_time: int,
    n_random_pos: int,
    n_time_pos: int,
) -> Path:
    """Random-split vs time-split PR-AUC per model, with the bootstrap intervals.

    The gap is the finding, so it gets its own figure. The error bars are what stop a
    reader concluding that a 0.02 difference between two models is real.
    """
    names = [row[0] for row in rows]
    x = np.arange(len(names))
    random_series = [(row[1], row[2]) for row in rows]
    time_series = [(row[3], row[4]) for row in rows]
    fig, ax = plt.subplots(figsize=(max(6.2, 1.5 * len(names)), 4.4), dpi=200)
    for offset, series, colour, label in (
        (-0.19, random_series, ACCENT, f"random split (n={n_random}, {n_random_pos} malware)"),
        (0.19, time_series, OK, f"time split (n={n_time}, {n_time_pos} malware)"),
    ):
        values = np.array([point for point, _ in series], dtype=np.float64)
        lows = np.array([interval[0] for _, interval in series], dtype=np.float64)
        highs = np.array([interval[1] for _, interval in series], dtype=np.float64)
        errors = np.vstack([np.clip(values - lows, 0, None), np.clip(highs - values, 0, None)])
        ax.bar(x + offset, values, 0.36, color=colour, label=label)
        ax.errorbar(
            x + offset, values, yerr=errors, fmt="none", ecolor=INK, elinewidth=1, capsize=3
        )
        for xi, value in zip(x + offset, values, strict=True):
            ax.text(xi, value + 0.015, f"{value:.3f}", ha="center", fontsize=7, color=INK)
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=8)
    ax.set_ylim(0, 1.12)
    _style(ax, "PR-AUC: random split vs time split (95% bootstrap CI)", "", "PR-AUC")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    return _save(fig, out)


def reliability_diagram(
    before: list[dict[str, float]],
    after: list[dict[str, float]],
    out: Path,
    *,
    method: str,
    brier_before: float,
    brier_after: float,
    n: int,
    n_pos: int,
) -> Path:
    """Predicted probability against observed frequency, before and after calibration.

    Marker area is proportional to the number of samples in the bin, so a point resting
    on four samples cannot masquerade as a point resting on four hundred.
    """
    fig, ax = plt.subplots(figsize=(5.4, 5.0), dpi=200)
    ax.plot([0, 1], [0, 1], "--", color=MUTED, linewidth=1, label="perfectly calibrated")
    for rows, colour, label in (
        (before, ACCENT, f"raw (Brier {brier_before:.4f})"),
        (after, OK, f"{method} (Brier {brier_after:.4f})"),
    ):
        points = [row for row in rows if row["n"] >= 3]
        if not points:
            continue
        xs = [row["mean_predicted"] for row in points]
        ys = [row["observed_frequency"] for row in points]
        counts = np.array([row["n"] for row in points], dtype=float)
        ax.plot(xs, ys, "-", color=colour, linewidth=1.5, label=label, zorder=2)
        ax.scatter(
            xs,
            ys,
            s=18 + 120 * counts / counts.max(),
            color=colour,
            edgecolor="white",
            linewidth=0.6,
            zorder=3,
        )
    _style(
        ax,
        f"Reliability on the test split — n={n} ({n_pos} malware)",
        "predicted probability",
        "observed frequency",
    )
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    ax.text(
        0.98,
        0.02,
        "marker area ∝ samples in bin; bins under 3 omitted",
        transform=ax.transAxes,
        ha="right",
        fontsize=7,
        color=MUTED,
    )
    return _save(fig, out)


def importance(entries: list[tuple[str, float]], out: Path, *, title: str, xlabel: str) -> Path:
    """Horizontal bars, most important at the top, named so a human can read them."""
    entries = list(reversed(entries))
    fig, ax = plt.subplots(figsize=(7.0, 0.28 * len(entries) + 1.4), dpi=200)
    values = [value for _, value in entries]
    colours = [OK if value >= 0 else BAD for value in values]
    ax.barh(range(len(entries)), values, color=colours)
    ax.set_yticks(range(len(entries)))
    ax.set_yticklabels([name for name, _ in entries], fontsize=7.5)
    _style(ax, title, xlabel, "")
    return _save(fig, out)


def corpus_composition(bands: dict[str, dict[str, int]], out: Path, *, total: int) -> Path:
    """What the corpus actually contains, per time band. The denominator for everything."""
    names = list(bands)
    x = np.arange(len(names))
    malware = [bands[b]["malware"] for b in names]
    benign = [bands[b]["benign"] for b in names]
    fig, ax = plt.subplots(figsize=(max(6.4, 1.6 * len(names)), 3.8), dpi=200)
    ax.bar(x - 0.2, malware, 0.4, label="malware", color=BAD)
    ax.bar(x + 0.2, benign, 0.4, label="benign", color=OK)
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=8)
    for i, (m, b) in enumerate(zip(malware, benign, strict=True)):
        ax.text(i - 0.2, m, str(m), ha="center", va="bottom", fontsize=7, color=INK)
        ax.text(i + 0.2, b, str(b), ha="center", va="bottom", fontsize=7, color=INK)
    _style(ax, f"Extracted corpus — {total} samples with real M2 features", "time band", "samples")
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, out)


def anomaly_distribution(
    scores_benign: np.ndarray, scores_malware: np.ndarray, out: Path, *, escalate_at: float
) -> Path:
    """Where the escalation threshold actually falls on the two populations.

    Drawn so the cost is visible: everything right of the line is a human review, and the
    benign mass right of the line is what that costs per thousand clean apps.
    """
    fig, ax = plt.subplots(figsize=(6.4, 4.0), dpi=200)
    bins = np.linspace(0, 1, 41).tolist()
    ax.hist(scores_benign, bins=bins, color=OK, alpha=0.7, label=f"benign (n={len(scores_benign)})")
    ax.hist(
        scores_malware, bins=bins, color=BAD, alpha=0.7, label=f"malware (n={len(scores_malware)})"
    )
    ax.axvline(escalate_at, color=INK, linestyle="--", linewidth=1.2)
    ax.text(
        escalate_at, ax.get_ylim()[1] * 0.92, f" escalate ≥ {escalate_at}", fontsize=7.5, color=INK
    )
    _style(ax, "IsolationForest novelty score on the test split", "normalised novelty", "samples")
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, out)


def learning_curve(
    points: list[dict[str, Any]],
    out: Path,
    *,
    model_name: str,
    n_test: int,
    n_test_malware: int,
) -> Path:
    """Time-split PR-AUC against training-set size, with the test split held fixed.

    Answers the question a truncated extraction run actually raises: is the number still
    climbing? A curve that has flattened says more corpus would not have helped; one that
    has not says the reported figure is a floor, not a ceiling. Each point is annotated
    with its training n so nobody reads the shape without the sample sizes.
    """
    xs = [point["n_train"] for point in points]
    ys = [point["pr_auc_time_split"] for point in points]
    fig, ax = plt.subplots(figsize=(6.4, 4.2), dpi=200)
    ax.plot(xs, ys, "o-", color=PALETTE.get(model_name, ACCENT), linewidth=1.8, markersize=5)
    for x, y, point in zip(xs, ys, points, strict=True):
        ax.annotate(
            f"{y:.3f}\nn={x} ({point['n_train_malware']} mal)",
            (x, y),
            textcoords="offset points",
            xytext=(0, 9),
            ha="center",
            fontsize=6.5,
            color=MUTED,
        )
    _style(
        ax,
        f"{model_name}: time-split PR-AUC vs training size "
        f"(test held fixed at n={n_test}, {n_test_malware} malware)",
        "training samples",
        "PR-AUC on the time-split test set",
    )
    ax.set_ylim(min(ys) - 0.08, min(1.04, max(ys) + 0.12))
    return _save(fig, out)
