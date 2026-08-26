"""Measure what a named group of feature columns is actually worth.

docs/PHASE_2_ML_AND_SCORING.md T2.6.

A feature that *exists* in the vocabulary has not been shown to carry anything. The
certificate columns are the case that forced this module: they were dropped from the
first real run because a two-epoch corpus made their presence a proxy for the label, and
when the corpus was re-extracted end to end they became **testable** — which is not the
same as **useful**. The only way to tell the difference is to refit without them and
measure what changes.

The measurement is a refit, not a column shuffle. Shuffling asks "how much does the
fitted model lean on this column"; refitting asks "would the model be worse if this
column had never existed", which is the question a reader asks of a re-admitted feature.
Both are reported: the refit delta, and permutation importance per column.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from drishti.m5_ml import models
from drishti.m5_ml.dataset import SEED


@dataclass(frozen=True)
class GroupAblation:
    """What one group of columns bought, measured on a held-out split."""

    group: str
    members: list[str]
    constant_in_train: list[str]
    varying_in_train: list[str]
    n_test: int
    n_test_pos: int
    pr_auc_with: float
    pr_auc_without: float
    delta: float
    delta_ci: tuple[float, float]
    roc_auc_with: float
    roc_auc_without: float
    per_feature_importance: list[dict[str, Any]] = field(default_factory=list)

    @property
    def carries_signal(self) -> bool:
        """True only when the paired interval on the delta excludes zero.

        A point estimate above zero is a coin flip dressed up as a finding; on a test
        split of a few hundred rows the interval is the claim.
        """
        low, high = self.delta_ci
        if not np.isfinite(low) or not np.isfinite(high):
            return False
        return low > 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "members": self.members,
            "constant_in_train": self.constant_in_train,
            "varying_in_train": self.varying_in_train,
            "n_test": self.n_test,
            "n_test_pos": self.n_test_pos,
            "pr_auc_with": self.pr_auc_with,
            "pr_auc_without": self.pr_auc_without,
            "delta": self.delta,
            "delta_ci": list(self.delta_ci),
            "roc_auc_with": self.roc_auc_with,
            "roc_auc_without": self.roc_auc_without,
            "carries_signal": self.carries_signal,
            "per_feature_importance": self.per_feature_importance,
        }


def members_of(vocabulary: list[str], prefix: str) -> list[str]:
    """The vocabulary columns in a named group. Sorted, so the report is stable."""
    return sorted(name for name in vocabulary if name.startswith(prefix))


def _paired_delta_ci(
    labels: np.ndarray,
    with_group: np.ndarray,
    without_group: np.ndarray,
    *,
    resamples: int = 2000,
    seed: int = SEED,
) -> tuple[float, float]:
    """Percentile bootstrap on the PAIRED difference in PR-AUC.

    Paired — the same resampled rows score both models — because the two PR-AUCs are
    measured on one test split and are strongly correlated. Bootstrapping them
    independently and differencing the intervals would widen the claim to the point of
    saying nothing, and would be the wrong test.
    """
    from sklearn.metrics import average_precision_score

    if len(labels) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    deltas: list[float] = []
    size = len(labels)
    for _ in range(resamples):
        index = rng.integers(0, size, size)
        y = labels[index]
        if y.min() == y.max():
            continue
        try:
            deltas.append(
                float(average_precision_score(y, with_group[index]))
                - float(average_precision_score(y, without_group[index]))
            )
        except ValueError:
            continue
    if not deltas:
        return (float("nan"), float("nan"))
    return (
        round(float(np.percentile(deltas, 2.5)), 4),
        round(float(np.percentile(deltas, 97.5)), 4),
    )


def ablate_group(
    model_name: str,
    *,
    group: str,
    members: list[str],
    vocabulary: list[str],
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,
    permutation_repeats: int = 5,
) -> GroupAblation:
    """Refit `model_name` with and without `members`, on identical rows and one seed.

    The only variable is the presence of those columns: same split, same seed, same
    hyper-parameters. Whatever moves is what the group is worth on this corpus, and the
    paired interval says whether the move is distinguishable from noise.
    """
    from sklearn.metrics import average_precision_score, roc_auc_score

    keep = [i for i, name in enumerate(vocabulary) if name not in set(members)]
    index_of = {name: i for i, name in enumerate(vocabulary)}

    with_model = models.fit(model_name, x_train, y_train)
    p_with = models.scores(with_model, x_test)
    without_model = models.fit(model_name, x_train[:, keep], y_train)
    p_without = models.scores(without_model, x_test[:, keep])

    pr_with = float(average_precision_score(y_test, p_with))
    pr_without = float(average_precision_score(y_test, p_without))

    # Per-column permutation importance, measured against the model that HAS the group.
    # F3: the column is restored after every repeat — a loop that forgets produces a
    # believable ranking measured against an already-degraded matrix.
    rng = np.random.default_rng(SEED)
    per_feature: list[dict[str, Any]] = []
    for name in members:
        column = index_of.get(name)
        if column is None:
            continue
        drops: list[float] = []
        original = x_test[:, column].copy()
        for _ in range(permutation_repeats):
            shuffled = original.copy()
            rng.shuffle(shuffled)
            x_test[:, column] = shuffled
            drops.append(
                pr_with - float(average_precision_score(y_test, models.scores(with_model, x_test)))
            )
            x_test[:, column] = original
        per_feature.append(
            {
                "feature": name,
                "mean_drop_pr_auc": round(float(np.mean(drops)), 6),
                "nonzero_in_test": int(np.count_nonzero(original)),
            }
        )
    per_feature.sort(key=lambda row: row["mean_drop_pr_auc"], reverse=True)

    train_columns = {name: x_train[:, index_of[name]] for name in members if name in index_of}
    return GroupAblation(
        group=group,
        members=members,
        constant_in_train=sorted(n for n, col in train_columns.items() if col.min() == col.max()),
        varying_in_train=sorted(n for n, col in train_columns.items() if col.min() != col.max()),
        n_test=len(y_test),
        n_test_pos=int((y_test == 1).sum()),
        pr_auc_with=round(pr_with, 4),
        pr_auc_without=round(pr_without, 4),
        delta=round(pr_with - pr_without, 4),
        delta_ci=_paired_delta_ci(y_test, p_with, p_without),
        roc_auc_with=round(float(roc_auc_score(y_test, p_with)), 4),
        roc_auc_without=round(float(roc_auc_score(y_test, p_without)), 4),
        per_feature_importance=per_feature,
    )
