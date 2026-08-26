"""Per-sample and global feature attribution, labelled with the method that produced it.

docs/PHASE_2_ML_AND_SCORING.md T2.6.

The report cites the top features behind a verdict, so the attribution has to be real and
it has to say what it is. Two methods, and the difference is disclosed rather than
smoothed over:

  * **SHAP** (`TreeExplainer` for the tree models, `LinearExplainer` for the linear ones)
    — additive, signed, per-sample contributions.
  * **Permutation importance** — measured by degrading the model on real data, global
    rather than per-sample. Honest, slower, and the only option for the MLP.

`attribution_method` travels with every result. A bar chart labelled "SHAP" that is
actually coefficient magnitude is a small lie that a technical reader will catch, and it
would undermine the one part of the pipeline whose entire purpose is being checkable.

Feature names are already human-readable — `perm:RECEIVE_SMS`, not `f_0142` — because
`features.extract` emits a named sparse mapping. `label_for` only prettifies them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from drishti.m5_ml.dataset import SEED

#: How many contributions the ledger node and the UI panel carry. Ten is the roadmap's
#: number and about as many as a reader will actually look at.
TOP_K = 10

#: Hard cap on model evaluations for the model-agnostic permutation explainer. Its
#: default is 2*n_features+1 per sample, which on a few-thousand-column vector makes one
#: explanation the slowest thing in the job.
MAX_PERMUTATION_EVALS = 800

#: Rows sampled as the SHAP background distribution. The full training matrix makes
#: KernelExplainer intractable and buys nothing for the tree explainers.
BACKGROUND_ROWS = 200

_FAMILY_LABELS: dict[str, str] = {
    "perm": "permission",
    "combo": "permission combination",
    "component": "component",
    "intent": "intent surface",
    "sink": "sink present",
    "reach": "sink reachable from lifecycle",
    "api": "suspicious API",
    "url": "outbound surface",
    "archive": "packaging",
    "cert": "certificate",
    "drift": "over-privilege drift",
    "manifest": "manifest hygiene",
}


@dataclass
class Attribution:
    """One feature's contribution to one prediction (or to the model, if global)."""

    feature: str
    value: float
    weight: float
    method: str

    @property
    def direction(self) -> str:
        return "+" if self.weight >= 0 else "-"


def label_for(feature: str) -> str:
    """`perm:RECEIVE_SMS` -> `permission: RECEIVE_SMS`. Never invents a name it cannot map."""
    family, _, rest = feature.partition(":")
    friendly = _FAMILY_LABELS.get(family)
    return f"{friendly}: {rest}" if friendly and rest else feature


class Explainer:
    """Wraps whichever attribution method this model and this environment support."""

    def __init__(self, model: Any, background: np.ndarray, vocabulary: list[str]) -> None:
        self.model = model
        self.vocabulary = vocabulary
        self.method = "none"
        self._shap: Any = None
        self._max_evals: int | None = None
        self._fallback_weights: np.ndarray | None = None
        self._build(background)

    def _build(self, background: np.ndarray) -> None:
        inner = self.model
        if hasattr(self.model, "named_steps"):
            inner = self.model.named_steps.get("clf", self.model)
        try:
            import shap
        except Exception:
            self._build_fallback()
            return

        rng = np.random.default_rng(SEED)
        if len(background) > BACKGROUND_ROWS:
            background = background[rng.choice(len(background), BACKGROUND_ROWS, replace=False)]
        try:
            if (hasattr(inner, "feature_importances_") and hasattr(inner, "get_booster")) or (
                hasattr(inner, "estimators_") and hasattr(inner, "feature_importances_")
            ):
                self._shap = shap.TreeExplainer(inner)
                self.method = "shap.TreeExplainer"
            elif hasattr(inner, "coef_"):
                # The pipeline's scaler must be applied before the linear explainer sees
                # a row, so explain the whole pipeline through the model-agnostic path.
                self._shap = shap.Explainer(
                    lambda x: np.asarray(self.model.predict_proba(x))[:, 1],
                    background,
                )
                # CLAUDE.md rule 10: budgets are asserts, not hopes. The permutation
                # explainer's default is 2*n_features+1 model evaluations PER SAMPLE, and
                # this vector runs to thousands of columns — unbounded, one explanation
                # would dominate the whole job's latency.
                self._max_evals = MAX_PERMUTATION_EVALS
                self.method = f"shap.Explainer(permutation, max_evals={MAX_PERMUTATION_EVALS})"
            else:
                self._build_fallback()
                return
        except Exception:
            self._build_fallback()

    def _build_fallback(self) -> None:
        from drishti.m5_ml.models import global_importance

        weights = global_importance(self.model, len(self.vocabulary))
        self._fallback_weights = weights
        self.method = (
            "model-native global importance (SHAP unavailable)"
            if weights is not None
            else "none (no per-sample attribution available for this model)"
        )

    def explain(self, row: np.ndarray, top_k: int = TOP_K) -> list[Attribution]:
        """Top-k contributions for one sample, largest magnitude first."""
        row = np.asarray(row, dtype=float).reshape(1, -1)
        weights = self._sample_weights(row)
        if weights is None:
            return []
        order = np.argsort(-np.abs(weights))[:top_k]
        return [
            Attribution(
                feature=self.vocabulary[i],
                value=float(row[0, i]),
                weight=round(float(weights[i]), 6),
                method=self.method,
            )
            for i in order
        ]

    def _sample_weights(self, row: np.ndarray) -> np.ndarray | None:
        if self._shap is not None:
            try:
                values = (
                    self._shap(row, max_evals=self._max_evals)
                    if self._max_evals
                    else self._shap(row)
                )
                array = np.asarray(getattr(values, "values", values), dtype=float)
                # Binary classifiers may return (n, features, classes); take the
                # positive class rather than averaging two mirrored explanations.
                while array.ndim > 2:
                    array = array[..., -1]
                return np.asarray(array.reshape(array.shape[0], -1)[0], dtype=float)
            except Exception:
                self._build_fallback()
        if self._fallback_weights is None:
            return None
        # Global magnitude scaled by this sample's value: still not per-sample SHAP, and
        # `method` says so — but it at least suppresses features this sample does not have.
        return np.asarray(self._fallback_weights * row[0], dtype=float)


def permutation_importance(
    model: Any,
    features: np.ndarray,
    labels: np.ndarray,
    vocabulary: list[str],
    *,
    repeats: int = 5,
    top_k: int = 25,
    max_columns: int = 60,
) -> list[Attribution]:
    """Global importance measured by shuffling one column at a time and watching PR-AUC fall.

    Model-agnostic and measured rather than read off internal weights, which is why it is
    the honest global answer for every model in the zoo including the MLP.

    Cost is `repeats x columns` full predictions, which on a few thousand features and a
    400-tree forest runs into hours. `max_columns` narrows the field to the model's own
    top candidates and then MEASURES those — the shortlist is a screen, every number
    reported is still a measurement. The restriction travels in `method` so the figure
    cannot claim to have ranked features it never shuffled.

    Implemented here rather than via `sklearn.inspection.permutation_importance`, which
    on this version offers no way to permute a column subset and would therefore shuffle
    all several thousand.
    """
    from sklearn.metrics import average_precision_score

    from drishti.m5_ml.models import global_importance, scores

    columns = np.arange(features.shape[1])
    restricted = ""
    if max_columns and features.shape[1] > max_columns:
        native = global_importance(model, features.shape[1])
        if native is None:
            # No model-native ranking: fall back to the columns that vary at all, since a
            # constant column's permutation importance is exactly zero by construction.
            native = np.asarray(features.std(axis=0), dtype=float)
        columns = np.argsort(-native)[:max_columns]
        restricted = (
            f", shortlisted to the {max_columns} highest-ranked of {features.shape[1]} "
            "columns before measuring"
        )

    baseline = float(average_precision_score(labels, scores(model, features)))
    rng = np.random.default_rng(SEED)
    rows = features.shape[0]
    means = np.zeros(features.shape[1], dtype=float)
    for column in columns:
        # All `repeats` shuffles of this column go through the model in ONE call. A
        # per-repeat call pays joblib's parallel start-up every time, which on a small
        # test split costs more than the prediction itself and turned this loop into the
        # slowest thing in the training job.
        stacked = np.tile(features, (repeats, 1))
        for repeat in range(repeats):
            block = slice(repeat * rows, (repeat + 1) * rows)
            stacked[block, column] = rng.permutation(features[:, column])
        predicted = scores(model, stacked)
        drops = [
            baseline
            - float(average_precision_score(labels, predicted[repeat * rows : (repeat + 1) * rows]))
            for repeat in range(repeats)
        ]
        means[column] = float(np.mean(drops))

    order = np.argsort(-means)[:top_k]
    return [
        Attribution(
            feature=vocabulary[i],
            value=float(np.mean(features[:, i])),
            weight=round(float(means[i]), 6),
            method=f"permutation importance on PR-AUC ({repeats} repeats{restricted})",
        )
        for i in order
    ]
