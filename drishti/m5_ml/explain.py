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
                self.method = "shap.Explainer(permutation)"
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
                values = self._shap(row)
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
) -> list[Attribution]:
    """Global importance measured by shuffling one column at a time and watching PR-AUC fall.

    Model-agnostic and measured rather than read off internal weights, which is why it is
    the honest global answer for every model in the zoo including the MLP.
    """
    from sklearn.inspection import permutation_importance as sk_permutation_importance

    result = sk_permutation_importance(
        model,
        features,
        labels,
        scoring="average_precision",
        n_repeats=repeats,
        random_state=SEED,
        n_jobs=-1,
    )
    means = np.asarray(result.importances_mean, dtype=float)
    order = np.argsort(-means)[:top_k]
    return [
        Attribution(
            feature=vocabulary[i],
            value=float(np.mean(features[:, i])),
            weight=round(float(means[i]), 6),
            method=f"permutation importance on PR-AUC ({repeats} repeats)",
        )
        for i in order
    ]
