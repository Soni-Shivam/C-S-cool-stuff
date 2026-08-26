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

#: pyproject pins `shap>=0.48,<1` and the lower bound is a requirement, not a
#: preference: shap 0.46 raises at IMPORT under numpy>=2.3
#: (`shap/plots/colors/_colorconv.py` calls `np.dtype(np.floating)`, which numpy 2
#: refuses). An environment that drifts back below this bound loses per-sample
#: attribution entirely, so the version is checked and NAMED rather than left to
#: surface as a bare TypeError swallowed by an `except`.
SHAP_MIN_VERSION = (0, 48)


def _installed_shap_version() -> str | None:
    """The installed shap version, readable even when `import shap` itself raises."""
    try:
        from importlib.metadata import version

        return version("shap")
    except Exception:
        return None


def _import_shap() -> tuple[Any, str | None]:
    """Return `(module, None)`, or `(None, reason)` naming why SHAP cannot run here.

    The reason is written for an operator reading it in `MLPrediction.errors`: it says
    which version is installed and which is required, because "SHAP unavailable" on its
    own reads as "shap is not installed" and sends the reader down the wrong path when
    the truth is that an incompatible shap is installed and failing at import.
    """
    installed = _installed_shap_version()
    try:
        import shap
    except Exception as exc:
        where = f"shap {installed} is installed but " if installed else ""
        return None, (
            f"{where}`import shap` raised {type(exc).__name__}: {exc} — this pipeline "
            "requires shap>=0.48,<1 (shap 0.46 raises at import under numpy>=2.3)"
        )
    reported = getattr(shap, "__version__", None) or installed
    if _version_tuple(reported) < SHAP_MIN_VERSION:
        return None, (
            f"shap {reported} is installed but this pipeline requires shap>=0.48,<1; "
            "older releases are not compatible with numpy>=2.3"
        )
    return shap, None


def _version_tuple(version: str | None) -> tuple[int, ...]:
    """`0.46.0` -> `(0, 46, 0)`. An unparseable version is treated as new enough."""
    if not version:
        return SHAP_MIN_VERSION
    parts: list[int] = []
    for chunk in version.split(".")[:3]:
        # Leading digits only: `1.0.0rc1` is release 1.0.0, and reading `0rc1` as 1
        # would rank a release candidate above the release it precedes.
        digits = ""
        for character in chunk:
            if not character.isdigit():
                break
            digits += character
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else SHAP_MIN_VERSION


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
        #: Why per-sample SHAP could not run, in words an operator can act on. `None`
        #: while SHAP is working. Threaded into `MLPrediction.errors` by `infer.predict`
        #: so a degraded explainer is diagnosable from the job output alone.
        self.unavailable_reason: str | None = None
        self._shap: Any = None
        self._max_evals: int | None = None
        self._fallback_weights: np.ndarray | None = None
        self._build(background)

    def _build(self, background: np.ndarray) -> None:
        inner = self.model
        if hasattr(self.model, "named_steps"):
            inner = self.model.named_steps.get("clf", self.model)
        shap, reason = _import_shap()
        if shap is None:
            self._build_fallback(reason)
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
                self._build_fallback(
                    f"{type(inner).__name__} is neither a tree nor a linear model, so "
                    "no SHAP explainer fits it; permutation importance is its honest answer"
                )
                return
        except Exception as exc:
            self._build_fallback(f"building the SHAP explainer raised {type(exc).__name__}: {exc}")

    def _build_fallback(self, reason: str | None = None) -> None:
        from drishti.m5_ml.models import global_importance

        weights = global_importance(self.model, len(self.vocabulary))
        self._fallback_weights = weights
        self.unavailable_reason = reason or "per-sample SHAP did not run"
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
            except Exception as exc:
                self._build_fallback(
                    f"the SHAP explainer raised {type(exc).__name__} on this sample: {exc}"
                )
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
    # All `repeats` shuffles of a column go through the model in ONE call: a per-repeat
    # call pays joblib's parallel start-up every time, which costs more than the
    # prediction and made this loop the slowest thing in the training job. The stacked
    # buffer is allocated once and the permuted column restored after each pass —
    # reallocating it per column would be tens of gigabytes over a full run.
    stacked = np.tile(features, (repeats, 1))
    for column in columns:
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
        # Restore, or the next column would be measured against an already-degraded
        # matrix and every importance after the first would be understated.
        for repeat in range(repeats):
            stacked[repeat * rows : (repeat + 1) * rows, column] = features[:, column]

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
