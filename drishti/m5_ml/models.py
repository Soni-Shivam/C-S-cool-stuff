"""The model zoo: five classifiers, one feature matrix, one seed.

docs/PHASE_2_ML_AND_SCORING.md T2.3.

A comparison is only worth reading when the only thing that varies is the model. Every
factory here is handed the same frozen vocabulary, the same splits and `dataset.SEED`,
and every one exposes `predict_proba`, so the evaluation code never branches on model
type and cannot accidentally score one family differently from another.

Why these five:

  * **`logreg_l2`** — the interpretable baseline. If a linear model over Drebin-style
    binary features gets within a point of the boosted trees, the trees are not earning
    their opacity, and that is worth knowing before the report claims otherwise.
  * **`linear_svm`** — the classical text-classification-shaped baseline for exactly this
    kind of high-dimensional sparse binary data. `LinearSVC` has no `predict_proba`, so it
    is wrapped in a 5-fold Platt calibration fitted **inside the training split only**;
    the calib split is untouched here and still does the final calibration for the winner.
  * **`random_forest`** — bagged trees; the variance-reduction counterpart to boosting.
  * **`xgboost`** — the roadmap's pick, hyperparameters as pinned in PHASE_2 T2.3.
  * **`mlp`** — a small dense network, to check whether anything non-linear-and-non-tree
    is left on the table.

Class imbalance is handled by weighting, never by resampling: SMOTE over binary
permission indicators invents APKs that do not exist, and every one of them would be an
ungrounded training example.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import numpy as np

from drishti.m5_ml.dataset import SEED


def _worker_count() -> int:
    """Threads each model may use. Deliberately NOT `n_jobs=-1`.

    Measured on the dev box: with an Android emulator, a browser and another agent's
    test run already on it, a 400-round XGBoost fit over a 276x478 matrix asking for all
    sixteen cores did not finish in three minutes, at 1030% CPU and load average 35 —
    OpenMP's spin-wait burns more time fighting for cores than the fit needs. Capped, the
    same fit is seconds. Grabbing every core on a shared machine is both antisocial and,
    here, measurably slower.
    """
    override = os.environ.get("DRISHTI_ML_JOBS", "").strip()
    if override.isdigit() and int(override) > 0:
        return int(override)
    return max(1, min(4, os.cpu_count() or 1))


N_JOBS = _worker_count()

#: Human-readable, stable, and used as the key in every metrics table and figure legend.
MODEL_NAMES: tuple[str, ...] = ("logreg_l2", "linear_svm", "random_forest", "xgboost", "mlp")

#: Rendered in ML_RESULTS.md so a reader knows what was actually fitted.
MODEL_DESCRIPTIONS: dict[str, str] = {
    "logreg_l2": "Logistic regression, L2, C=1.0, balanced class weight, standardised inputs",
    "linear_svm": "LinearSVC (squared hinge, C=0.5, balanced) + 5-fold Platt inside train",
    "random_forest": "RandomForest, 400 trees, balanced_subsample, min_samples_leaf=2",
    "xgboost": "XGBoost hist, 400 rounds, depth 6, lr 0.06, scale_pos_weight=neg/pos",
    "mlp": "MLP (128, 64), ReLU, adam, early stopping on a 10% internal validation slice",
}


def _scale_pos_weight(labels: np.ndarray) -> float:
    positive = int((labels == 1).sum())
    negative = int((labels == 0).sum())
    return (negative / positive) if positive else 1.0


def build(name: str, labels: np.ndarray) -> Any:
    """Return a fresh, unfitted estimator. `labels` is used only for class weighting.

    Fresh every call: a refitted estimator carries state from the previous split, and
    "the random split scored higher" would then partly mean "it was fitted second".
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import LinearSVC

    if name == "logreg_l2":
        return Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        # L2 is the default; naming it explicitly is deprecated from
                        # scikit-learn 1.8 and the pin allows >=1.5, so leave it implicit.
                        C=1.0,
                        class_weight="balanced",
                        max_iter=4000,
                        solver="lbfgs",
                        random_state=SEED,
                    ),
                ),
            ]
        )

    if name == "linear_svm":
        from sklearn.calibration import CalibratedClassifierCV

        return Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        LinearSVC(C=0.5, class_weight="balanced", max_iter=8000, random_state=SEED),
                        method="sigmoid",
                        cv=5,
                    ),
                ),
            ]
        )

    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=400,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=N_JOBS,
            random_state=SEED,
        )

    if name == "xgboost":
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.06,
            subsample=0.85,
            colsample_bytree=0.7,
            scale_pos_weight=_scale_pos_weight(labels),
            eval_metric="aucpr",
            tree_method="hist",
            n_jobs=N_JOBS,
            random_state=SEED,
        )

    if name == "mlp":
        return Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "clf",
                    MLPClassifier(
                        hidden_layer_sizes=(128, 64),
                        activation="relu",
                        solver="adam",
                        alpha=1e-4,
                        # "auto" is min(200, n_samples). A fixed 256 exceeds the sample
                        # count on every cross-validation fold of a small corpus, which
                        # sklearn clips with a warning per fit — noise that buries the
                        # warnings worth reading.
                        batch_size="auto",
                        learning_rate_init=1e-3,
                        max_iter=300,
                        early_stopping=True,
                        n_iter_no_change=15,
                        validation_fraction=0.1,
                        random_state=SEED,
                    ),
                ),
            ]
        )

    raise ValueError(f"unknown model {name!r}; known: {MODEL_NAMES}")


def fit(name: str, features: np.ndarray, labels: np.ndarray) -> Any:
    """Fit one model. Kept separate from `build` so a caller can inspect the unfitted spec."""
    model = build(name, labels)
    model.fit(features, labels)
    return model


def scores(model: Any, features: np.ndarray) -> np.ndarray:
    """P(malicious) for each row.

    Every model in the zoo exposes `predict_proba`; the `decision_function` branch exists
    only so a caller that swaps in a raw `LinearSVC` gets a ranking rather than a crash —
    and such a score is explicitly NOT a probability and must not be calibrated as one.
    """
    if hasattr(model, "predict_proba"):
        return np.asarray(model.predict_proba(features), dtype=float)[:, 1]
    raw = np.asarray(model.decision_function(features), dtype=float)
    return raw


def global_importance(model: Any, n_features: int) -> np.ndarray | None:
    """Model-native importance, or None when the model has no honest notion of one.

    Returns unsigned magnitudes so the caller can rank. `None` (rather than zeros) for an
    MLP: a bar chart of zeros reads as "no feature matters", which is a claim the model
    never made. Permutation importance is the answer for those, and it is measured, not
    read off the weights.
    """
    inner = model
    if hasattr(model, "named_steps"):
        inner = model.named_steps.get("clf", model)
    if hasattr(inner, "feature_importances_"):
        weights = np.asarray(inner.feature_importances_, dtype=float)
    elif hasattr(inner, "coef_"):
        weights = np.abs(np.asarray(inner.coef_, dtype=float)).ravel()
    else:
        return None
    return weights if weights.shape[0] == n_features else None


def _factory(name: str) -> Callable[[np.ndarray], Any]:
    def make(labels: np.ndarray) -> Any:
        return build(name, labels)

    return make


#: For call sites that want to iterate without importing sklearn at module scope.
FACTORIES: dict[str, Callable[[np.ndarray], Any]] = {name: _factory(name) for name in MODEL_NAMES}
