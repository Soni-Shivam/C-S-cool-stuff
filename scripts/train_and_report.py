#!/usr/bin/env python3
"""Train the model zoo on extracted corpus features and emit the honest comparison.

docs/PHASE_2_ML_AND_SCORING.md T2.3, T2.4, T2.5, T2.6.

Runs on whatever `corpus_extract.py` has produced so far. Below `--min-per-class` in
either evaluation split it refuses to report metrics rather than printing a number nobody
should quote.

The methodology, stated once and enforced below:

  * **Five models, one matrix, one seed.** Logistic regression, linear SVM, random
    forest, XGBoost and an MLP see identical features, identical splits, identical
    `dataset.SEED`. The only variable is the model.
  * **Two split schemes, both reported.** A stratified random split (the number everyone
    quotes) and a time split where test is strictly newer than train (the number that
    predicts field behaviour). The GAP is the finding — it is the argument for the
    behavioural and GenAI layers, not an embarrassment to bury.
  * **The winner is chosen by cross-validation inside the training split**, never by test
    PR-AUC. Picking the best of five models on the test set turns the test set into a
    validation set and inflates whatever you then report from it.
  * **Calibration happens on the held-out calib split.** Never on test; that leak is the
    first thing a good judge asks about. The calibration METHOD is likewise chosen by
    cross-validation within calib, not by its test Brier.
  * **Vocabulary is frozen from training rows only**, per scheme, and the shipped one is
    written to `models/vocab_v1.json`. Inference loads it and never recomputes one.

Every figure is generated from an array measured in this run. There is no path here that
draws a curve from an assumption.

    uv run python scripts/train_and_report.py data/corpus/features.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np

from drishti.m5_ml import anomaly, bundle, calibrate, dataset, evaluate, explain, figures, models
from drishti.m5_ml.features import FEATURE_SCHEMA_VERSION

#: Below this many of either class in an evaluation split, no metric is reported.
#: A PR-AUC over nine test samples is noise with a decimal point on it.
MIN_PER_CLASS = 25


def _cv_pr_auc(
    name: str, features: np.ndarray, labels: np.ndarray, folds: int
) -> tuple[float, float]:
    """Stratified CV PR-AUC inside the training split. This is how the winner is chosen.

    Returns (mean, std). Selecting on test would make every subsequently reported test
    number the best of five draws rather than an estimate of field performance.
    """
    from sklearn.metrics import average_precision_score
    from sklearn.model_selection import StratifiedKFold

    positives = int((labels == 1).sum())
    usable = min(folds, positives, int((labels == 0).sum()))
    if usable < 2:
        return (float("nan"), float("nan"))
    splitter = StratifiedKFold(n_splits=usable, shuffle=True, random_state=dataset.SEED)
    scores: list[float] = []
    for train_index, test_index in splitter.split(features, labels):
        model = models.fit(name, features[train_index], labels[train_index])
        probabilities = models.scores(model, features[test_index])
        scores.append(float(average_precision_score(labels[test_index], probabilities)))
    return (round(float(np.mean(scores)), 4), round(float(np.std(scores)), 4))


def _three_way_random(labels: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Stratified 60/20/20 train/calib/test over the pooled corpus.

    Mirrors the time scheme's three-way structure exactly, so the random-vs-time
    comparison isolates the assignment rule and nothing else.
    """
    rng = np.random.default_rng(seed)
    train, calib, test = [], [], []
    for value in (0, 1):
        members = np.flatnonzero(labels == value)
        rng.shuffle(members)
        n = len(members)
        first, second = round(0.6 * n), round(0.8 * n)
        train.extend(members[:first].tolist())
        calib.extend(members[first:second].tolist())
        test.extend(members[second:].tolist())
    return (
        np.array(sorted(train), dtype=int),
        np.array(sorted(calib), dtype=int),
        np.array(sorted(test), dtype=int),
    )


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_jsonl", type=Path, nargs="+")
    parser.add_argument("--figures", type=Path, default=Path("docs/figures"))
    parser.add_argument("--models", type=Path, default=Path("models"))
    parser.add_argument("--results", type=Path, default=Path("docs/ML_RESULTS.md"))
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--min-per-class", type=int, default=MIN_PER_CLASS)
    parser.add_argument(
        "--only", nargs="*", default=list(models.MODEL_NAMES), help="subset of the model zoo"
    )
    parser.add_argument(
        "--no-ci",
        action="store_true",
        help="skip bootstrap intervals (fast plumbing runs only — never for a reported result)",
    )
    parser.add_argument(
        "--provenance",
        default="",
        help="free-text note recorded in the model card and ML_RESULTS.md",
    )
    parser.add_argument(
        "--allow-small",
        action="store_true",
        help="fit and persist below the min-per-class gate, marking every number PILOT",
    )
    parser.add_argument(
        "--no-repartition",
        action="store_true",
        help=(
            "keep the shipped calib/test boundary even when calib is too small to "
            "calibrate on; the run then ships an uncalibrated probability"
        ),
    )
    parser.add_argument(
        "--calib-fraction",
        type=float,
        default=0.3,
        help="share of the held-out bands assigned to calib when repartitioning",
    )
    args = parser.parse_args()

    started = time.monotonic()
    corpus = dataset.load_jsonl(list(args.corpus_jsonl))
    if not len(corpus):
        print("no usable records in", args.corpus_jsonl, file=sys.stderr)
        return 1

    # The shipped list puts 7 malware rows in calib, which cannot support a calibrator.
    # Re-cut the boundary INSIDE the held-out bands — train is untouched, so this stays a
    # time split — and report exactly what moved.
    repartition: dict[str, Any] = {"applied": False}
    calib_positives = corpus.composition()["calib"]["malware"]
    if not args.no_repartition and calib_positives < calibrate.MIN_POSITIVES_FOR_ANY_CALIBRATION:
        repartition = dataset.repartition_holdout(corpus, calib_fraction=args.calib_fraction)
        repartition["trigger"] = (
            f"the shipped calibration split held {calib_positives} malware rows, under the "
            f"{calibrate.MIN_POSITIVES_FOR_ANY_CALIBRATION} needed to fit a calibrator"
        )
        print(f"\nREPARTITIONED THE HELD-OUT BANDS: {json.dumps(repartition, indent=2)}")

    summary = dataset.summarise(corpus)
    summary["repartition"] = repartition
    print(json.dumps(summary, indent=2))
    args.figures.mkdir(parents=True, exist_ok=True)
    figures.corpus_composition(
        corpus.bands(), args.figures / "ml_corpus_composition.png", total=len(corpus)
    )

    composition = corpus.composition()
    smallest = min(
        composition["test"]["malware"],
        composition["test"]["benign"],
        composition["train"]["malware"],
        composition["train"]["benign"],
    )
    pilot = smallest < args.min_per_class
    if pilot and not args.allow_small:
        print(
            f"\nREFUSING TO REPORT METRICS: the smallest class in train/test holds "
            f"{smallest} samples, under the {args.min_per_class} gate. A PR-AUC over a "
            "handful of samples is noise with a decimal point on it. Let extraction run "
            "longer, or pass --allow-small to produce explicitly PILOT-marked numbers."
        )
        return 0

    # ── time scheme ──────────────────────────────────────────────────────────
    train_samples = corpus.of_split("train")
    calib_samples = corpus.of_split("calib")
    test_samples = corpus.of_split("test")
    vocabulary = dataset.freeze_vocabulary(train_samples)
    print(f"\nfroze {len(vocabulary)} feature names from {len(train_samples)} training rows")

    x_train, y_train = dataset.matrix(train_samples, vocabulary)
    x_calib, y_calib = dataset.matrix(calib_samples, vocabulary)
    x_test, y_test = dataset.matrix(test_samples, vocabulary)

    # ── random scheme (its own vocabulary, frozen on its own training rows) ──
    all_samples = corpus.samples
    y_all = np.asarray([s.label for s in all_samples], dtype=int)
    r_train_idx, r_calib_idx, r_test_idx = _three_way_random(y_all, dataset.SEED)
    r_train_samples = [all_samples[i] for i in r_train_idx]
    r_vocabulary = dataset.freeze_vocabulary(r_train_samples)
    xr_train, yr_train = dataset.matrix(r_train_samples, r_vocabulary)
    xr_calib, yr_calib = dataset.matrix([all_samples[i] for i in r_calib_idx], r_vocabulary)
    xr_test, yr_test = dataset.matrix([all_samples[i] for i in r_test_idx], r_vocabulary)

    zoo = [name for name in args.only if name in models.MODEL_NAMES]
    if not zoo:
        print(f"no known models in --only {args.only}", file=sys.stderr)
        return 1

    results: list[evaluate.Metrics] = []
    cv_scores: dict[str, tuple[float, float]] = {}
    fitted_time: dict[str, Any] = {}
    probabilities: dict[tuple[str, str], np.ndarray] = {}

    for name in zoo:
        print(f"\n── {name} ──")
        cv_scores[name] = _cv_pr_auc(name, x_train, y_train, args.cv_folds)
        print(f"  CV PR-AUC inside train: {cv_scores[name][0]} ± {cv_scores[name][1]}")

        # Time scheme.
        model = models.fit(name, x_train, y_train)
        fitted_time[name] = model
        p_calib = models.scores(model, x_calib) if len(y_calib) else np.zeros(0)
        threshold, source = (
            evaluate.choose_threshold(y_calib, p_calib)
            if len(y_calib)
            else (0.5, "default 0.5 (no calibration split)")
        )
        p_test = models.scores(model, x_test)
        probabilities[(name, "time")] = p_test
        results.append(
            evaluate.evaluate(
                model_name=name,
                split_name="time",
                labels=y_test,
                probabilities=p_test,
                threshold=threshold,
                threshold_source=source,
                with_ci=not args.no_ci,
            )
        )

        # Random scheme.
        r_model = models.fit(name, xr_train, yr_train)
        pr_calib = models.scores(r_model, xr_calib)
        r_threshold, r_source = evaluate.choose_threshold(yr_calib, pr_calib)
        pr_test = models.scores(r_model, xr_test)
        probabilities[(name, "random")] = pr_test
        results.append(
            evaluate.evaluate(
                model_name=name,
                split_name="random",
                labels=yr_test,
                probabilities=pr_test,
                threshold=r_threshold,
                threshold_source=r_source,
                with_ci=not args.no_ci,
            )
        )
        time_row = results[-2]
        random_row = results[-1]
        print(
            f"  time  PR-AUC {time_row.pr_auc:.4f} {time_row.pr_auc_ci}  "
            f"n={time_row.n} ({time_row.n_pos} malware)"
        )
        print(
            f"  random PR-AUC {random_row.pr_auc:.4f} {random_row.pr_auc_ci}  "
            f"n={random_row.n} ({random_row.n_pos} malware)"
        )

    # ── winner: cross-validated inside train, never on test ──────────────────
    ranked = sorted(
        (name for name in zoo if not np.isnan(cv_scores[name][0])),
        key=lambda n: cv_scores[n][0],
        reverse=True,
    )
    winner = ranked[0] if ranked else zoo[0]
    selection_basis = (
        f"highest {args.cv_folds}-fold CV PR-AUC inside the training split "
        f"({cv_scores[winner][0]} ± {cv_scores[winner][1]}); the test split played no part"
        if ranked
        else "training split too small to cross-validate; first model in the zoo"
    )
    print(f"\nwinner: {winner} — {selection_basis}")
    model = fitted_time[winner]

    # ── figures over every model ─────────────────────────────────────────────
    by_key = {(row.model, row.split): row for row in results}
    panels = {}
    for split_label, key in (("random split", "random"), ("time split", "time")):
        entries = []
        for name in zoo:
            row = by_key[(name, key)]
            labels = yr_test if key == "random" else y_test
            entries.append((name, labels, probabilities[(name, key)], row.pr_auc, row.n, row.n_pos))
        panels[split_label] = entries
    figures.pr_curves(panels, args.figures / "ml_pr_curves.png")
    figures.split_gap(
        [
            (
                name,
                by_key[(name, "random")].pr_auc,
                by_key[(name, "random")].pr_auc_ci,
                by_key[(name, "time")].pr_auc,
                by_key[(name, "time")].pr_auc_ci,
            )
            for name in zoo
        ],
        args.figures / "ml_split_gap.png",
        n_random=by_key[(zoo[0], "random")].n,
        n_time=by_key[(zoo[0], "time")].n,
        n_random_pos=by_key[(zoo[0], "random")].n_pos,
        n_time_pos=by_key[(zoo[0], "time")].n_pos,
    )

    # ── calibration of the winner, on calib ──────────────────────────────────
    calibration: dict[str, Any] = {"performed": False}
    calibrator = None
    try:
        chosen = calibrate.select(model, x_calib, y_calib)
    except (calibrate.NotEnoughCalibrationDataError, ValueError) as exc:
        chosen = None
        calibration["reason"] = str(exc)
        print(f"calibration REFUSED: {exc}")
    if chosen is not None:
        calibrator = chosen.calibrator
        raw_test = probabilities[(winner, "time")]
        both = calibrate.fit_all(model, x_calib, y_calib)
        per_method = {}
        for method, fitted in both.items():
            calibrated = fitted.predict_proba(x_test)[:, 1]
            per_method[method] = {
                "brier_test": calibrate.brier(y_test, calibrated),
                "ece_test": calibrate.expected_calibration_error(y_test, calibrated),
            }
        calibrated_test = calibrator.predict_proba(x_test)[:, 1]
        calibration = {
            "performed": True,
            **chosen.as_dict(),
            "brier_test_before": calibrate.brier(y_test, raw_test),
            "brier_test_after": calibrate.brier(y_test, calibrated_test),
            "ece_test_before": calibrate.expected_calibration_error(y_test, raw_test),
            "ece_test_after": calibrate.expected_calibration_error(y_test, calibrated_test),
            "per_method_on_test": per_method,
            "n_test": len(y_test),
            "n_test_malware": int((y_test == 1).sum()),
        }
        figures.reliability_diagram(
            calibrate.reliability(y_test, raw_test),
            calibrate.reliability(y_test, calibrated_test),
            args.figures / "ml_reliability.png",
            method=chosen.method,
            brier_before=calibration["brier_test_before"],
            brier_after=calibration["brier_test_after"],
            n=len(y_test),
            n_pos=int((y_test == 1).sum()),
        )
        print(
            f"calibration: {chosen.method} on n={chosen.n_calib} "
            f"({chosen.n_calib_pos} malware) — Brier {calibration['brier_test_before']} "
            f"-> {calibration['brier_test_after']}"
        )

    # ── anomaly escalator (T2.5), fitted on benign training rows only ────────
    anomaly_summary: dict[str, Any] = {"performed": False}
    detector = None
    try:
        detector = anomaly.fit(x_train, y_train)
        anomaly_summary = {"performed": True, **anomaly.summarise(detector, x_test, y_test)}
        test_scores = detector.score(x_test)
        figures.anomaly_distribution(
            test_scores[y_test == 0],
            test_scores[y_test == 1],
            args.figures / "ml_anomaly.png",
            escalate_at=anomaly.ESCALATE_AT,
        )
        print(f"anomaly: {json.dumps(anomaly_summary)}")
    except Exception as exc:
        anomaly_summary = {"performed": False, "reason": f"{type(exc).__name__}: {exc}"}
        print(f"anomaly skipped: {anomaly_summary['reason']}")

    # ── explanation of the winner (T2.6) ─────────────────────────────────────
    explainer = explain.Explainer(model, x_train, vocabulary)
    global_rows = explain.permutation_importance(
        model, x_test, y_test, vocabulary, repeats=5, top_k=20
    )
    figures.importance(
        [(explain.label_for(row.feature), row.weight) for row in global_rows],
        args.figures / "ml_feature_importance.png",
        title=f"{winner}: top 20 features by permutation importance (test split, n={len(y_test)})",
        xlabel="mean drop in PR-AUC when the column is shuffled",
    )
    shap_rows: list[explain.Attribution] = []
    if len(x_test):
        # Explain the highest-scoring true positive — the sample the report would cite.
        candidates = np.flatnonzero(y_test == 1)
        if candidates.size:
            pick = int(candidates[int(np.argmax(probabilities[(winner, "time")][candidates]))])
            shap_rows = explainer.explain(x_test[pick])
            if shap_rows:
                figures.importance(
                    [(explain.label_for(row.feature), row.weight) for row in shap_rows],
                    args.figures / "ml_shap_example.png",
                    title=(
                        f"{winner}: per-sample attribution for the highest-scoring test "
                        f"malware ({explainer.method})"
                    ),
                    xlabel="contribution to P(malicious)",
                )
    print(f"attribution method: {explainer.method}")

    # ── persist the bundle ───────────────────────────────────────────────────
    time_row = by_key[(winner, "time")]
    random_row = by_key[(winner, "random")]
    notes: list[str] = []
    if pilot:
        notes.append(
            f"PILOT: the smallest class in train/test held {smallest} samples, under the "
            f"{args.min_per_class} gate. Every number from this run is provisional."
        )
    if args.provenance:
        notes.append(args.provenance)
    if not summary["time_split_disjoint"]:
        notes.append(f"time split is NOT band-disjoint: {summary['time_split_detail']}")
    if repartition.get("applied"):
        notes.append(
            "calib/test boundary was re-cut inside the held-out bands "
            f"({repartition['rule']}) because {repartition['trigger']}. Train untouched, "
            "so this is still a time split."
        )
    if not calibration.get("performed"):
        notes.append(
            "NO CALIBRATOR SHIPPED — the probability is raw and must be labelled "
            f"uncalibrated: {calibration.get('reason', 'no reason recorded')}"
        )

    card = bundle.ModelCard(
        model_name=winner,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        n_features=len(vocabulary),
        trained_at=datetime.now(UTC).isoformat(),
        corpus_sources=summary["sources"],
        n_train=composition["train"]["n"],
        n_train_malware=composition["train"]["malware"],
        n_calib=composition["calib"]["n"],
        n_calib_malware=composition["calib"]["malware"],
        n_test=composition["test"]["n"],
        n_test_malware=composition["test"]["malware"],
        calibration_method=str(calibration.get("method", "none")),
        operating_threshold=time_row.threshold,
        threshold_source=time_row.threshold_source,
        time_split_pr_auc=time_row.pr_auc,
        time_split_pr_auc_ci=list(time_row.pr_auc_ci),
        random_split_pr_auc=random_row.pr_auc,
        random_split_pr_auc_ci=list(random_row.pr_auc_ci),
        generalisation_gap=round(random_row.pr_auc - time_row.pr_auc, 4),
        attribution_method=explainer.method,
        notes=notes,
    )

    metrics = {
        "generated_at": card.trained_at,
        "schema_version": FEATURE_SCHEMA_VERSION,
        "seed": dataset.SEED,
        "corpus": summary,
        "vocabulary": {"time_scheme": len(vocabulary), "random_scheme": len(r_vocabulary)},
        "winner": winner,
        "winner_selection": selection_basis,
        "cv_pr_auc_in_train": {name: cv_scores[name] for name in zoo},
        "models": {name: models.MODEL_DESCRIPTIONS[name] for name in zoo},
        "results": [row.as_dict() for row in results],
        "calibration": calibration,
        "anomaly": anomaly_summary,
        "attribution_method": explainer.method,
        "global_importance_top20": [
            {"feature": row.feature, "weight": row.weight} for row in global_rows
        ],
        "example_attribution": [
            {"feature": row.feature, "value": row.value, "weight": row.weight} for row in shap_rows
        ],
        "pilot": pilot,
        "runtime_seconds": round(time.monotonic() - started, 1),
    }

    bundle.save(
        args.models,
        model=model,
        vocabulary=vocabulary,
        calibrator=calibrator,
        detector=detector,
        card=card,
        metrics=metrics,
        background=x_train,
    )
    print(f"\nsaved bundle -> {args.models} (model_version {card.version})")
    (args.figures / "ml_metrics.json").write_text(json.dumps(metrics, indent=2, default=str) + "\n")

    _write_results(args.results, metrics, card, results, zoo, cv_scores)
    print(f"wrote {args.results}")
    print(f"figures -> {args.figures}")
    print(f"\n{evaluate.markdown_table(results)}")
    return 0


def _write_results(
    path: Path,
    metrics: dict[str, Any],
    card: bundle.ModelCard,
    results: list[evaluate.Metrics],
    zoo: list[str],
    cv_scores: dict[str, tuple[float, float]],
) -> None:
    """Render ML_RESULTS.md entirely from this run's measurements.

    Generated rather than hand-written so that no number in it can drift away from the
    run that produced it. Prose that is a judgement rather than a measurement is marked
    as such.
    """
    corpus = metrics["corpus"]
    composition = corpus["composition"]
    by_key = {(row.model, row.split): row for row in results}
    calibration = metrics["calibration"]
    anomaly_summary = metrics["anomaly"]

    time_rows = [by_key[(name, "time")] for name in zoo]
    random_rows = [by_key[(name, "random")] for name in zoo]
    gap_lines = []
    for name in zoo:
        time_row, random_row = by_key[(name, "time")], by_key[(name, "random")]
        gap_lines.append(
            f"| `{name}` | {random_row.pr_auc:.4f} | {time_row.pr_auc:.4f} | "
            f"{random_row.pr_auc - time_row.pr_auc:+.4f} | "
            f"{cv_scores[name][0]} ± {cv_scores[name][1]} |"
        )

    lines: list[str] = []
    lines.append("# DRISHTI — ML results\n")
    lines.append(
        "**Generated by `scripts/train_and_report.py`. Every number below was measured in "
        f"the run recorded at `{card.trained_at}`; nothing here is an estimate, a target, "
        "or carried over from a previous build.**\n"
    )
    if card.notes:
        lines.append("> " + "\n> ".join(card.notes) + "\n")

    lines.append("## 1. What was actually trained on\n")
    lines.append(
        f"Feature schema `{FEATURE_SCHEMA_VERSION}`, extracted by real M2 over real APKs on "
        "the GCE extractor VM. Training and inference call the same "
        "`m5_ml.features.extract`; `tests/contract/test_feature_parity.py` is what keeps "
        "that true.\n"
    )
    lines.append(f"- Sources: {', '.join(f'`{s}`' for s in corpus['sources']) or 'none'}")
    lines.append(f"- Usable extracted samples: **{corpus['extracted']}**")
    lines.append(
        f"- Dropped: {corpus['skipped_failed_extraction']} failed extraction, "
        f"{corpus['skipped_no_features']} produced no features "
        "(dropped, never zero-filled — a sample androguard could not parse is missing "
        "data, and a row of zeros would teach the model that unparseable looks harmless)"
    )
    lines.append(
        f"- Vocabulary: **{metrics['vocabulary']['time_scheme']}** features, frozen from "
        "training rows only\n"
    )
    lines.append("| split | n | malware | benign |")
    lines.append("|---|---:|---:|---:|")
    for split in ("train", "calib", "test"):
        row = composition[split]
        lines.append(f"| {split} | {row['n']} | {row['malware']} | {row['benign']} |")
    lines.append("")
    lines.append(f"Time-split integrity: {corpus['time_split_detail']}\n")
    repartition = corpus.get("repartition", {})
    if repartition.get("applied"):
        lines.append(
            "**The calib/test boundary was re-cut.** "
            f"{repartition['trigger'].capitalize()}, so the held-out rows were "
            f"re-partitioned: {repartition['rule']}. "
            f"{repartition['moved_to_calib']} rows moved test -> calib and "
            f"{repartition['moved_to_test']} moved calib -> test. "
            "The training split was not touched, so test remains strictly newer than "
            "train and this is still a time split. Assignment is by hash bucket and "
            "therefore label-independent — assigning by label would have manufactured "
            "whatever balance flattered the numbers.\n"
        )
        lines.append("| split | before (n / malware) | after (n / malware) |")
        lines.append("|---|---|---|")
        for split in ("calib", "test"):
            before = repartition["before"][split]
            after = repartition["after"][split]
            lines.append(
                f"| {split} | {before['n']} / {before['malware']} | "
                f"{after['n']} / {after['malware']} |"
            )
        lines.append("")
    lines.append(
        "`vt_detection` is **not** a feature. AndroZoo's label is thresholded "
        "`vt_detection`, so a VirusTotal-derived input would make every metric below "
        "circular; `dataset.assert_no_label_leak` refuses such a vocabulary outright.\n"
    )

    lines.append("## 2. Model comparison\n")
    lines.append("| model | specification |")
    lines.append("|---|---|")
    for name in zoo:
        lines.append(f"| `{name}` | {models.MODEL_DESCRIPTIONS[name]} |")
    lines.append("")
    lines.append(
        "All five see identical features, identical splits and seed "
        f"`{metrics['seed']}`. The only variable is the model.\n"
    )
    lines.append("### 2.1 Full results — every model, every split\n")
    lines.append(evaluate.markdown_table(results))
    lines.append(
        "`FPR@90%R` is the false-positive rate at the lowest threshold that still reaches "
        "90% recall — the triage-desk question: *if we insist on catching nine in ten, how "
        "much clean traffic does an analyst wade through?* `n/a` means no threshold "
        "reached that recall.\n"
    )
    lines.append(
        "Confidence intervals are 2000-resample percentile bootstraps. Read the interval, "
        "not the point estimate — especially on the time split, where the malware count is "
        f"**{time_rows[0].n_pos}**.\n"
    )

    lines.append("## 3. The random-vs-time-split gap\n")
    lines.append("| model | random-split PR-AUC | time-split PR-AUC | gap | CV PR-AUC in train |")
    lines.append("|---|---:|---:|---:|---|")
    lines.extend(gap_lines)
    lines.append("")
    lines.append(
        f"Random split: n={random_rows[0].n} ({random_rows[0].n_pos} malware, prevalence "
        f"{random_rows[0].prevalence:.3f}). Time split: n={time_rows[0].n} "
        f"({time_rows[0].n_pos} malware, prevalence {time_rows[0].prevalence:.3f}). "
        "The two prevalences differ, so compare each PR-AUC against its own no-skill "
        "baseline (drawn on `ml_pr_curves.png`) rather than against each other directly.\n"
    )
    lines.append(
        "The gap is the finding, not an embarrassment. A random split lets a model see "
        "2024 malware families while being tested on their siblings; a time split does "
        "not. Whatever the gap is here, it is the measured cost of concept drift on this "
        "corpus — and the argument for the behavioural and GenAI layers that do not "
        "depend on having seen the family before.\n"
    )
    lines.append("![PR curves](figures/ml_pr_curves.png)\n")
    lines.append("![Random vs time split](figures/ml_split_gap.png)\n")

    lines.append("## 4. Winner\n")
    lines.append(f"**`{card.model_name}`** — {metrics['winner_selection']}.\n")
    lines.append(
        "Selection is by cross-validation **inside the training split**. Picking the best "
        "of five models by test PR-AUC would turn the test set into a validation set, and "
        "every number reported from it afterwards would be the best of five draws rather "
        "than an estimate of field performance.\n"
    )
    lines.append(f"- Shipped `model_version`: `{card.version}`")
    lines.append(
        f"- Operating threshold: `{card.operating_threshold}` — {card.threshold_source}. "
        "Chosen on the calibration split; the test split never informed it."
    )
    lines.append(f"- Per-sample attribution method: `{card.attribution_method}`\n")

    lines.append("## 5. Calibration\n")
    if calibration.get("performed"):
        lines.append(
            f"Fitted on the held-out **calib** split (n={calibration['n_calib']}, "
            f"{calibration['n_calib_pos']} malware), never on test.\n"
        )
        lines.append(f"- Method chosen: **{calibration['method']}**")
        for method, reason in calibration.get("methods_rejected", {}).items():
            lines.append(f"- Rejected `{method}`: {reason}")
        lines.append(
            f"- Brier on test: **{calibration['brier_test_before']} -> "
            f"{calibration['brier_test_after']}** "
            f"(n={calibration['n_test']}, {calibration['n_test_malware']} malware)"
        )
        lines.append(
            f"- Expected calibration error on test: "
            f"**{calibration['ece_test_before']} -> {calibration['ece_test_after']}**"
        )
        if calibration.get("per_method_on_test"):
            lines.append("\n| method | Brier on test | ECE on test |")
            lines.append("|---|---:|---:|")
            for method, values in calibration["per_method_on_test"].items():
                lines.append(f"| {method} | {values['brier_test']} | {values['ece_test']} |")
        lines.append("\n![Reliability](figures/ml_reliability.png)\n")
        lines.append(
            "The method is chosen by cross-validated Brier **within** the calibration "
            "split. Choosing it by its test Brier would be the same leak as calibrating "
            "on test, one level of indirection away.\n"
        )
    else:
        lines.append(
            f"**Not performed.** {calibration.get('reason', 'no reason recorded')} "
            "Inference labels the resulting probability uncalibrated rather than "
            "presenting it as `P_cal`.\n"
        )

    lines.append("## 6. Novelty escalator (T2.5)\n")
    if anomaly_summary.get("performed"):
        lines.append(
            f"`IsolationForest`, 200 trees, fitted on **{anomaly_summary['n_fit_benign']} "
            "benign training rows only** — fitting on a mixed corpus would teach it that "
            "malware is normal. The published score is a percentile against that benign "
            "distribution, so the threshold means the same thing across retrainings.\n"
        )
        lines.append(
            f"- Escalates at `{anomaly_summary['escalate_at']}`; on the test split "
            f"(n={anomaly_summary['n_scored']}) it escalated "
            f"**{anomaly_summary['escalated_malware']}** malware and "
            f"**{anomaly_summary['escalated_benign']}** benign samples"
        )
        lines.append(
            f"- Benign escalation rate **{_fmt(anomaly_summary['benign_escalation_rate'])}**, "
            f"malware escalation rate **{_fmt(anomaly_summary['malware_escalation_rate'])}**. "
            "The benign rate is the analyst cost this flag creates and belongs next to the "
            "claim it supports."
        )
        lines.append(
            "\nIt is an **escalator, not an additive term**: it forces the band to at least "
            "HIGH and requires human review, and it never moves `S`.\n"
        )
        lines.append("![Anomaly](figures/ml_anomaly.png)\n")
    else:
        lines.append(f"**Not performed.** {anomaly_summary.get('reason', 'no reason recorded')}\n")

    lines.append("## 7. What the model leans on (T2.6)\n")
    lines.append(
        f"Global importance measured by permutation on the test split "
        f"(n={time_rows[0].n}): each column is shuffled and the drop in PR-AUC recorded. "
        "Model-agnostic and measured, rather than read off internal weights.\n"
    )
    lines.append("| feature | mean drop in PR-AUC when shuffled |")
    lines.append("|---|---:|")
    for row in metrics["global_importance_top20"][:15]:
        lines.append(f"| `{row['feature']}` | {row['weight']} |")
    lines.append("")
    lines.append("![Feature importance](figures/ml_feature_importance.png)\n")
    if metrics["example_attribution"]:
        lines.append(
            f"Per-sample attribution (`{card.attribution_method}`) for the highest-scoring "
            "malware in the test split — the shape the report and the UI panel render:\n"
        )
        lines.append("| feature | value | contribution |")
        lines.append("|---|---:|---:|")
        for row in metrics["example_attribution"]:
            lines.append(f"| `{row['feature']}` | {row['value']} | {row['weight']} |")
        lines.append("\n![Example attribution](figures/ml_shap_example.png)\n")

    lines.append("## 8. Limitations\n")
    limitations = [
        f"The time-split test set holds **{time_rows[0].n_pos} malware rows**. Every "
        "time-split number rests on that count; the bootstrap intervals in §2.1 are the "
        "honest width of the claim.",
        "Recent-band malware labels come from MalwareBazaar while older-band labels come "
        "from AndroZoo's thresholded `vt_detection` — the two halves of the corpus are "
        "not labelled by the same process.",
        "Static features only. Nothing here has seen a runtime trace; the behavioural and "
        "GenAI layers are what cover the gap this table measures.",
    ]
    if calibration.get("performed") and calibration.get("n_calib_pos", 0) < 25:
        limitations.append(
            f"The calibration split holds only {calibration['n_calib_pos']} malware rows, "
            "which is why isotonic was rejected in favour of Platt."
        )
    if metrics.get("pilot"):
        limitations.append(
            "This run is marked **PILOT**: at least one class in train/test fell under the "
            "reporting gate. Treat every figure as provisional."
        )
    for item in limitations:
        lines.append(f"- {item}")
    lines.append("")
    lines.append(
        f"Raw metrics: `{Path('docs/figures/ml_metrics.json')}` and `models/metrics.json`. "
        f"Model card: `models/model_card.json`.\n"
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
