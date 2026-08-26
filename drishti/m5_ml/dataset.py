"""Load extracted corpus features into matrices, with the leakage guards that matter.

docs/PHASE_2_ML_AND_SCORING.md T2.2/T2.3, CLAUDE.md "Real-malware corpus and ML training".

Consumes the JSONL that `scripts/corpus_extract.py` writes on the GCE extractor VM — one
record per sample, holding the output of `m5_ml.features.extract` over a real
`StaticReport`. **This module never sees an APK.** It reads features, and the APKs stay
in GCS and on the VM's scratch disk.

Three invariants are enforced here rather than remembered:

  * **The vocabulary is frozen from TRAIN rows only.** Building it over everything would
    put test-set feature names into the model's input space — a leak that no exception
    would announce, because the extra columns are simply zero for train.
  * **No label-derived feature reaches the matrix.** AndroZoo's labels come from
    `vt_detection`; a `vt:*` feature IS the label wearing a hat. `assert_no_label_leak`
    refuses the matrix rather than quietly training a circular model.
  * **A time split means test is strictly newer than train.** `split` comes from
    `build_sample_list.py`, which already applied the `dex_date` plausibility window;
    this module re-checks the band ordering and says so if it does not hold.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from drishti.m5_ml.features import (
    FEATURE_SCHEMA_VERSION,
    RETIRED_FEATURES,
    SCHEMA_EPOCH_MARKERS,
    FeatureVector,
    project,
)

#: One seed for every model, every split, every bootstrap. Comparisons across models are
#: only meaningful when the only thing that changed is the model.
SEED = 20260826

#: Feature-name prefixes that are, or are derived from, the label. AndroZoo's `label`
#: column is thresholded `vt_detection`, so any VirusTotal-derived signal makes every
#: downstream metric circular. See CLAUDE.md: `reputation.py` refuses these for `R`, and
#: the classifier refuses them here for the same reason.
LABEL_DERIVED_PREFIXES: tuple[str, ...] = (
    "vt:",
    "vt_",
    "virustotal",
    "label",
    "av:",
    "avclass",
    "detection",
)

SPLITS: tuple[str, ...] = ("train", "calib", "test")


class LabelLeakError(ValueError):
    """A label-derived feature reached the feature matrix."""


class RetiredFeatureError(ValueError):
    """A vocabulary lists a feature the current extractor can no longer emit."""


@dataclass(frozen=True)
class Sample:
    """One extracted corpus row. `features` is the sparse output of `features.extract`."""

    sha256: str
    label: int
    split: str
    time_band: str
    dex_date: str
    features: dict[str, float]
    package: str = ""
    static_partial: bool = False

    @property
    def is_malware(self) -> bool:
        return self.label == 1


@dataclass
class Corpus:
    """Every usable extracted sample, plus the provenance needed to report it honestly."""

    samples: list[Sample]
    sources: list[str] = field(default_factory=list)
    skipped_failed: int = 0
    skipped_empty: int = 0

    def __len__(self) -> int:
        return len(self.samples)

    def of_split(self, *splits: str) -> list[Sample]:
        wanted = set(splits)
        return [s for s in self.samples if s.split in wanted]

    def composition(self) -> dict[str, dict[str, int]]:
        """malware/benign counts per split. Every reported n comes from here."""
        counts = Counter((s.split, s.label) for s in self.samples)
        return {
            split: {
                "benign": counts[(split, 0)],
                "malware": counts[(split, 1)],
                "n": counts[(split, 0)] + counts[(split, 1)],
            }
            for split in SPLITS
        }

    def bands(self) -> dict[str, dict[str, int]]:
        counts = Counter((s.time_band, s.label) for s in self.samples)
        return {
            band: {"benign": counts[(band, 0)], "malware": counts[(band, 1)]}
            for band in sorted({s.time_band for s in self.samples})
        }


def assert_no_label_leak(names: list[str]) -> None:
    """Refuse a vocabulary that contains a label-derived feature.

    Not a warning. A model trained on `vt_detection` scores 1.00 PR-AUC and means
    nothing, and the failure is invisible in every metric you would think to check.
    """
    offenders = [
        name
        for name in names
        if any(name.lower().startswith(prefix) for prefix in LABEL_DERIVED_PREFIXES)
    ]
    if offenders:
        raise LabelLeakError(
            f"label-derived features in the vocabulary: {offenders[:10]} — AndroZoo's "
            "label is thresholded vt_detection, so training on these is circular. "
            "Remove them from the extractor, do not suppress this check."
        )


def assert_no_retired_features(names: list[str]) -> None:
    """Refuse a vocabulary containing a feature this extractor version cannot produce.

    The failure this prevents is silent by construction: `project` zero-fills a missing
    feature, so a stale vocabulary produces a full-width vector, the model runs, and
    every prediction is made with a learned weight applied to a permanent zero. No
    exception, no shape mismatch, just a quietly worse model.
    """
    offenders = [name for name in names if name in RETIRED_FEATURES]
    if offenders:
        detail = ", ".join(f"{name} (retired at {RETIRED_FEATURES[name]})" for name in offenders)
        raise RetiredFeatureError(
            f"vocabulary lists features the {FEATURE_SCHEMA_VERSION} extractor no longer "
            f"emits: {detail}. This vocabulary was frozen by an older extractor — "
            "regenerate it from freshly extracted rows rather than suppressing this check."
        )


def detect_schema_epoch(sample: Sample) -> str:
    """Which extractor version wrote this row, recovered from its marker features.

    Corpus rows carry no schema stamp, so the version is inferred from mutually
    exclusive marker features. Returns `"unknown"` when no marker is present.
    """
    for marker, version in SCHEMA_EPOCH_MARKERS:
        if marker in sample.features:
            return version
    return "unknown"


def epoch_divergent_features(
    samples: list[Sample], *, presence_gap: float = 0.5, min_rows_per_epoch: int = 10
) -> dict[str, Any]:
    """Find features whose presence tracks the *extractor version*, not the sample.

    A batch that runs for days gets its extractor fixed underneath it, and the result is
    one corpus written by two schema versions. Any feature only one version emits is
    then absent from the other version's rows — and `matrix` will dutifully zero-fill it.

    That zero-fill is not neutral. It encodes *when the row was extracted*, and
    extraction order is never independent of the label (a batch ordered test-first, or a
    malware feed that ran before a benign one, makes epoch a proxy for class). The model
    then learns the proxy, which is a leak that every ranking metric rewards.

    Returns the divergent names plus the per-epoch malware rate, so a reader can see how
    much of the label the discarded columns would have carried. Epochs with fewer than
    `min_rows_per_epoch` rows are ignored — a handful of stragglers must not cost the
    vocabulary a real feature.
    """
    by_epoch: dict[str, list[Sample]] = {}
    for sample in samples:
        by_epoch.setdefault(detect_schema_epoch(sample), []).append(sample)

    epochs = {
        version: {
            "n": len(rows),
            "malware": sum(s.label for s in rows),
            "malware_rate": round(sum(s.label for s in rows) / len(rows), 4) if rows else 0.0,
        }
        for version, rows in sorted(by_epoch.items())
    }

    considered = {v: rows for v, rows in by_epoch.items() if len(rows) >= min_rows_per_epoch}
    divergent: list[str] = []
    detail: list[dict[str, Any]] = []
    if len(considered) > 1:
        every_name = {name for rows in considered.values() for s in rows for name in s.features}
        for name in sorted(every_name):
            rates = {
                version: sum(1 for s in rows if name in s.features) / len(rows)
                for version, rows in considered.items()
            }
            if max(rates.values()) - min(rates.values()) > presence_gap:
                divergent.append(name)
                detail.append({"feature": name, "presence_by_epoch": rates})
    return {
        "epochs": epochs,
        "mixed": len(considered) > 1,
        "presence_gap": presence_gap,
        "divergent": divergent,
        "detail": detail,
    }


def load_jsonl(paths: list[Path] | Path) -> Corpus:
    """Read one or more corpus-extraction JSONL files.

    Records that failed extraction (`ok=false`) or produced no features are counted and
    dropped, never zero-filled: a sample androguard could not parse is missing data, and
    a row of zeros would tell the model that "unparseable" looks like "harmless".
    """
    if isinstance(paths, Path):
        paths = [paths]
    samples: list[Sample] = []
    seen: set[str] = set()
    failed = empty = 0
    sources: list[str] = []
    for path in paths:
        if not path.exists():
            continue
        sources.append(str(path))
        with path.open() as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not record.get("ok"):
                    failed += 1
                    continue
                features = record.get("features") or {}
                if not features:
                    empty += 1
                    continue
                sha = str(record.get("sha256", "")).lower()
                # Resumed batches re-emit rows; the last write wins, deterministically.
                if sha in seen:
                    samples = [s for s in samples if s.sha256 != sha]
                seen.add(sha)
                samples.append(
                    Sample(
                        sha256=sha,
                        label=int(record["label"]),
                        split=str(record["split"]),
                        time_band=str(record.get("time_band", "")),
                        dex_date=str(record.get("dex_date", "")),
                        features={str(k): float(v) for k, v in features.items()},
                        package=str(record.get("package", "")),
                        static_partial=bool(record.get("static_partial", False)),
                    )
                )
    samples.sort(key=lambda s: s.sha256)
    return Corpus(samples=samples, sources=sources, skipped_failed=failed, skipped_empty=empty)


def freeze_vocabulary(
    train: list[Sample], *, min_count: int = 1, exclude: list[str] | tuple[str, ...] = ()
) -> list[str]:
    """Build the frozen vocabulary from TRAINING rows only, sorted.

    Sorted so column *i* means the same thing on every machine and every run. `min_count`
    drops names seen in fewer than N training samples — a feature present once is a
    memorised sample id, not a signal. `exclude` drops named columns outright; the caller
    passes `epoch_divergent_features` output there, and must disclose what it dropped.
    """
    counts: Counter[str] = Counter()
    for sample in train:
        counts.update(sample.features.keys())
    banned = set(exclude)
    names = sorted(
        name for name, count in counts.items() if count >= min_count and name not in banned
    )
    assert_no_label_leak(names)
    assert_no_retired_features(names)
    return names


def write_vocabulary(path: Path, vocabulary: list[str]) -> None:
    """Pin the vocabulary next to the model. Inference loads this and never rebuilds it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"schema_version": FEATURE_SCHEMA_VERSION, "features": list(vocabulary)},
            indent=2,
        )
        + "\n"
    )


def matrix(samples: list[Sample], vocabulary: list[str]) -> tuple[np.ndarray, np.ndarray]:
    """Project samples onto the frozen vocabulary. Returns (X, y).

    Uses `features.project` — the same function inference uses — so an unseen feature is
    dropped and a missing one is zero-filled, identically on both paths.
    """
    if not samples:
        return np.zeros((0, len(vocabulary)), dtype=float), np.zeros((0,), dtype=int)
    rows = [
        project(FeatureVector(schema_version=FEATURE_SCHEMA_VERSION, values=s.features), vocabulary)
        for s in samples
    ]
    features = np.asarray(rows, dtype=float)
    # A NaN silently poisons a linear model and is silently tolerated by a tree, so the
    # two disagree for a reason unrelated to the models. Fail here instead.
    if not np.isfinite(features).all():
        raise ValueError("non-finite feature values reached the matrix")
    return features, np.asarray([s.label for s in samples], dtype=int)


def random_split_indices(
    labels: np.ndarray, *, test_fraction: float = 0.2, seed: int = SEED
) -> tuple[np.ndarray, np.ndarray]:
    """Stratified random split over the pooled corpus, for the random-vs-time comparison.

    The random split is the number everyone quotes and the time split is the number that
    predicts field behaviour. Both are reported; the GAP is the finding.
    """
    rng = np.random.default_rng(seed)
    train_idx: list[int] = []
    test_idx: list[int] = []
    for value in (0, 1):
        members = np.flatnonzero(labels == value)
        rng.shuffle(members)
        cut = round(len(members) * test_fraction)
        test_idx.extend(members[:cut].tolist())
        train_idx.extend(members[cut:].tolist())
    return np.array(sorted(train_idx), dtype=int), np.array(sorted(test_idx), dtype=int)


def time_split_is_honest(corpus: Corpus) -> tuple[bool, str]:
    """Check that no test/calib time band also appears in train.

    Returns (ok, explanation). A time split whose bands overlap is a random split with
    extra steps, and reporting it as a time split would be the dishonest kind of wrong.
    """
    train_bands = {s.time_band for s in corpus.of_split("train")}
    later_bands = {s.time_band for s in corpus.of_split("calib", "test")}
    overlap = train_bands & later_bands
    if overlap:
        return False, f"time bands appear in both train and calib/test: {sorted(overlap)}"
    return True, f"train bands {sorted(train_bands)} are disjoint from {sorted(later_bands)}"


def repartition_holdout(
    corpus: Corpus, *, calib_fraction: float = 0.3, buckets: int = 10
) -> dict[str, Any]:
    """Re-cut the calib/test boundary inside the held-out bands. Mutates `corpus`.

    The shipped `samples.csv` puts 7 malware rows in calib and 92 in test. Seven positives
    cannot support a calibrator — measured: a Platt fit on that few made the test Brier
    strictly worse — so `P_cal` would have to be shipped uncalibrated, which is a real
    loss for a score whose whole point is that the probability means something.

    This re-cuts the boundary **within the already-held-out bands only**:

      * `train` is not touched, so test stays strictly newer than train and the split
        remains a time split. That is the property that matters and it is preserved.
      * Assignment is by `sha256` bucket, so it is deterministic, reproducible from the
        hash alone, and **independent of the label** — assigning by label would manufacture
        whatever calib/test balance flattered the numbers.

    Returns a report of exactly what moved. The caller must disclose it; a re-partitioned
    split reported as the shipped one would be a quiet change to what the numbers mean.
    """
    before = corpus.composition()
    cut = max(0, min(buckets, round(calib_fraction * buckets)))
    moved_to_calib = moved_to_test = 0
    repartitioned: list[Sample] = []
    for sample in corpus.samples:
        if sample.split == "train":
            repartitioned.append(sample)
            continue
        bucket = int(sample.sha256[:8], 16) % buckets if sample.sha256 else 0
        target = "calib" if bucket < cut else "test"
        if target != sample.split:
            if target == "calib":
                moved_to_calib += 1
            else:
                moved_to_test += 1
            sample = Sample(**{**sample.__dict__, "split": target})
        repartitioned.append(sample)
    corpus.samples = repartitioned
    after = corpus.composition()
    return {
        "applied": True,
        "rule": (
            f"sha256 bucket < {cut} of {buckets} -> calib, else test; applied to the "
            "held-out bands only, label-independent, train untouched"
        ),
        "calib_fraction_requested": calib_fraction,
        "moved_to_calib": moved_to_calib,
        "moved_to_test": moved_to_test,
        "before": {k: before[k] for k in ("calib", "test")},
        "after": {k: after[k] for k in ("calib", "test")},
    }


def summarise(corpus: Corpus) -> dict[str, Any]:
    """Everything a reader needs to judge whether a metric from this corpus is worth much."""
    ok, detail = time_split_is_honest(corpus)
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "sources": corpus.sources,
        "extracted": len(corpus),
        "skipped_failed_extraction": corpus.skipped_failed,
        "skipped_no_features": corpus.skipped_empty,
        "composition": corpus.composition(),
        "time_bands": corpus.bands(),
        "time_split_disjoint": ok,
        "time_split_detail": detail,
    }
