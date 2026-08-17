"""R3 mitigation: one extractor, one vocabulary, one vector — for train and inference.

docs/PHASE_2_ML_AND_SCORING.md T2.1, docs/00_GUIDING_MAP.md §11 risk R3.

R3 is rated **High probability / "model useless in prod"**: a model trained on features
the inference path cannot reproduce. The roadmap names exactly two defences, and this
file is both of them.

    "`features.py` is the *single* extractor used by both train and infer. Contract test
     asserts identical vector for a fixture APK."

    "Vocabularies are computed once on the training set and frozen into
     `models/vocab_v1.json`. Inference loads that file. Never recompute a vocab at
     inference. Assert `len(vector) == len(vocab)` on both paths."

The golden file is committed. If a change to the extractor alters it, that diff must be
intentional and reviewed — which is the whole point during the sleep-deprived hours.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse
from drishti.m5_ml.features import (
    FEATURE_SCHEMA_VERSION,
    build_vocabulary,
    extract,
    load_vocabulary,
    project,
)

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "canary" / "dist" / "canary.apk"
GOLDEN = REPO / "data" / "fixtures" / "features" / "canary.json"


@pytest.fixture(scope="module")
def canary_features(tmp_path_factory):
    assert CANARY.exists(), f"{CANARY} is missing — run `bash canary/build.sh`"
    tmp = tmp_path_factory.mktemp("parity")
    store = LedgerStore(tmp / "l.db", tmp / "k.pem")
    store.open("job_parity")
    try:
        yield extract(analyse(CANARY, store))
    finally:
        store.close()


def test_extraction_is_deterministic(canary_features, tmp_path_factory) -> None:
    """Same APK, same features. A dict ordering change here silently breaks training."""
    tmp = tmp_path_factory.mktemp("parity2")
    store = LedgerStore(tmp / "l.db", tmp / "k.pem")
    store.open("job_parity2")
    try:
        again = extract(analyse(CANARY, store))
    finally:
        store.close()
    assert canary_features.values == again.values
    assert list(canary_features.values) == list(again.values), "key ORDER must be stable too"


def test_matches_the_golden_file(canary_features) -> None:
    """The R3 tripwire. Any extractor change that moves this must be a reviewed diff."""
    assert GOLDEN.exists(), (
        f"{GOLDEN} is missing — regenerate with "
        "`uv run python -m drishti.m5_ml.features --write-golden`"
    )
    golden = json.loads(GOLDEN.read_text())
    assert golden["schema_version"] == FEATURE_SCHEMA_VERSION, (
        "schema version moved; regenerate the golden file deliberately"
    )
    assert canary_features.values == pytest.approx(golden["values"]), (
        "feature extraction changed. If intentional, regenerate the golden file "
        "in the SAME commit so the diff is reviewable."
    )


def test_every_specified_family_is_present(canary_features) -> None:
    """PHASE_2 T2.1 enumerates the families. A silently dropped family is skew."""
    families = {key.split(":", 1)[0] for key in canary_features.values}
    required = {
        "perm",
        "combo",
        "component",
        "intent",
        "sink",
        "reach",
        "api",
        "url",
        "archive",
        "cert",
        "drift",
        "manifest",
    }
    missing = required - families
    assert missing == set(), f"feature families absent from the extractor: {sorted(missing)}"


# ── vocabulary pinning ───────────────────────────────────────────────────────
def test_projection_width_equals_the_vocabulary(canary_features) -> None:
    """`len(vector) == len(vocab)` on both paths — the roadmap's explicit assertion."""
    vocab = build_vocabulary([canary_features])
    vector = project(canary_features, vocab)
    assert len(vector) == len(vocab)


def test_inference_never_recomputes_the_vocabulary(canary_features) -> None:
    """A feature unseen at training time must be DROPPED, not appended.

    Appending would shift every downstream column and produce a vector the model was
    never trained on — the exact shape of R3.
    """
    vocab = build_vocabulary([canary_features])
    unseen = type(canary_features)(
        schema_version=canary_features.schema_version,
        values={**canary_features.values, "perm:BRAND_NEW_PERMISSION": 1.0},
    )
    vector = project(unseen, vocab)
    assert len(vector) == len(vocab), "an unseen feature must not widen the vector"


def test_a_missing_feature_is_zero_filled_not_omitted(canary_features) -> None:
    vocab = build_vocabulary([canary_features])
    sparse = type(canary_features)(schema_version=canary_features.schema_version, values={})
    vector = project(sparse, vocab)
    assert len(vector) == len(vocab)
    assert all(value == 0.0 for value in vector)


def test_vocabulary_round_trips_through_disk(canary_features, tmp_path) -> None:
    """Inference loads the frozen file; it must survive serialisation unchanged."""
    vocab = build_vocabulary([canary_features])
    path = tmp_path / "vocab_v1.json"
    path.write_text(json.dumps({"schema_version": FEATURE_SCHEMA_VERSION, "features": vocab}))
    assert load_vocabulary(path) == vocab


def test_projection_is_order_stable(canary_features) -> None:
    """Column i must mean the same thing on every call, or the model reads noise."""
    vocab = build_vocabulary([canary_features])
    assert project(canary_features, vocab) == project(canary_features, vocab)
    assert vocab == sorted(vocab), "vocabulary must be sorted so column order is canonical"
