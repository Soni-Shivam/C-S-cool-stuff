"""M1 `ingest()` against a real, genuinely parseable APK.

docs/PHASE_0_FOUNDATIONS.md T0.9, T0.10.

Every synthetic fixture in this repo carries a placeholder manifest, so androguard
refuses it and the M1 tests only ever exercise the **degradation** path. `PROGRESS.md`
recorded that under T0.10 as the most significant gap in the task:

    "No genuinely parseable APK has been ingested [...] the androguard success path is
     exercised only by the code, never by a test."

`test_m2_static.py` now analyses the canary, but that is M2's `analyse()`. M1's
`ingest()` — manifest facts, `partial`, `errors` — is a different code path and nothing
asserts its success case. This does.

The APK is committed at `canary/dist/`, so this runs anywhere without a JDK. A missing
artifact **fails** rather than skips: a skip would quietly restore the blind spot.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.ledger.store import LedgerStore
from drishti.m1_ingest.ingest import ingest

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"

#: `in` is a reserved word in Kotlin, so the *source* package is backtick-escaped — but
#: the INSTALLED package id keeps the `.in` identity, because applicationId is only a
#: string. If this changes, the frontier's morph target and canary/README.md are stale.
EXPECTED_PACKAGE = "in.drishti.canary"


@pytest.fixture(scope="module")
def canary_meta(tmp_path_factory):
    assert CANARY.exists(), (
        f"{CANARY} is missing — rebuild with `bash canary/build.sh`. It is committed "
        "precisely so neither the tests nor the demo depend on a local toolchain."
    )
    tmp = tmp_path_factory.mktemp("canary-ingest")
    store = LedgerStore(tmp / "ledger.db", tmp / "key.pem")
    store.open("job_canary_test")
    try:
        yield ingest(CANARY, store, filename="canary.apk")
    finally:
        store.close()


def test_the_manifest_actually_parses(canary_meta) -> None:
    """The androguard success path. Nothing else in the suite reaches it via M1."""
    assert canary_meta.partial is False, f"expected a clean parse, got: {canary_meta.errors}"
    assert canary_meta.errors == ()


def test_manifest_facts_are_populated(canary_meta) -> None:
    assert canary_meta.package == EXPECTED_PACKAGE
    assert canary_meta.app_label == "DRISHTI Canary"
    assert canary_meta.version_name == "1.0"
    assert canary_meta.version_code == 1
    assert canary_meta.min_sdk == 26
    assert canary_meta.target_sdk == 35


def test_a_real_apk_is_not_mistaken_for_a_split_bundle(canary_meta) -> None:
    assert canary_meta.is_split is False
    assert canary_meta.split_names == ()


def test_an_unknown_sample_gets_a_positive_intel_floor(canary_meta) -> None:
    """Absence of intel is not evidence of innocence — a zero-day is unknown to everyone."""
    assert canary_meta.intel.verdict == "unknown"
    assert canary_meta.intel.known_bad_hash is False


def test_ingest_recorded_evidence(canary_meta) -> None:
    assert len(canary_meta.ledger_refs) >= 2  # FILE_META + THREAT_INTEL
