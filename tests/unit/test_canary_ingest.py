"""M1 against a real, genuinely parseable APK.

docs/PHASE_0_FOUNDATIONS.md T0.9.

Until the canary was buildable, **every** fixture in this repo had a placeholder
manifest, so androguard always refused it and the ingest tests only ever exercised the
*degradation* path. The success path — package, label, versionCode, min/target SDK — was
covered by no test at all, which `PROGRESS.md` recorded as the most significant gap in
T0.10.

The APK is committed at `canary/dist/`, so this runs anywhere without a JDK. A missing
artifact is a failure, not a skip: it would mean the one APK we can safely analyse has
been lost.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.ledger.store import LedgerStore
from drishti.m1_ingest.ingest import ingest

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary-debug.apk"

#: The *installed* package id keeps the `.in` identity even though the Kotlin source
#: package cannot (`in` is a reserved keyword), because applicationId is only a string.
#: If this ever changes, the frontier's morph target and canary/README.md are both stale.
EXPECTED_PACKAGE = "in.drishti.canary"


@pytest.fixture(scope="module")
def canary_meta():
    assert CANARY.exists(), (
        f"{CANARY} is missing — rebuild it with `bash canary/build.sh`. "
        "It is committed precisely so the demo does not depend on a local toolchain."
    )
    store = LedgerStore("/tmp/drishti-canary-test.db", "/tmp/drishti-canary-test.key")
    store.open("job_canary_test")
    try:
        yield ingest(CANARY, store, filename="canary-debug.apk")
    finally:
        store.close()
        Path("/tmp/drishti-canary-test.db").unlink(missing_ok=True)


def test_the_manifest_actually_parses(canary_meta) -> None:
    """The androguard success path. Nothing else in the suite reaches it."""
    assert canary_meta.partial is False, f"expected a clean parse, got errors: {canary_meta.errors}"
    assert canary_meta.errors == ()


def test_manifest_facts_are_populated(canary_meta) -> None:
    assert canary_meta.package == EXPECTED_PACKAGE
    assert canary_meta.app_label == "DRISHTI Canary"
    assert canary_meta.version_name == "1.0"
    assert canary_meta.version_code == 1
    assert canary_meta.min_sdk == 26
    assert canary_meta.target_sdk == 35


def test_it_is_not_a_split_bundle(canary_meta) -> None:
    assert canary_meta.is_split is False
    assert canary_meta.split_names == ()


def test_an_unknown_sample_gets_a_positive_intel_floor(canary_meta) -> None:
    """Absence of intel is not evidence of innocence — a zero-day is unknown to everyone."""
    assert canary_meta.intel.verdict == "unknown"
    assert canary_meta.intel.known_bad_hash is False


def test_ingest_wrote_a_verifiable_chain(canary_meta) -> None:
    assert len(canary_meta.ledger_refs) >= 2  # FILE_META + THREAT_INTEL
