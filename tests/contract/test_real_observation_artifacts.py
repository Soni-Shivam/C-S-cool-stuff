"""v2's wire contract can read the real harness output. CI gate.

The fixtures here are **real `ObservationArtifact` files** produced by v1's harness on
the sealed GCE detonator, rescued from the detonator disk on 2026-08-14 and stored in
full at `gs://drishti-v2-260814-artifacts/v1-provenance/observations/`.

Why this test exists: `ObservationArtifact` was ported from v1 with `extra="forbid"`,
and when the real artifacts were finally run through it, **all 14 failed** — over three
fields the harness emits (`duration_s`, `diagnostics`, `mitre_observed`) that the port
had dropped. A contract that cannot read the data it was designed for is the wrong
contract, and nothing would have caught that until the first P4 ingestion.

So: real data, in the repo, in CI, forever.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drishti.contracts.dynamic_trace import ObservationArtifact

FIXTURES = Path(__file__).resolve().parents[2] / "data" / "fixtures" / "observations"

#: The one artifact in this directory that is NOT a corpus row. `canary/` is authored by
#: this repo and its behaviour is bounded by CLAUDE.md, so it is a real detonation of a
#: provably inert sample rather than of vetted malware.
CANARY_PACKAGE = "in.drishti.canary"


def _artifacts() -> list[Path]:
    return sorted(FIXTURES.glob("*.json"))


def test_fixtures_are_present() -> None:
    assert _artifacts(), "real observation fixtures are missing from data/fixtures/observations"


@pytest.mark.parametrize("path", _artifacts(), ids=lambda p: p.name[:12])
def test_real_artifact_validates_under_the_v2_contract(path: Path) -> None:
    """The regression test for the three dropped fields."""
    artifact = ObservationArtifact.model_validate_json(path.read_text())
    assert artifact.sha256 == path.stem, "artifact must be stored under its own hash"
    assert artifact.schema_version == "1.0"


@pytest.mark.parametrize("path", _artifacts(), ids=lambda p: p.name[:12])
def test_real_artifact_round_trips(path: Path) -> None:
    """A real artifact survives our own serialisation, not just our parsing."""
    original = ObservationArtifact.model_validate_json(path.read_text())
    revived = ObservationArtifact.model_validate(json.loads(original.model_dump_json()))
    assert revived == original


@pytest.mark.parametrize("path", _artifacts(), ids=lambda p: p.name[:12])
def test_real_artifact_is_never_marked_simulated(path: Path) -> None:
    """`simulated: Literal[False]` — measured data must be unmistakable for synthetic."""
    assert ObservationArtifact.model_validate_json(path.read_text()).simulated is False


@pytest.mark.parametrize("path", _artifacts(), ids=lambda p: p.name[:12])
def test_every_observation_declares_itself_redacted(path: Path) -> None:
    """Redaction happened in the guest; the contract re-checks it here.

    `ObservationEvent` refuses to construct if `contains_sensitive_text` still matches,
    so this passing on real data means the in-guest redaction actually worked.
    """
    artifact = ObservationArtifact.model_validate_json(path.read_text())
    assert all(event.redacted for event in artifact.observations)


def test_a_completed_artifact_carries_containment_and_snapshot_evidence() -> None:
    """The safety claims are in the data, not just in a runbook.

    Containment verified before the run, and snapshot restore asserted afterwards with
    the package gone — that is what rules out cross-sample contamination.
    """
    completed = [
        a
        for a in (ObservationArtifact.model_validate_json(p.read_text()) for p in _artifacts())
        if a.outcome == "completed"
    ]
    assert completed, "expected at least one completed real artifact"
    for artifact in completed:
        assert artifact.metadata.containment_verified is True
        # `sample_kind` must be the TRUE kind, not a constant. Every artifact here is a
        # corpus row — labelled and VT-counted — except the canary, which this repo
        # authors and which is genuinely inert; `detonator_run.sh detonate` hardcodes
        # `vetted_malware`, so the canary is detonated through dynamic_analyze.py
        # directly to keep its provenance honest. Asserting the constant would have
        # forced the canary to be mislabelled as vetted malware to make a test pass.
        expected = "inert_fixture" if artifact.package == CANARY_PACKAGE else "vetted_malware"
        assert artifact.metadata.sample_kind == expected, artifact.sha256
        assert artifact.snapshot is not None
        assert artifact.snapshot.before_restore == "passed"
        assert artifact.snapshot.after_restore == "passed"
        assert artifact.snapshot.package_absent_after is True


def test_mitre_observed_matches_the_events_it_summarises() -> None:
    """The harness's summary field must agree with the events.

    If these ever diverge, a batch report keyed on `mitre_observed` would describe
    behaviour the event list does not support.
    """
    for path in _artifacts():
        artifact = ObservationArtifact.model_validate_json(path.read_text())
        from_events = {event.mitre for event in artifact.observations}
        assert set(artifact.mitre_observed) == from_events, path.name


def test_a_failed_artifact_records_why_and_claims_no_behaviour() -> None:
    """An install failure is a tooling outcome, not evidence about the sample.

    v1 originally scored install refusals as evasion, which inflated its evasion
    numbers (docs/CARRIED_FINDINGS.md defect 11). A failed artifact must carry a
    failure record and no observations.
    """
    failed = [
        a
        for a in (ObservationArtifact.model_validate_json(p.read_text()) for p in _artifacts())
        if a.outcome == "failed"
    ]
    assert failed, "expected at least one failed real artifact"
    for artifact in failed:
        assert artifact.failures, "a failed run must say why"
        assert artifact.observations == (), "a failed run claims no behaviour"
