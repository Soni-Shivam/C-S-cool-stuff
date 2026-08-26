"""Build minimal `ObservationArtifact`s for tests, without a detonator.

The wire model is strict (`extra="forbid"`, no coercion) and carries a lot of required
provenance, so hand-writing one per test would bury the assertion under boilerplate.
This keeps the metadata fixed and honest — it is clearly a fixture, not a real run — and
lets a test say only what it is actually about.
"""

from __future__ import annotations

from drishti.contracts.dynamic_trace import (
    HarnessMetadata,
    ObservationArtifact,
    ObservationEvent,
    SnapshotLifecycle,
)

_START = "2026-08-26T10:00:00+00:00"


def metadata(**overrides: object) -> HarnessMetadata:
    base: dict[str, object] = {
        "harness_version": "test-harness-1",
        "hook_version": "test-hooks-1",
        "emulator_image": "drishti-m3-tools-v1",
        "emulator_serial": "emulator-5554",
        "avd_name": "drishti-avd",
        "sample_kind": "inert_fixture",
        "containment_verified": True,
        "containment_manifest_sha256": "c" * 64,
        "containment_verified_at": _START,
    }
    base.update(overrides)
    return HarnessMetadata(**base)  # type: ignore[arg-type]


def artifact_with(
    *details: tuple[str, str, str], outcome: str = "completed"
) -> ObservationArtifact:
    """`(source_hook, mitre, detail)` triples -> one completed, contained artifact."""
    events = tuple(
        ObservationEvent(
            technique=hook.split(".")[0],
            mitre=mitre,
            detail=detail,
            source_hook=hook,
            occurred_at=_START,
        )
        for hook, mitre, detail in details
    )
    return ObservationArtifact(
        sha256="a" * 64,
        package="com.example.sample",
        outcome=outcome,  # type: ignore[arg-type]
        observations=events,
        metadata=metadata(),
        snapshot=SnapshotLifecycle(
            name="clean",
            before_restore="passed",
            after_restore="passed",
            package_absent_after=True,
        ),
        started_at=_START,
        finished_at=_START,
        diagnostics=("containment:1234567890; hooks completed",),
    )
