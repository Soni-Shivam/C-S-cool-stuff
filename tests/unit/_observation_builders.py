"""Build minimal `ObservationArtifact`s for tests, without a detonator.

The wire model is strict (`extra="forbid"`, no coercion) and carries a lot of required
provenance, so hand-writing one per test would bury the assertion under boilerplate.
This keeps the metadata fixed and honest — it is clearly a fixture, not a real run — and
lets a test say only what it is actually about.
"""

from __future__ import annotations

from datetime import datetime

from drishti.contracts.dynamic_trace import (
    CapturedFlow,
    HarnessMetadata,
    ObservationArtifact,
    ObservationEvent,
    SnapshotLifecycle,
)

_START = "2026-08-26T10:00:00+00:00"

#: The run's start as epoch milliseconds. `CapturedFlow.t_ms_epoch` is wall-clock while
#: every trace-side `t_ms` is an offset from the run's start, so a test that wants a
#: captured flow "4.2s into the run" has to say so in the proxy's own time base.
START_EPOCH_MS = int(datetime.fromisoformat(_START).timestamp() * 1000)


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


def captured_flow(
    host: str,
    *,
    at_ms: int = 0,
    method: str = "GET",
    path: str = "/",
    scheme: str = "http",
    status: int | None = 200,
    resp_body_preview: str = "",
    synthesised: bool = False,
    served_kind: str | None = None,
) -> CapturedFlow:
    """One proxy-captured flow, `at_ms` milliseconds into the run.

    `at_ms` is run-relative for the test's convenience and converted to the wall-clock
    base the contract actually carries, so a test never has to spell an epoch out.
    """
    return CapturedFlow(
        t_ms_epoch=START_EPOCH_MS + at_ms,
        method=method,
        scheme=scheme,
        host=host,
        path=path,
        status=status,
        resp_body_preview=resp_body_preview,
        synthesised=synthesised,
        served_kind=served_kind,
    )


def artifact_with(
    *details: tuple[str, str, str],
    outcome: str = "completed",
    captured_flows: tuple[CapturedFlow, ...] = (),
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
        captured_flows=captured_flows,
    )
