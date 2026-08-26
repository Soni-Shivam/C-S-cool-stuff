"""`LiveSandboxSource` — the orchestration half of M3, exercised against a fake VM.

Everything here runs on a laptop and nothing here detonates anything. That is the
point: the laptop's job in a live run is to *drive* the sealed detonator over IAP, and
the split is what CLAUDE.md's one stated rule protects. So the object under test owns
no execution at all — it owns sequencing, refusal, and provenance — and a fake
`DetonatorClient` stands in for the VM.

The refusals are the interesting assertions, not the happy path:

* an unreachable or stopped detonator raises rather than returning an empty trace,
  because an empty `DynamicTrace` asserts that the sample did nothing;
* an artifact whose containment was not verified **aborts**, and never downgrades to a
  warning on a trace somebody might still read;
* an artifact the harness marked unsafe to ingest is refused for the same reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.contracts.dynamic_trace import ObservationArtifact, TraceSourceKind
from drishti.contracts.frontier import Morph, MorphKind, SandboxPlan
from drishti.m3_dynamic.trace_source import (
    LiveSandboxSource,
    TraceSourceUnavailableError,
)

REPO = Path(__file__).resolve().parents[2]
OBSERVATIONS = REPO / "data" / "fixtures" / "observations"


def _an_artifact_with_observations() -> ObservationArtifact:
    for path in sorted(OBSERVATIONS.glob("*.json")):
        artifact = ObservationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        if artifact.observations and artifact.safe_for_ingestion:
            return artifact
    pytest.skip("no safely ingestible artifact in the fixture corpus")


class FakeDetonator:
    """Records what it was asked to do; executes nothing."""

    def __init__(self, artifact: ObservationArtifact | None = None, state: str = "RUNNING") -> None:
        self._artifact = artifact
        self._state = state
        self.calls: list[str] = []

    def instance_state(self) -> str:
        self.calls.append("instance_state")
        return self._state

    def stage(self, apk_path: Path, sha256: str) -> None:
        self.calls.append(f"stage:{sha256[:12]}")

    def detonate(self, sha256: str, *, morphs: tuple[Morph, ...], duration_s: int) -> None:
        self.calls.append(f"detonate:{sha256[:12]}:morphs={len(morphs)}")

    def collect(self, sha256: str, *, morphed: bool = False) -> ObservationArtifact:
        self.calls.append(f"collect:{sha256[:12]}")
        assert self._artifact is not None
        return self._artifact


def _plan(*morphs: Morph) -> SandboxPlan:
    return SandboxPlan(morphs=morphs)


def test_a_stopped_detonator_is_unavailable(tmp_path: Path) -> None:
    source = LiveSandboxSource(client=FakeDetonator(state="TERMINATED"))
    assert source.available() is False


def test_a_running_detonator_is_available() -> None:
    assert LiveSandboxSource(client=FakeDetonator(state="RUNNING")).available() is True


def test_it_refuses_rather_than_returning_an_empty_trace(tmp_path: Path) -> None:
    """An empty trace claims the sample did nothing. Refusal is a different statement."""
    source = LiveSandboxSource(client=FakeDetonator(state="TERMINATED"))
    with pytest.raises(TraceSourceUnavailableError):
        source.run(tmp_path / "sample.apk", _plan(), sha256="a" * 64)


def test_it_declares_itself_live() -> None:
    assert LiveSandboxSource(client=FakeDetonator()).kind is TraceSourceKind.LIVE


def test_a_full_run_sequences_stage_detonate_collect(tmp_path: Path) -> None:
    artifact = _an_artifact_with_observations()
    client = FakeDetonator(artifact)
    source = LiveSandboxSource(client=client)

    trace = source.run(tmp_path / "sample.apk", _plan(), sha256=artifact.sha256)

    assert [c.split(":")[0] for c in client.calls] == [
        "instance_state",
        "stage",
        "detonate",
        "collect",
    ]
    assert trace.source is TraceSourceKind.LIVE
    assert trace.synthetic is False
    assert trace.emulator_image == artifact.metadata.emulator_image


def test_unverified_containment_aborts(tmp_path: Path) -> None:
    """CLAUDE.md: a containment failure aborts. It never downgrades to a warning."""
    artifact = _an_artifact_with_observations()
    unverified = artifact.model_copy(
        update={
            "metadata": artifact.metadata.model_copy(update={"containment_verified": False}),
        }
    )
    source = LiveSandboxSource(client=FakeDetonator(unverified))
    with pytest.raises(TraceSourceUnavailableError, match="containment"):
        source.run(tmp_path / "sample.apk", _plan(), sha256=artifact.sha256)


def test_an_unsafe_artifact_is_refused(tmp_path: Path) -> None:
    """`safe_for_ingestion` gates the snapshot lifecycle, not just containment."""
    artifact = _an_artifact_with_observations()
    dirty = artifact.model_copy(
        update={"snapshot": artifact.snapshot.model_copy(update={"after_restore": "failed"})}
    )
    source = LiveSandboxSource(client=FakeDetonator(dirty))
    with pytest.raises(TraceSourceUnavailableError):
        source.run(tmp_path / "sample.apk", _plan(), sha256=artifact.sha256)


def test_morphs_are_passed_through_and_recorded(tmp_path: Path) -> None:
    """Pass 2 must be distinguishable from pass 1 in the trace itself."""
    artifact = _an_artifact_with_observations()
    client = FakeDetonator(artifact)
    morph = Morph(
        kind=MorphKind.INSTALL_PACKAGES,
        params={"packages": ["com.example.bank"]},
        rationale="the sample asked whether it was installed",
        derived_from=("ev_test",),
    )
    trace = LiveSandboxSource(client=client).run(
        tmp_path / "sample.apk", _plan(morph), sha256=artifact.sha256
    )
    assert "detonate:" in client.calls[2] and "morphs=1" in client.calls[2]
    assert trace.morphs_applied == (MorphKind.INSTALL_PACKAGES.value,)


def test_the_default_client_is_remote() -> None:
    """No local execution path may exist. The default must be the IAP client."""
    from drishti.m3_dynamic.detonator import RemoteDetonatorClient

    assert isinstance(LiveSandboxSource().client, RemoteDetonatorClient)
