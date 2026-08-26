"""A captured detonation replays as a *disclosed replay of a real measurement*.

`scripts/observation_to_trace.py` is the bridge between what the detonator writes
(`ObservationArtifact`) and what the demo replays (`TraceFixture`). The failure mode
this guards is the one CLAUDE.md's honesty requirements exist for: a fixture that
presents typed-in values as a measurement, or a replay that presents itself as live.

So the assertions here are about provenance, not about parsing:

* a converted fixture is `provenance.kind == "captured"`, so `ReplayTraceSource`
  leaves `synthetic=False` — this is a real execution, replayed;
* it still reports `source == REPLAY`, because a replay may never claim to be live;
* the emulator image, VM instance id and containment flag survive the conversion,
  because the UI's live-vs-replay badge is derived from those and not from a config;
* an artifact with no observations produces **no fixture at all**, rather than a
  fixture that replays as a sample which did nothing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from drishti.contracts.dynamic_trace import ObservationArtifact, TraceSourceKind
from drishti.contracts.frontier import Morph, MorphKind, SandboxPlan
from drishti.m3_dynamic.trace_source import (
    ReplayTraceSource,
    TraceFixture,
    TraceSourceUnavailableError,
)

REPO = Path(__file__).resolve().parents[2]
OBSERVATIONS = REPO / "data" / "fixtures" / "observations"
CONVERTER = REPO / "scripts" / "observation_to_trace.py"


def _artifacts() -> list[Path]:
    return sorted(OBSERVATIONS.glob("*.json"))


@pytest.fixture(scope="module")
def converted(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("traces")
    subprocess.run(
        [sys.executable, str(CONVERTER), *[str(p) for p in _artifacts()], "--out", str(out)],
        check=True,
        capture_output=True,
        cwd=REPO,
    )
    return out


def test_every_artifact_with_observations_becomes_a_fixture(converted: Path) -> None:
    expected = {
        a.sha256
        for a in (ObservationArtifact.model_validate_json(p.read_text()) for p in _artifacts())
        if a.observations
    }
    assert expected, "no captured artifact carries observations — nothing to replay"
    assert {p.stem for p in converted.glob("*.json")} == expected


def test_an_empty_artifact_produces_no_fixture(converted: Path) -> None:
    """"We could not observe it" and "it did nothing" are different statements."""
    empty = {
        a.sha256
        for a in (ObservationArtifact.model_validate_json(p.read_text()) for p in _artifacts())
        if not a.observations
    }
    assert empty, "expected at least one artifact with no observations"
    assert not (empty & {p.stem for p in converted.glob("*.json")})


def test_converted_fixtures_declare_themselves_captured(converted: Path) -> None:
    for path in converted.glob("*.json"):
        fixture = TraceFixture.model_validate_json(path.read_text())
        assert fixture.provenance.kind == "captured"
        assert fixture.provenance.source_sha256 == path.stem
        assert fixture.provenance.captured_from_image


def test_replay_is_a_disclosed_replay_of_a_real_measurement(converted: Path) -> None:
    source = ReplayTraceSource(converted)
    for path in converted.glob("*.json"):
        trace = source.run(Path("/dev/null"), SandboxPlan(), sha256=path.stem)
        assert trace.source == TraceSourceKind.REPLAY, "a replay must declare itself a replay"
        assert trace.synthetic is False, "a captured trace is a measurement, not a fixture"
        assert trace.containment_verified is True
        assert trace.emulator_image and trace.vm_instance_id
        assert trace.api_events, "a captured trace must carry the events it was made from"


def test_no_morphed_half_is_invented(converted: Path) -> None:
    """No morphed pass has been run, so pass 2 must fail rather than replay pass 1."""
    source = ReplayTraceSource(converted)
    path = next(iter(converted.glob("*.json")))
    assert TraceFixture.model_validate_json(path.read_text()).post_morph == {}

    # Pass 1 replays the captured run.
    assert source.run(Path("/dev/null"), SandboxPlan(), sha256=path.stem).detonated

    # Pass 2 has nothing behind it, and must say so instead of serving pass 1 again.
    morphed = SandboxPlan(
        morphs=(
            Morph(
                kind=MorphKind.INSTALL_PACKAGES,
                params={"packages": ["com.example.bank"]},
                rationale="test: a morphed pass that was never captured",
            ),
        )
    )
    with pytest.raises(TraceSourceUnavailableError):
        source.run(Path("/dev/null"), morphed, sha256=path.stem)
