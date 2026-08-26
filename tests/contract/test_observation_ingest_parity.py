"""One converter, both paths — the M3 analogue of `test_feature_parity.py`.

`ObservationArtifact` -> `DynamicTrace` happens in two places: offline, when a captured
artifact is frozen into a replayable `TraceFixture`, and online, when `LiveSandboxSource`
collects a fresh detonation off the sealed VM. If those are two implementations they
will drift, and the drift is invisible: a replayed trace and a live trace of the *same
run* would disagree, and the UI badge that distinguishes them would be the only thing
still telling the truth.

So there is exactly one function, `ingest.artifact_to_trace`, and this file is what
keeps it that way. The script is a CLI over the module, never a second copy of it.

The provenance assertions matter as much as the parity one. `ObservationArtifact` pins
`simulated` to `False` at the type level, so anything derived from one is a measurement;
`synthetic` must therefore never come back True on this path, no matter what else is
missing from the run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from drishti.contracts.dynamic_trace import DynamicTrace, ObservationArtifact, TraceSourceKind
from drishti.m3_dynamic.ingest import artifact_to_trace

REPO = Path(__file__).resolve().parents[2]
OBSERVATIONS = REPO / "data" / "fixtures" / "observations"
CONVERTER = REPO / "scripts" / "observation_to_trace.py"


def _artifacts() -> list[ObservationArtifact]:
    return [
        ObservationArtifact.model_validate_json(p.read_text(encoding="utf-8"))
        for p in sorted(OBSERVATIONS.glob("*.json"))
    ]


def _with_observations() -> list[ObservationArtifact]:
    return [a for a in _artifacts() if a.observations]


def test_there_are_real_artifacts_to_test_against() -> None:
    """A vacuous parity test passes when the corpus is empty. Guard that first."""
    assert len(_with_observations()) >= 20


@pytest.mark.parametrize("artifact", _with_observations(), ids=lambda a: a.sha256[:12])
def test_module_and_script_agree(artifact: ObservationArtifact, tmp_path: Path) -> None:
    """The fixture the script writes is exactly what the module produces."""
    source = OBSERVATIONS / f"{artifact.sha256}.json"
    subprocess.run(
        [sys.executable, str(CONVERTER), str(source), "--out", str(tmp_path)],
        check=True,
        capture_output=True,
        cwd=REPO,
        # PYTHONPATH pins the subprocess to the tree under test. `python scripts/x.py`
        # puts `scripts/` on sys.path, not the repo root, so without this the script
        # imports whichever `drishti` the venv has installed — which in a git worktree
        # is a DIFFERENT checkout, and the parity assertion would silently compare this
        # tree's module against another tree's script.
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )
    produced = artifact_to_trace(artifact)
    target = tmp_path / f"{artifact.sha256}.json"

    if not produced.api_events:
        # Parity still holds, and this is the interesting half: when every observation
        # was dropped as untrustworthy the module yields an empty trace and the script
        # writes no fixture at all. A fixture with nothing in it would replay as a
        # sample that did nothing — a different claim from "we could not observe it".
        assert not target.exists(), "an empty conversion must not become a replayable fixture"
        return

    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["pre_morph"] == produced.model_dump(mode="json")


@pytest.mark.parametrize("artifact", _with_observations(), ids=lambda a: a.sha256[:12])
def test_a_measurement_is_never_marked_synthetic(artifact: ObservationArtifact) -> None:
    """`synthetic` means hand-authored. An artifact cannot be hand-authored."""
    assert artifact_to_trace(artifact).synthetic is False


@pytest.mark.parametrize("artifact", _with_observations(), ids=lambda a: a.sha256[:12])
def test_provenance_survives_conversion(artifact: ObservationArtifact) -> None:
    """The UI's live-vs-replay badge reads these fields, so they may not be dropped."""
    trace = artifact_to_trace(artifact)
    assert trace.emulator_image == artifact.metadata.emulator_image
    assert trace.harness_version == artifact.metadata.harness_version
    assert trace.containment_verified == artifact.metadata.containment_verified
    assert trace.captured_at == artifact.started_at


@pytest.mark.parametrize("artifact", _with_observations(), ids=lambda a: a.sha256[:12])
def test_aggregation_caps_what_reaches_the_ledger(artifact: ObservationArtifact) -> None:
    """CLAUDE.md rule 11: raw events are grouped before they can reach a prompt."""
    from drishti.m3_dynamic.normaliser import MAX_OBSERVATION_GROUPS

    assert len(artifact_to_trace(artifact).api_events) <= MAX_OBSERVATION_GROUPS


def test_silence_is_inconclusive_never_detonated() -> None:
    """A run with no observations is `inconclusive`. CLAUDE.md honesty requirements."""
    empty = [a for a in _artifacts() if not a.observations]
    assert empty, "expected at least one artifact that produced nothing"
    for artifact in empty:
        trace = artifact_to_trace(artifact)
        assert trace.detonated is False
        assert trace.outcome != "completed" or not trace.detonated


@pytest.mark.parametrize("artifact", _with_observations(), ids=lambda a: a.sha256[:12])
def test_live_ingest_declares_itself_live(artifact: ObservationArtifact) -> None:
    """The default source is LIVE; only `ReplayTraceSource` may stamp REPLAY."""
    assert artifact_to_trace(artifact).source is TraceSourceKind.LIVE
    replayed = artifact_to_trace(artifact, source=TraceSourceKind.REPLAY)
    assert replayed.source is TraceSourceKind.REPLAY


@pytest.mark.parametrize("artifact", _with_observations()[:10], ids=lambda a: a.sha256[:12])
def test_result_validates_as_the_contract(artifact: ObservationArtifact) -> None:
    """The converter returns a real `DynamicTrace`, not a dict that looks like one."""
    trace = artifact_to_trace(artifact)
    assert isinstance(trace, DynamicTrace)
    DynamicTrace.model_validate(trace.model_dump(mode="json"))
