"""Both `TraceSource` implementations satisfy the ABC and cannot misrepresent themselves.

docs/PHASE_0_FOUNDATIONS.md T0.7 acceptance criterion, docs/01_DATA_CONTRACTS.md §3.1.
CI gate.

The interface conformance half is mechanical. The half that matters is the honesty
half: a replayed trace must never be able to claim it was live, and a hand-authored
fixture must never be able to claim it was measured. Those are enforced in the loader
rather than left to whoever edits a JSON file, and these tests are what keep them
enforced.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drishti.contracts.dynamic_trace import DynamicTrace, TraceSourceKind
from drishti.contracts.frontier import Morph, MorphKind, SandboxPlan
from drishti.m3_dynamic.trace_source import (
    DEFAULT_FIXTURE_DIR,
    LiveSandboxSource,
    ReplayTraceSource,
    TraceSource,
    TraceSourceUnavailableError,
    resolve_trace_source,
)

DEMO_SHA = "deadbeef" * 8
REPO_FIXTURES = Path(__file__).resolve().parents[2] / DEFAULT_FIXTURE_DIR

MORPHED = SandboxPlan(
    morphs=(
        Morph(
            kind=MorphKind.INSTALL_PACKAGES,
            params={"packages": ["com.sbi.yono"]},
            rationale="pass 1 probed and stalled",
        ),
    ),
    pass_num=2,
)


@pytest.fixture
def replay() -> ReplayTraceSource:
    return ReplayTraceSource(REPO_FIXTURES)


class _NoLab:
    """A detonator that is not there. Records what it was asked, executes nothing."""

    def __init__(self, state: str = "UNCONFIGURED") -> None:
        self._state = state
        self.calls: list[str] = []

    def instance_state(self) -> str:
        self.calls.append("instance_state")
        return self._state

    def stage(self, apk_path: Path, sha256: str) -> None:
        self.calls.append("stage")

    def detonate(self, sha256: str, *, morphs: tuple, duration_s: int) -> None:
        self.calls.append("detonate")

    def collect(self, sha256: str, *, morphed: bool = False):
        self.calls.append("collect")
        raise AssertionError("collect must never be reached without a running detonator")


# ── interface conformance ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "source",
    # The live source is given a fake detonator on purpose: `available()` is a real
    # health probe now, and a CI gate that shells out to `gcloud` would both be slow and
    # break CLAUDE.md's rule that CI never touches GCP.
    [LiveSandboxSource(client=_NoLab()), ReplayTraceSource(REPO_FIXTURES)],
)
def test_both_implementations_satisfy_the_abc(source: TraceSource) -> None:
    assert isinstance(source, TraceSource)
    assert isinstance(source.available(), bool)
    assert isinstance(source.kind, TraceSourceKind)


def test_live_source_is_unavailable_without_a_configured_lab() -> None:
    """It raises rather than degrading.

    A live source that quietly returned an empty trace would make a missing sandbox
    indistinguishable from a sample that did nothing.

    With no `DRISHTI_GCP_PROJECT` there is nowhere a sample may legally be executed, so
    the source reports itself unavailable and refuses. This is the same refusal the P0
    stub made, now for a real reason instead of a hardcoded `False` — the live path is
    implemented (T4.1), it simply has no lab to drive here.
    """
    live = LiveSandboxSource(settings=None, client=_NoLab())
    assert live.available() is False
    assert live.kind is TraceSourceKind.LIVE
    with pytest.raises(TraceSourceUnavailableError, match="detonator is not running"):
        live.run(Path("/nonexistent.apk"), SandboxPlan(), sha256="a" * 64)


def test_live_source_never_starts_the_vm_as_a_side_effect() -> None:
    """Bringing the lab up is an operator action, never a consequence of a job.

    An idle nested-virt VM is the single fastest way to consume the research budget
    (CLAUDE.md, cost guardrails), so `available()` reports the state and stops there.
    """
    probe = _NoLab(state="TERMINATED")
    assert LiveSandboxSource(client=probe).available() is False
    assert probe.calls == ["instance_state"], "no start, stage or detonate may be issued"


def test_replay_source_is_available_with_the_committed_fixture(replay) -> None:
    assert replay.available() is True
    assert replay.has_fixture_for(DEMO_SHA)


def test_replay_raises_for_an_unknown_sample(replay) -> None:
    with pytest.raises(TraceSourceUnavailableError, match="no replay fixture"):
        replay.run(Path("/nonexistent.apk"), SandboxPlan(), sha256="f" * 64)


# ── the pre/post-morph arc ───────────────────────────────────────────────────
def test_pre_morph_half_shows_probe_miss_stall(replay) -> None:
    """Pass 1: the sample does nothing. This is the whole problem, in data."""
    trace = replay.run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)

    assert isinstance(trace, DynamicTrace)
    assert trace.detonated is False
    assert trace.outcome == "inconclusive", "a sample that emitted nothing is not benign"
    assert trace.evasion_observations, "the frontier needs an observation to respond to"

    probe = trace.evasion_observations[0]
    assert probe.result == "MISS"
    assert probe.followed_by_stall is True
    assert probe.inferred_requirement


def test_post_morph_half_shows_detonation(replay) -> None:
    """Pass 2: after environment synthesis, the payload fires."""
    trace = replay.run(Path("/x.apk"), MORPHED, sha256=DEMO_SHA)

    assert trace.detonated is True
    assert trace.detonation_reason == "exfil_observed"
    assert trace.outcome == "completed"
    assert trace.dex_loads, "a dropper should show runtime code loading"
    assert trace.dex_loads[0].in_original_apk is False
    assert trace.network_flows, "exfil should be visible"
    assert trace.decrypted_blobs, "plaintext-before-encryption is the anti-evasion beat"


def test_the_half_is_selected_by_plan_morphs(replay) -> None:
    """`plan.morphs` is the switch — exactly as a live source would behave."""
    assert replay.run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA).detonated is False
    assert replay.run(Path("/x.apk"), MORPHED, sha256=DEMO_SHA).detonated is True


def test_applied_morphs_are_recorded_on_the_trace(replay) -> None:
    trace = replay.run(Path("/x.apk"), MORPHED, sha256=DEMO_SHA)
    assert trace.morphs_applied == ("install_packages",)


def test_run_ids_are_unique_per_replay(replay) -> None:
    """Two replays are two runs. Reusing a run_id would collapse them in the ledger."""
    first = replay.run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)
    second = replay.run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)
    assert first.run_id != second.run_id


# ── the honesty properties ───────────────────────────────────────────────────
def test_a_replay_can_never_claim_to_be_live(replay, tmp_path) -> None:
    """Even a fixture that says `source: live` comes back as REPLAY.

    The disclosure cannot depend on whoever wrote the JSON. This is the property that
    makes disclosed replay honest rather than a promise.
    """
    fixture = json.loads((REPO_FIXTURES / f"{DEMO_SHA}.json").read_text())
    fixture["pre_morph"]["source"] = "live"
    fixture["provenance"] = {"kind": "captured", "source_sha256": "a" * 64}
    path = tmp_path / f"{DEMO_SHA}.json"
    path.write_text(json.dumps(fixture))

    trace = ReplayTraceSource(tmp_path).run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)
    assert trace.source is TraceSourceKind.REPLAY


def test_hand_authored_fixtures_are_forced_to_declare_themselves(replay) -> None:
    """The committed P0 fixture is hand-authored, so it must say so.

    `synthetic` and `partial` flow into the report's Limitations section, so a typed-up
    trace cannot present itself as a measurement.
    """
    trace = replay.run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)
    assert trace.synthetic is True
    assert trace.partial is True
    assert any("hand-authored" in e for e in trace.errors)


def test_a_fixture_cannot_lie_about_being_synthetic(tmp_path) -> None:
    """`synthetic: false` in a hand_authored fixture is overridden, not honoured."""
    fixture = json.loads((REPO_FIXTURES / f"{DEMO_SHA}.json").read_text())
    fixture["pre_morph"]["synthetic"] = False
    (tmp_path / f"{DEMO_SHA}.json").write_text(json.dumps(fixture))

    trace = ReplayTraceSource(tmp_path).run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)
    assert trace.synthetic is True


def test_a_captured_fixture_is_not_marked_synthetic(tmp_path) -> None:
    """The P4 case: replaying a real capture is legitimate and not 'synthetic'.

    It is still disclosed as a replay via `source`, which is the honest distinction.
    """
    fixture = json.loads((REPO_FIXTURES / f"{DEMO_SHA}.json").read_text())
    fixture["provenance"] = {
        "kind": "captured",
        "source_sha256": "b" * 64,
        "captured_from_image": "drishti-m3-tools-v1",
    }
    (tmp_path / f"{DEMO_SHA}.json").write_text(json.dumps(fixture))

    trace = ReplayTraceSource(tmp_path).run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)
    assert trace.synthetic is False
    assert trace.source is TraceSourceKind.REPLAY


def test_a_malformed_fixture_fails_loudly(tmp_path) -> None:
    """A fixture that has drifted from the contract must not half-populate a trace."""
    (tmp_path / f"{DEMO_SHA}.json").write_text(
        json.dumps(
            {
                "fixture_version": "1.0",
                "sha256": DEMO_SHA,
                "provenance": {"kind": "hand_authored"},
                "pre_morph": {"detonated": False, "not_a_real_field": 1},
                "post_morph": {},
            }
        )
    )
    with pytest.raises(Exception, match=r"extra_forbidden|Extra inputs|validation"):
        ReplayTraceSource(tmp_path).run(Path("/x.apk"), SandboxPlan(), sha256=DEMO_SHA)


# ── mode resolution ──────────────────────────────────────────────────────────
def test_auto_falls_back_to_replay_while_live_is_unavailable() -> None:
    """The parachute, wired in at hour zero so the H40 tripwire is a 20-minute switch."""
    source = resolve_trace_source("auto", fixture_dir=REPO_FIXTURES, client=_NoLab())
    assert isinstance(source, ReplayTraceSource)


def test_explicit_live_does_not_silently_become_replay() -> None:
    """Asking for live and getting replay would make the disclosure meaningless."""
    source = resolve_trace_source("live", fixture_dir=REPO_FIXTURES, client=_NoLab())
    assert isinstance(source, LiveSandboxSource)
    with pytest.raises(TraceSourceUnavailableError):
        source.run(Path("/x.apk"), SandboxPlan(), sha256="a" * 64)


def test_explicit_replay_is_replay() -> None:
    assert isinstance(resolve_trace_source("replay", fixture_dir=REPO_FIXTURES), ReplayTraceSource)


# ── the committed fixture itself ─────────────────────────────────────────────
def test_committed_fixture_is_valid_and_declares_its_provenance(replay) -> None:
    """Guards the artefact the contracts doc calls the most important in the build."""
    fixture = replay.load_fixture(DEMO_SHA)
    assert fixture.fixture_version == "1.0"
    assert fixture.provenance.kind == "hand_authored"
    assert fixture.provenance.note, "a hand-authored fixture must explain what it is"
    assert fixture.pre_morph and fixture.post_morph, "both halves are required"


def test_no_fixture_contains_an_apk_or_key(replay) -> None:
    """Fixtures are JSON traces. Samples and keys never enter the repository."""
    for path in REPO_FIXTURES.glob("*.json"):
        blob = path.read_text()
        assert "PK" not in blob
        assert "BEGIN PRIVATE KEY" not in blob
