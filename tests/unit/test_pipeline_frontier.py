"""The frontier branch fires on an observed probe, and never on nothing.

docs/PHASE_5_FRONTIER.md T5.5. This file exists because the branch previously had no
honest coverage: the only test that reached it relied on `_stub_trace` fabricating an
`EvasionObservation` for a sample that was never executed. Removing that fabrication
removed the coverage with it, which is exactly the trade a test suite should refuse to
make silently.

Both directions are asserted here, because only the pair is meaningful:

* given an observed probe, the frontier runs and the morph it plans cites that probe;
* given no observation, the frontier does not run at all.

The second is the honesty property. A morph with nothing behind it is a guess, and the
frontier's entire claim is that it responds to what the sandbox actually saw.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.config import Settings
from drishti.contracts.dynamic_trace import (
    DynamicTrace,
    EvasionObservation,
    TraceSourceKind,
)
from drishti.contracts.frontier import SandboxPlan
from drishti.contracts.job import Job, JobStage
from drishti.ledger.store import LedgerStore
from drishti.pipeline import Context, run_pipeline
from drishti.util import now
from tests.apk_fixtures import minimal_apk_bytes


class _ProbeThenStallSource:
    """A trace source whose pass 1 really did observe a package probe that missed.

    Pass 2 (morphs present) reports the payload firing, so the arc the frontier exists
    to produce — stall, synthesise, re-run, behaviour changes — is exercised end to end
    without a detonator.
    """

    def __init__(self) -> None:
        self.plans: list[SandboxPlan] = []

    @property
    def kind(self) -> TraceSourceKind:
        return TraceSourceKind.REPLAY

    def available(self) -> bool:
        return True

    def run(self, apk_path: Path, plan: SandboxPlan, *, sha256: str | None = None) -> DynamicTrace:
        self.plans.append(plan)
        if plan.morphs:
            return DynamicTrace(
                run_id="run_post",
                source=TraceSourceKind.REPLAY,
                detonated=True,
                outcome="completed",
                morphs_applied=tuple(m.kind.value for m in plan.morphs),
                synthetic=False,
            )
        return DynamicTrace(
            run_id="run_pre",
            source=TraceSourceKind.REPLAY,
            detonated=False,
            outcome="inconclusive",
            evasion_observations=(
                EvasionObservation(
                    probe_kind="installed_package",
                    queried="com.bank.example",
                    result="MISS",
                    t_ms=1200,
                    followed_by_stall=True,
                    inferred_requirement="a banking package must be present",
                ),
            ),
            synthetic=False,
        )


class _NothingObservedSource(_ProbeThenStallSource):
    """Pass 1 completed and saw nothing. There is no probe to answer."""

    def run(self, apk_path: Path, plan: SandboxPlan, *, sha256: str | None = None) -> DynamicTrace:
        self.plans.append(plan)
        return DynamicTrace(
            run_id="run_quiet",
            source=TraceSourceKind.REPLAY,
            detonated=False,
            outcome="inconclusive",
            evasion_observations=(),
            synthetic=False,
        )


@pytest.fixture
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "sample.apk"
    path.write_bytes(minimal_apk_bytes())
    return path


def _context(tmp_path: Path, source: _ProbeThenStallSource) -> Context:
    settings = Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        groq_api_key="gsk-test",
    )
    return Context(
        settings=settings,
        ledger=LedgerStore(settings.db_path, settings.ledger_key_path),
        trace_source=source,  # type: ignore[arg-type]
    )


def _stages(job: Job) -> list[str]:
    return [entry.stage.value for entry in job.stage_history]


def test_an_observed_probe_runs_the_frontier_and_a_second_pass(apk: Path, tmp_path: Path) -> None:
    source = _ProbeThenStallSource()
    ctx = _context(tmp_path, source)
    job = Job(
        id="job_frontier",
        sha256="c" * 64,
        filename="sample.apk",
        stage=JobStage.QUEUED,
        created_at=now(),
    )

    finished = run_pipeline(job=job, ctx=ctx, apk_path=apk)

    stages = _stages(finished)
    assert JobStage.FRONTIER.value in stages, "an observed probe must reach the frontier"
    assert JobStage.SANDBOX_2.value in stages, "the frontier must be followed by a second pass"
    # Two calls: pass 1 with no morphs, pass 2 carrying them. The second proves the plan
    # was actually applied rather than merely computed.
    assert len(source.plans) == 2
    assert not source.plans[0].morphs
    assert source.plans[1].morphs, "pass 2 must carry the morphs the frontier planned"


def test_nothing_observed_means_no_frontier_and_no_second_pass(apk: Path, tmp_path: Path) -> None:
    """The honesty property: no observation, no morph, no second detonation."""
    source = _NothingObservedSource()
    ctx = _context(tmp_path, source)
    job = Job(
        id="job_quiet",
        sha256="d" * 64,
        filename="sample.apk",
        stage=JobStage.QUEUED,
        created_at=now(),
    )

    finished = run_pipeline(job=job, ctx=ctx, apk_path=apk)

    stages = _stages(finished)
    assert JobStage.FRONTIER.value not in stages
    assert JobStage.SANDBOX_2.value not in stages
    assert len(source.plans) == 1, "a sample with nothing to answer is detonated once"
