"""The P0 exit criterion: upload -> stages -> ledger -> verified chain.

docs/PHASE_0_FOUNDATIONS.md T0.5 and the Phase 0 Definition of Done.

Nothing is analysed here. What is being proved is that the *skeleton is load-bearing*:
stages transition in the canonical order, the conditional frontier branch is taken,
every stage leaves a ledger node, the chain verifies, and a crash becomes evidence
rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.job import Job, JobStage
from drishti.ledger.store import LedgerStore
from drishti.pipeline import STAGES_IN_ORDER, Context, run_pipeline
from drishti.util import new_id, now

#: Node count for a run over the SYNTHETIC fixture, whose manifest is a placeholder.
#:
#: It dropped from 12 to 10 when the real M2 and M4 were wired in, and both losses are
#: correct rather than regressions:
#:   * no MANIFEST_ENTRY — androguard cannot parse the placeholder, so there is no
#:     manifest fact to record. The stub invented one.
#:   * one TECHNIQUE_MAP instead of two — with no static evidence to cite, M4 refuses to
#:     make a claim at all rather than append an ungrounded AI_CLAIM the ledger would
#:     reject (CLAUDE.md rule 5).
#:
#: It then rose to 16 when the real M6 was wired in, because the scorer emits ONE NODE
#: PER FACTOR at each of the two score stages instead of a single stub node. That is the
#: mechanism behind "every score point traces back to an artefact" — without those nodes
#: the claim is marketing rather than a property.
#:
#: A genuinely parseable APK produces more; see `test_a_real_apk_produces_more_evidence`.
EXPECTED_NODES_PER_RUN = 16


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        groq_api_key="gsk-test",
        job_workers=2,
    )


@pytest.fixture
def apk(tmp_path):
    """A structurally valid APK-shaped zip.

    Must be a real zip since T0.10: M1's guards reject a corrupt archive outright, and
    they are right to. The manifest inside is a placeholder, so androguard refuses it and
    M1 returns partial=True — the degradation path, exercised for free on every run.
    """
    from tests.apk_fixtures import write_minimal_apk

    return write_minimal_apk(tmp_path / "sample.apk")


def _job(sha256: str = "a" * 64) -> Job:
    return Job(
        id=new_id("job"),
        sha256=sha256,
        filename="sample.apk",
        stage=JobStage.QUEUED,
        created_at=now(),
    )


# ── the pipeline itself ──────────────────────────────────────────────────────
def test_pipeline_walks_every_stage_and_chain_verifies(settings, apk) -> None:
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    events = []
    ctx = Context(settings=settings, ledger=store, on_event=events.append)
    job = _job()

    finished = run_pipeline(job, ctx, apk_path=apk)

    assert finished.stage == JobStage.DONE, finished.error

    completed = [e.stage for e in events if e.status == "completed"]
    assert completed == list(STAGES_IN_ORDER), "stages must run in canonical §7.1 order"

    # 11 stages, but real M1 (T0.10) writes FILE_META *and* THREAT_INTEL — intel is
    # recorded even when nothing is known, because "no feed had an opinion on this file"
    # is a finding and `gamma` reads whether intel exists at all.
    assert store.count(job.id) == EXPECTED_NODES_PER_RUN

    verification = store.verify_chain(job.id)
    assert verification.ok is True, verification.reason
    assert verification.node_count == EXPECTED_NODES_PER_RUN
    store.close()


def test_p0_exit_criterion_at_least_five_ledger_nodes(settings, apk) -> None:
    """PHASE_0's stated exit criterion, asserted literally."""
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    job = _job()
    run_pipeline(job, Context(settings=settings, ledger=store), apk_path=apk)
    assert store.count(job.id) >= 5
    assert store.verify_chain(job.id).ok is True
    store.close()


def test_conditional_frontier_branch_is_taken(settings, apk) -> None:
    """The branch the whole demo narrative hangs on must actually execute.

    Pass 1 reports an evasion observation and does not detonate, so §7.1 requires
    FRONTIER and SANDBOX_2 to run. A skeleton that never takes its conditional path
    has not been tested.
    """
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    events = []
    job = _job()
    run_pipeline(
        job,
        Context(settings=settings, ledger=store, on_event=events.append),
        apk_path=apk,
    )
    stages = {e.stage for e in events}
    assert JobStage.FRONTIER in stages
    assert JobStage.SANDBOX_2 in stages
    store.close()


def test_preliminary_score_is_emitted_before_the_sandbox(settings, apk) -> None:
    """Two-verdict design is a product requirement (§7), not an implementation detail."""
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    events = []
    run_pipeline(
        _job(),
        Context(settings=settings, ledger=store, on_event=events.append),
        apk_path=apk,
    )
    order = [e.stage for e in events if e.status == "completed"]
    assert order.index(JobStage.SCORE_PRELIM) < order.index(JobStage.SANDBOX_1)
    store.close()


def test_final_job_carries_both_verdicts(settings, apk) -> None:
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    finished = run_pipeline(_job(), Context(settings=settings, ledger=store), apk_path=apk)
    assert finished.preliminary is not None, "preliminary verdict must survive to the end"
    assert finished.final is not None
    # gamma is derived from evidence quality, not from how far the run got. With a
    # non-detonating trace it correctly stays put; see the scorer's formula.
    assert finished.preliminary.gamma == finished.final.gamma
    store.close()


def test_stage_failure_becomes_an_error_node_not_a_traceback(settings, apk, monkeypatch) -> None:
    """A crash is a finding about the run, and the evidence trail should show it."""
    import drishti.pipeline as pipeline

    def boom(*_a, **_k):
        raise RuntimeError("androguard exploded")

    monkeypatch.setattr(pipeline, "_static", boom)

    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    job = _job()
    finished = run_pipeline(job, Context(settings=settings, ledger=store), apk_path=apk)

    assert finished.stage == JobStage.FAILED
    assert finished.error is not None and "androguard exploded" in finished.error

    from drishti.contracts.evidence import EvidenceType

    errors = store.query(job_id=job.id, type=EvidenceType.ERROR)
    assert len(errors) == 1
    assert errors[0].content["stage"] == JobStage.STATIC.value
    # Even a failed run leaves a valid chain — the failure is recorded, not corrupting.
    assert store.verify_chain(job.id).ok is True
    store.close()


# ── the runner ───────────────────────────────────────────────────────────────
def test_runner_submits_and_completes(settings, apk) -> None:
    runner = JobRunner(settings)
    try:
        job = runner.submit(apk, "sample.apk")
        assert job.stage == JobStage.QUEUED

        # Draining the stream is the synchronisation point: it returns when the run
        # ends, so there is no sleep-and-hope in this test.
        seen = list(runner.stream(job.id, timeout_s=30))
        assert seen, "expected stage events"

        final = runner.get(job.id)
        assert final is not None
        assert final.stage == JobStage.DONE, final.error

        store = LedgerStore(settings.db_path, settings.ledger_key_path)
        assert store.verify_chain(job.id).ok is True
        store.close()
    finally:
        runner.shutdown()


def test_runner_computes_sha256_of_the_upload(settings, apk) -> None:
    import hashlib

    expected = hashlib.sha256(apk.read_bytes()).hexdigest()
    runner = JobRunner(settings)
    try:
        job = runner.submit(apk, "sample.apk")
        assert job.sha256 == expected
        list(runner.stream(job.id, timeout_s=30))
    finally:
        runner.shutdown()


def test_two_concurrent_jobs_keep_separate_chains(settings, apk) -> None:
    """Concurrency check: two workers appending at once must not interleave chains.

    Each job's `seq` starts at 0 and both chains must verify independently. Without
    per-job sequencing this is where a shared counter would show up.
    """
    runner = JobRunner(settings)
    try:
        first = runner.submit(apk, "one.apk")
        second = runner.submit(apk, "two.apk")
        list(runner.stream(first.id, timeout_s=30))
        list(runner.stream(second.id, timeout_s=30))

        store = LedgerStore(settings.db_path, settings.ledger_key_path)
        for job_id in (first.id, second.id):
            result = store.verify_chain(job_id)
            assert result.ok is True, f"{job_id}: {result.reason}"
            assert result.node_count == EXPECTED_NODES_PER_RUN
        store.close()
    finally:
        runner.shutdown()


def test_unknown_job_stream_is_empty_not_hanging(settings) -> None:
    runner = JobRunner(settings)
    try:
        assert list(runner.stream("job_nonexistent", timeout_s=1)) == []
    finally:
        runner.shutdown()


# ── replay mode through the whole pipeline (T0.7) ────────────────────────────
DEMO_SHA = "deadbeef" * 8


def test_replay_fixture_drives_the_full_frontier_arc(settings, apk) -> None:
    """The demo's central beat, end to end, in replay mode.

    Pass 1 does not detonate and reports an evasion observation; the frontier derives a
    morph plan from that observation; pass 2 detonates. This is the arc that has to work
    identically whether the sandbox is live or replayed — which is the entire reason
    `TraceSource` exists at hour zero (00_GUIDING_MAP.md §3).
    """
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    events: list = []
    # The fixture is keyed by sha256, so the job must claim the fixture's hash. In P4
    # the fixture is rewritten under a real sample's hash and this indirection vanishes.
    job = _job(sha256=DEMO_SHA)
    ctx = Context(settings=settings, ledger=store, on_event=events.append)

    finished = run_pipeline(job, ctx, apk_path=apk)
    assert finished.stage == JobStage.DONE, finished.error

    trace = ctx.artefacts["dynamic"]
    assert trace.detonated is True, "pass 2 should detonate after morphs are applied"
    assert trace.detonation_reason == "exfil_observed"
    assert trace.morphs_applied == ("install_packages",)
    assert trace.source.value == "replay"

    stages = [e.stage for e in events if e.status == "completed"]
    assert JobStage.FRONTIER in stages and JobStage.SANDBOX_2 in stages
    assert store.verify_chain(job.id).ok is True
    store.close()


def test_replayed_trace_is_disclosed_as_synthetic(settings, apk) -> None:
    """A hand-authored fixture must reach the pipeline still declaring what it is.

    If this ever passes with synthetic=False, the report's Limitations section would
    silently start presenting typed-up values as measurements.
    """
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    ctx = Context(settings=settings, ledger=store)
    run_pipeline(_job(sha256=DEMO_SHA), ctx, apk_path=apk)

    trace = ctx.artefacts["dynamic"]
    assert trace.synthetic is True
    assert trace.partial is True
    assert any("hand-authored" in e for e in trace.errors)
    store.close()


def test_frontier_morphs_are_derived_from_observed_probes(settings, apk) -> None:
    """A morph with no derivation is a guess.

    The stub frontier reads pass 1's evasion observations rather than inventing a
    package list, because the frontier's claim is that it responds to observed
    behaviour — and that claim has to be checkable.
    """
    from drishti.contracts.evidence import EvidenceType

    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    job = _job(sha256=DEMO_SHA)
    run_pipeline(job, Context(settings=settings, ledger=store), apk_path=apk)

    morphs = store.query(job_id=job.id, type=EvidenceType.MORPH_ACTION)
    assert len(morphs) == 1
    assert morphs[0].content["derived_from_observations"] >= 1
    assert morphs[0].content["human_reviewed"] is False
    store.close()


def test_no_fixture_falls_back_to_a_declared_stub(settings, apk) -> None:
    """An unknown sample must not silently look like a clean one.

    The fallback trace carries partial=True and an error naming why, because an empty
    trace asserts the sample did nothing — a different statement from "we could not
    observe it".
    """
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    ctx = Context(settings=settings, ledger=store)
    run_pipeline(_job(sha256="c" * 64), ctx, apk_path=apk)

    trace = ctx.artefacts["dynamic"]
    assert trace.detonated is False
    assert trace.outcome == "inconclusive"
    assert trace.partial is True
    assert any("no trace source available" in e for e in trace.errors)
    store.close()


def test_a_real_apk_produces_more_evidence_than_an_unparseable_one(settings) -> None:
    """The node count above is a floor for a fixture that cannot be parsed, not a target.

    Wiring real M2/M4 made the synthetic-fixture count go DOWN, which is easy to misread
    as a regression. This is the assertion that actually matters: a real APK yields more
    evidence, including the manifest facts the placeholder cannot produce.
    """
    canary = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"
    assert canary.exists(), "canary APK missing — run `bash canary/build.sh`"

    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    job = _job()
    run_pipeline(job, Context(settings=settings, ledger=store), apk_path=canary)

    nodes = store.query(job_id=job.id)
    assert len(nodes) > EXPECTED_NODES_PER_RUN, (
        f"a parseable APK produced {len(nodes)} nodes, no more than the unparseable "
        "fixture — M2 is probably not running"
    )
    types = {n.type for n in nodes}
    assert EvidenceType.MANIFEST_ENTRY in types, "real M2 must record manifest facts"
    assert store.verify_chain(job.id).ok is True
