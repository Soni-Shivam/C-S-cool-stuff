"""The P0 exit criterion: upload -> stages -> ledger -> verified chain.

docs/PHASE_0_FOUNDATIONS.md T0.5 and the Phase 0 Definition of Done.

Nothing is analysed here. What is being proved is that the *skeleton is load-bearing*:
stages transition in the canonical order, the conditional frontier branch is taken,
every stage leaves a ledger node, the chain verifies, and a crash becomes evidence
rather than a traceback.
"""

from __future__ import annotations

import pytest

from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.job import Job, JobStage
from drishti.ledger.store import LedgerStore
from drishti.pipeline import STAGES_IN_ORDER, Context, run_pipeline
from drishti.util import new_id, now


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        llm_provider="mock",
        job_workers=2,
    )


@pytest.fixture
def apk(tmp_path):
    """Not a real APK. The P0 pipeline is stubs and never parses it."""
    path = tmp_path / "sample.apk"
    path.write_bytes(b"PK\x03\x04" + b"stub" * 64)
    return path


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

    # One ledger node per executed stage.
    assert store.count(job.id) == len(STAGES_IN_ORDER)

    verification = store.verify_chain(job.id)
    assert verification.ok is True, verification.reason
    assert verification.node_count == len(STAGES_IN_ORDER)
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
    assert finished.preliminary.gamma < finished.final.gamma, (
        "gamma must rise once dynamic evidence exists"
    )
    store.close()


def test_stage_failure_becomes_an_error_node_not_a_traceback(settings, apk, monkeypatch) -> None:
    """A crash is a finding about the run, and the evidence trail should show it."""
    import drishti.pipeline as pipeline

    def boom(*_a, **_k):
        raise RuntimeError("androguard exploded")

    monkeypatch.setattr(pipeline, "_stub_static", boom)

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
            assert result.node_count == len(STAGES_IN_ORDER)
        store.close()
    finally:
        runner.shutdown()


def test_unknown_job_stream_is_empty_not_hanging(settings) -> None:
    runner = JobRunner(settings)
    try:
        assert list(runner.stream("job_nonexistent", timeout_s=1)) == []
    finally:
        runner.shutdown()
