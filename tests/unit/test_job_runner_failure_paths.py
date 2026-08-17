"""A worker thread that dies must still end the job and close the stream.

docs/superpowers/plans/2026-08-17-ledger-hardening-and-reconciliation.md Task 2.

JobRunner._run promises in its docstring that it never raises. The ledger was being
constructed above the try block, so a failure there skipped both the handler that
marks the job FAILED and the finally that publishes the done sentinel — leaving the
SSE consumer to block until its timeout on a job that would never progress.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.job import JobStage
from drishti.ledger.store import LedgerStore, initialise_schema
from tests.apk_fixtures import minimal_apk_bytes


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        llm_provider="mock",
        job_workers=2,
    )


@pytest.fixture
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "sample.apk"
    path.write_bytes(minimal_apk_bytes())
    return path


def test_ledger_construction_failure_fails_the_job_and_closes_the_stream(
    settings: Settings, apk: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr("drishti.api.jobs.LedgerStore", explode)

    runner = JobRunner(settings)
    try:
        job = runner.submit(apk, "sample.apk")

        started = time.monotonic()
        # If the sentinel is never published this blocks for the full timeout.
        list(runner.stream(job.id, timeout_s=10))
        elapsed = time.monotonic() - started
        assert elapsed < 5, f"stream blocked {elapsed:.1f}s — the done sentinel was not published"

        current = runner.get(job.id)
        assert current is not None
        assert current.stage is JobStage.FAILED
        assert current.error is not None
        assert "ledger unavailable" in current.error
    finally:
        runner.shutdown()


class _FlakyConnection:
    """A connection that reports the database locked for the first `fail_times` calls.

    Stands in for the real race, which is inherently timing-dependent: SQLite returns
    SQLITE_BUSY without calling the busy handler when two connections both try to
    upgrade a shared lock. Injecting the error makes the retry testable at all.
    """

    def __init__(self, real: sqlite3.Connection, fail_times: int) -> None:
        self._real = real
        self._remaining = fail_times
        self.attempts = 0

    def execute(self, sql: str) -> Any:
        return self._real.execute(sql)

    def executescript(self, script: str) -> Any:
        self.attempts += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise sqlite3.OperationalError("database is locked")
        return self._real.executescript(script)


def test_schema_initialisation_retries_a_locked_database(tmp_path: Path) -> None:
    real = sqlite3.connect(tmp_path / "t.db", isolation_level=None)
    flaky = _FlakyConnection(real, fail_times=2)
    try:
        initialise_schema(flaky, timeout_s=10.0)  # type: ignore[arg-type]
        assert flaky.attempts == 3, "expected two retries then success"
    finally:
        real.close()


def test_schema_initialisation_gives_up_after_the_deadline(tmp_path: Path) -> None:
    """The retry must be bounded — a permanently locked database has to surface."""
    real = sqlite3.connect(tmp_path / "t.db", isolation_level=None)
    flaky = _FlakyConnection(real, fail_times=10_000)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            initialise_schema(flaky, timeout_s=0.2)  # type: ignore[arg-type]
    finally:
        real.close()


def test_a_non_lock_error_is_not_retried(tmp_path: Path) -> None:
    """Only contention is retried. A real schema error must fail fast."""

    class _Broken(_FlakyConnection):
        def executescript(self, script: str) -> Any:
            self.attempts += 1
            raise sqlite3.OperationalError('near "CREAT": syntax error')

    real = sqlite3.connect(tmp_path / "t.db", isolation_level=None)
    broken = _Broken(real, fail_times=0)
    try:
        with pytest.raises(sqlite3.OperationalError, match="syntax error"):
            initialise_schema(broken, timeout_s=10.0)  # type: ignore[arg-type]
        assert broken.attempts == 1, "a syntax error must not be retried"
    finally:
        real.close()


def test_two_concurrent_jobs_on_a_fresh_db_both_verify(settings: Settings, apk: Path) -> None:
    """The regression this whole plan exists for.

    Two jobs submitted at once against a database and key that do not yet exist. Both
    chains must verify against the key that ends up on disk.
    """
    runner = JobRunner(settings)
    try:
        first = runner.submit(apk, "one.apk")
        second = runner.submit(apk, "two.apk")
        list(runner.stream(first.id, timeout_s=30))
        list(runner.stream(second.id, timeout_s=30))

        store = LedgerStore(settings.db_path, settings.ledger_key_path)
        try:
            for job_id in (first.id, second.id):
                result = store.verify_chain(job_id)
                assert result.ok is True, f"{job_id}: {result.reason}"
                assert result.node_count > 0
        finally:
            store.close()
    finally:
        runner.shutdown()
