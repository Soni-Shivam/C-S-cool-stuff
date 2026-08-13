"""In-process job runner. No Celery, no Redis, no broker.

docs/PHASE_0_FOUNDATIONS.md T0.5, 00_GUIDING_MAP.md §3.

Jobs are I/O-bound — subprocess, adb, HTTP to a model provider — so threads are the
right primitive and a broker would be three more moving parts to fail at 4am. Two
workers, because the analysis host is also running an emulator.
"""

from __future__ import annotations

import hashlib
import queue
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from drishti.config import Settings
from drishti.contracts.job import Job, JobStage, StageEvent
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger
from drishti.pipeline import Context, run_pipeline
from drishti.util import new_id, now

log = get_logger(__name__)

#: Sentinel pushed onto a job's event queue when the run ends, so an SSE consumer
#: knows to close rather than poll a queue that will never fill again.
_DONE = object()


class JobRunner:
    """Submit an APK, walk the pipeline on a worker thread, stream stage events."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool = ThreadPoolExecutor(max_workers=settings.job_workers)
        self._jobs: dict[str, Job] = {}
        self._queues: dict[str, queue.Queue[StageEvent | object]] = {}
        # Stage outputs per job, populated by the pipeline as it runs so the API can
        # serve a partial result mid-run instead of only at the end.
        self._artefacts: dict[str, dict[str, Any]] = {}
        # One lock for both dicts. Contention is irrelevant at two workers, and a
        # single lock is one fewer ordering rule to get wrong.
        self._lock = threading.Lock()

    # ── submit / read ────────────────────────────────────────────────────────
    def submit(self, apk_path: Path, filename: str) -> Job:
        sha256 = self._sha256(apk_path)
        job = Job(
            id=new_id("job"),
            sha256=sha256,
            filename=filename,
            stage=JobStage.QUEUED,
            created_at=now(),
        )
        with self._lock:
            self._jobs[job.id] = job
            self._queues[job.id] = queue.Queue()
            self._artefacts[job.id] = {}

        log.info("job_submitted", job_id=job.id, sha256=sha256, filename=filename)
        self._pool.submit(self._run, job, apk_path)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    def artefact(self, job_id: str, kind: str) -> Any | None:
        """A stage output, or None if that stage has not produced one yet."""
        with self._lock:
            return self._artefacts.get(job_id, {}).get(kind)

    def stream(self, job_id: str, *, timeout_s: float = 300.0) -> Iterator[StageEvent]:
        """Yield stage events until the run ends.

        A synchronous generator rather than an async one: the producer is a worker
        thread, and `sse-starlette` runs a sync iterator in a threadpool perfectly
        well. Making this `async` would mean bridging a thread queue into an event
        loop for no benefit.
        """
        with self._lock:
            events = self._queues.get(job_id)
        if events is None:
            return

        while True:
            try:
                item = events.get(timeout=timeout_s)
            except queue.Empty:
                log.warning("job_stream_timeout", job_id=job_id, timeout_s=timeout_s)
                return
            if item is _DONE:
                return
            assert isinstance(item, StageEvent)
            yield item

    # ── internals ────────────────────────────────────────────────────────────
    def _run(self, job: Job, apk_path: Path) -> None:
        """Worker body. Must never raise — a dead worker thread is a silent hang."""
        # A per-job ledger connection: sqlite3 connections are not shareable across
        # threads, and WAL means the concurrent reader is unaffected.
        ledger = LedgerStore(self._settings.db_path, self._settings.ledger_key_path)
        try:
            with self._lock:
                artefacts = self._artefacts.setdefault(job.id, {})
            # The same dict object the API reads, so a stage's output is visible the
            # instant it is recorded rather than after the run.
            ctx = Context(
                settings=self._settings,
                ledger=ledger,
                on_event=lambda event: self._publish(job.id, event),
                artefacts=artefacts,
            )
            finished = run_pipeline(job, ctx, apk_path=apk_path)
            self._store(finished)
        except Exception as exc:
            log.error("job_crashed", job_id=job.id, error=str(exc), exc_info=True)
            with self._lock:
                current = self._jobs.get(job.id, job)
                self._jobs[job.id] = current.model_copy(
                    update={"stage": JobStage.FAILED, "error": f"runner: {exc}"}
                )
        finally:
            ledger.close()
            self._publish(job.id, _DONE)

    def _publish(self, job_id: str, item: StageEvent | object) -> None:
        with self._lock:
            events = self._queues.get(job_id)
            # Keep the job's snapshot current as events arrive, so a poller sees
            # progress without waiting for the run to finish.
            if isinstance(item, StageEvent) and job_id in self._jobs:
                job = self._jobs[job_id]
                self._jobs[job_id] = job.model_copy(
                    update={
                        "stage": item.stage,
                        "stage_history": (*job.stage_history, item),
                    }
                )
        if events is not None:
            events.put(item)

    def _store(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def shutdown(self, *, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)
