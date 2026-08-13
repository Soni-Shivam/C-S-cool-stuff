"""Shared dependencies and the two "not available yet" conventions.

docs/PHASE_0_FOUNDATIONS.md T0.6 freezes the route surface. The UI is built against
it and must not chase changes, so the *shapes* — including failure shapes — are part
of the contract.

Two distinct failures, deliberately not conflated:

**404 + `{"stage": ...}`** — the job has not reached the stage that produces this
artefact yet. The UI renders "pending" and keeps polling. This is what T0.6 specifies.

**501 + `{"detail": ..., "task": ...}`** — the route is frozen but the feature is not
built (report rendering is T6.3, YARA is T6.1, STIX is T6.2). The UI must render
"not available in this build", *not* "pending", because polling will never help.

Collapsing these into one status would make a permanently-missing feature look like a
slow one, and the honesty requirements in CLAUDE.md would be the first casualty.
"""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import Depends, HTTPException

from drishti.api.jobs import JobRunner
from drishti.config import Settings, get_settings
from drishti.contracts.job import Job
from drishti.ledger.store import LedgerStore

_runner: JobRunner | None = None


def get_runner() -> JobRunner:
    """Lazily built so importing a module does not create threads or files.

    Matters for tests and for `--reload`: a module-level runner would spawn a thread
    pool on every import.
    """
    global _runner
    if _runner is None:
        from drishti.logging import configure_logging

        settings = get_settings()
        configure_logging(level=settings.log_level, log_path=settings.log_path)
        _runner = JobRunner(settings)
    return _runner


def set_runner(runner: JobRunner | None) -> None:
    """Test seam: inject a runner built on tmp_path settings."""
    global _runner
    _runner = runner


RunnerDep = Annotated[JobRunner, Depends(get_runner)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def require_job(job_id: str, runner: RunnerDep) -> Job:
    job = runner.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return job


JobDep = Annotated[Job, Depends(require_job)]


def pending(job: Job) -> NoReturn:
    """404 signalling "not produced yet", carrying the stage so the UI can say why."""
    raise HTTPException(
        status_code=404,
        detail={"reason": "not_produced_yet", "stage": job.stage.value},
    )


def not_implemented(what: str, task: str) -> NoReturn:
    """501 signalling "frozen route, unbuilt feature". Never conflate with pending."""
    raise HTTPException(
        status_code=501,
        detail={"reason": "not_implemented", "what": what, "task": task},
    )


def open_ledger(settings: Settings) -> LedgerStore:
    """A short-lived read connection. sqlite3 handles are not thread-shareable."""
    return LedgerStore(settings.db_path, settings.ledger_key_path)


def artefact_or_pending(runner: JobRunner, job: Job, kind: str) -> Any:
    stored = runner.artefact(job.id, kind)
    if stored is None:
        pending(job)
    return stored
