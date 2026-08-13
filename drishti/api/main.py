"""FastAPI application entrypoint.

T0.1 gave the app object and a liveness probe. T0.5 adds the three routes needed to
drive and observe a job. The **full** frozen route surface is T0.6 — the UI is built
against that list, so it must not chase changes, and endpoints are added there rather
than piecemeal here.

Not-yet-produced artefacts return 404 with `{"stage": job.stage}` so the UI can render
"pending" instead of erroring (T0.6).
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from drishti import __version__
from drishti.api.jobs import JobRunner
from drishti.config import Settings, get_settings
from drishti.contracts.job import Job
from drishti.ledger.store import LedgerStore
from drishti.logging import configure_logging

app = FastAPI(
    title="DRISHTI",
    description="Defensive Android malware triage",
    version=__version__,
)

_runner: JobRunner | None = None


def get_runner() -> JobRunner:
    """Lazily built so importing this module does not create threads or files.

    Matters for tests and for `--reload`: a module-level runner would spawn a pool on
    every import.
    """
    global _runner
    if _runner is None:
        settings = get_settings()
        configure_logging(level=settings.log_level, log_path=settings.log_path)
        _runner = JobRunner(settings)
    return _runner


def set_runner(runner: JobRunner | None) -> None:
    """Test seam: inject a runner built on a tmp_path settings object."""
    global _runner
    _runner = runner


@app.get("/api/health")
def health() -> dict[str, str]:
    """Liveness probe. Reports the version, never any analysis state."""
    return {"status": "ok", "version": __version__}


@app.post("/api/jobs", status_code=202)
async def create_job(
    apk: Annotated[UploadFile, File()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    """Accept an upload and queue it. Returns immediately with a job id.

    The upload is streamed to a temp file rather than read into memory: a 300MB APK
    read into a request handler is a trivial way to fall over, and the size guard has
    to act on bytes actually received rather than a header we were told.
    """
    runner = get_runner()
    filename = Path(apk.filename or "upload.apk").name

    tmp_dir = Path(tempfile.mkdtemp(prefix="drishti-upload-"))
    target = tmp_dir / filename
    written = 0
    try:
        with target.open("wb") as handle:
            while chunk := await apk.read(1024 * 1024):
                written += len(chunk)
                if written > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"upload exceeds {settings.max_upload_bytes} bytes",
                    )
                handle.write(chunk)
    except HTTPException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    if written == 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="empty upload")

    job = runner.submit(target, filename)
    return {"job_id": job.id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> Job:
    job = get_runner().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return job


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str) -> EventSourceResponse:
    """SSE stream of stage transitions. The demo screen tails this."""
    runner = get_runner()
    if runner.get(job_id) is None:
        raise HTTPException(status_code=404, detail="unknown job")

    def publisher() -> Iterator[dict[str, str]]:
        for event in runner.stream(job_id):
            yield {"event": "stage", "data": event.model_dump_json()}
        yield {"event": "done", "data": json.dumps({"job_id": job_id})}

    return EventSourceResponse(publisher())


@app.get("/api/jobs/{job_id}/ledger/verify")
def verify_ledger(
    job_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    """Verify a job's hash chain. The trust claim, over HTTP."""
    if get_runner().get(job_id) is None:
        raise HTTPException(status_code=404, detail="unknown job")
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    try:
        result = store.verify_chain(job_id)
    finally:
        store.close()
    # A broken chain is a successful *report* of a bad state, not a failed request —
    # so 200 with ok=false, and the caller decides what that means.
    return JSONResponse(result.model_dump(mode="json"))
