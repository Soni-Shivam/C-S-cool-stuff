"""FastAPI application entrypoint.

The route surface is **frozen** here as of T0.6 (docs/PHASE_0_FOUNDATIONS.md). The UI
is built against it and must not chase changes: add a route by adding it to the doc
first, the same discipline the contracts follow.

Two failure conventions, kept distinct (see `drishti.api.deps`):
  404 + {"reason": "not_produced_yet", "stage": ...}  -> the UI renders "pending"
  501 + {"reason": "not_implemented", "task": ...}    -> "not available in this build"
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile
from sse_starlette.sse import EventSourceResponse

from drishti import __version__
from drishti.api.deps import JobDep, RunnerDep, SettingsDep, get_runner, set_runner
from drishti.api.routes import analysis, artifacts, ledger, logs, samples
from drishti.contracts.job import Job

__all__ = ["app", "get_runner", "set_runner"]

app = FastAPI(
    title="DRISHTI",
    description="Defensive Android malware triage",
    version=__version__,
)


@app.get("/api/health", tags=["meta"])
def health() -> dict[str, str]:
    """Liveness probe. Reports the version, never any analysis state."""
    return {"status": "ok", "version": __version__}


@app.post("/api/jobs", status_code=202, tags=["jobs"])
async def create_job(
    apk: Annotated[UploadFile, File()],
    settings: SettingsDep,
    runner: RunnerDep,
) -> dict[str, str]:
    """Accept an upload and queue it. Returns immediately with a job id.

    Streamed to a temp file rather than read into memory, and the size guard counts
    bytes actually received: a `Content-Length` can lie, the stream cannot.
    """
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


@app.get("/api/jobs", tags=["jobs"])
def list_jobs(runner: RunnerDep) -> list[Job]:
    """Every job this process has seen, newest first.

    Added for the live demo (docs/DEMO_SCRIPT.md): jobs are created by the DRISHTI
    Shield app on the phone, so the dashboard has no job id to deep-link to and needs
    a way to discover the newest one. Additive to the T0.6 surface — no existing
    route's path, method, or response shape changes.
    """
    return sorted(runner.list_jobs(), key=lambda job: job.created_at, reverse=True)


@app.get("/api/jobs/{job_id}", tags=["jobs"])
def get_job(job: JobDep) -> Job:
    return job


@app.get("/api/jobs/{job_id}/events", tags=["jobs"])
async def job_events(job: JobDep, runner: RunnerDep) -> EventSourceResponse:
    """SSE stream of stage transitions."""

    def publisher() -> Iterator[dict[str, str]]:
        for event in runner.stream(job.id):
            yield {"event": "stage", "data": event.model_dump_json()}
        yield {"event": "done", "data": json.dumps({"job_id": job.id})}

    return EventSourceResponse(publisher())


# Order matters: `analysis` and `artifacts` both mount under /api/jobs, and the
# ledger router owns /api/evidence as well.
app.include_router(analysis.router)
app.include_router(ledger.router)
app.include_router(artifacts.router)
app.include_router(logs.router)
# /api/samples is its own prefix; the picker never mounts under /api/jobs.
app.include_router(samples.router)
