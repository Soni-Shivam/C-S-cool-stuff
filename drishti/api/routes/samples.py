"""The staged-sample picker: analyse a sample of known nature (contract A21).

Two routes, and the shape of them is the safety argument.

`GET /api/samples` lists what the analysis VM holds — package, size, hash, and the
corpus ground truth. It does not serve, and there is no route that serves, the APK
itself. The sample stays in the analysis project (CLAUDE.md's hard boundary); what
crosses to the browser is a description and an id.

`POST /api/samples/{id}/analyse` runs one. It resolves the id to a path and calls
the same `runner.submit()` the upload route calls, with the same two arguments. The
ground-truth label is not among them and cannot be: a VT-derived signal entering the
pipeline here would make every composite score over this corpus circular, which is
what `m5_ml/reputation.py` refuses a label-derived feed to prevent. The label exists
in this module so a human can be shown whether the verdict was right — never so the
verdict can know.

The comparison the dashboard draws from this is therefore an honest one: the run
that produced the score had no more information than an upload of the same bytes
would have had.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from drishti.api.deps import RunnerDep, SettingsDep
from drishti.contracts.sample import SampleEntry
from drishti.logging import get_logger
from drishti.m1_ingest import catalogue

log = get_logger(__name__)

router = APIRouter(prefix="/api/samples", tags=["samples"])


@router.get("")
def list_samples(settings: SettingsDep) -> list[SampleEntry]:
    """The staged samples this deployment can run, with their known nature.

    An empty list means no samples are staged here — the honest answer on a laptop,
    where the dashboard hides the picker rather than offering a button that cannot
    work. It is not an error and must not be rendered as one.
    """
    entries = catalogue.load(settings)
    log.info("sample_catalogue_listed", count=len(entries))
    return entries


@router.post("/{sample_id}/analyse", status_code=202)
def analyse_sample(sample_id: str, settings: SettingsDep, runner: RunnerDep) -> dict[str, str]:
    """Queue a staged sample. Same pipeline, same arguments, as an upload.

    404 for an id this deployment does not offer — including anything shaped like a
    path, which simply matches no catalogue entry.
    """
    resolved = catalogue.resolve(settings, sample_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail=f"unknown sample {sample_id!r}")

    # Exactly what `create_job` passes. The entry's `label` and `vt_detection` are
    # deliberately not in this call and must never be added to it.
    job = runner.submit(resolved.path, resolved.entry.filename)
    log.info(
        "sample_analysis_queued",
        job_id=job.id,
        sample_id=resolved.entry.id,
        package=resolved.entry.package,
        sha256=resolved.entry.sha256,
    )
    return {"job_id": job.id}
