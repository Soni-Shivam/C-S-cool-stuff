"""Report, YARA, STIX, and the human-confirmation gate.

docs/PHASE_0_FOUNDATIONS.md T0.6.

The three export routes are implemented: report (T6.3), YARA (T6.1), STIX (T6.2).
They still 404-pending when the job has not produced `ingest` and `score` yet, which
is a different thing from "this build cannot do it" and is deliberately not conflated
with it (see `deps.py`).

None of the three invents anything it was not given. The report's Limitations section
is derived from provenance flags, the YARA rule declares itself disabled when too few
distinctive strings survived filtering, and the STIX bundle publishes only verified
claims and observed — never synthesised — network infrastructure.

The confirmation route, by contrast, is fully implemented from P0 — because "nothing
executes without a human" is a safety property, not a feature, and it should not be
possible to reach a demo where a consequential action has no gate.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

from drishti.api.deps import (
    JobDep,
    RunnerDep,
    SettingsDep,
    artefact_or_pending,
    open_ledger,
)
from drishti.api.jobs import JobRunner
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.job import Job
from drishti.contracts.score import CompositeScore, ProposedAction
from drishti.contracts.static_report import FileMeta
from drishti.logging import get_logger
from drishti.m7_report import dossier, html, stix, yara
from drishti.util import now

log = get_logger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["artifacts"])

#: The actions a human may confirm. Mirrors ProposedAction.action.
CONFIRMABLE = {
    "block",
    "quarantine",
    "notify_customers",
    "push_ioc",
    "fast_track_analyst",
    "analyst_review",
    "monitor",
    "log",
}


def _bundle_inputs(runner: JobRunner, job: Job) -> tuple[FileMeta, CompositeScore, Any, Any, Any]:
    """Gather every artefact the exporters need.

    `ingest` and `score` are required — without them there is nothing to export and
    the honest answer is 404-pending, not an empty document. Everything else is
    optional by design: a report that omits the dynamic section because no detonation
    ran is correct, and its Limitations section will say so.
    """
    meta: FileMeta = artefact_or_pending(runner, job, "ingest")
    score: CompositeScore = artefact_or_pending(runner, job, "score")
    return (
        meta,
        score,
        runner.artefact(job.id, "static"),
        runner.artefact(job.id, "genai"),
        runner.artefact(job.id, "dynamic"),
    )


@router.get("/{job_id}/report.html", response_class=HTMLResponse)
def get_report(job: JobDep, runner: RunnerDep, settings: SettingsDep) -> HTMLResponse:
    """The full investigation report as one self-contained HTML document (T6.3)."""
    meta, score, static, genai, dynamic = _bundle_inputs(runner, job)

    # The chain state is read live rather than cached: a report that asserts its own
    # evidence is intact must prove that at render time, not quote an older check.
    store = open_ledger(settings)
    try:
        store.open(job.id)
        chain = store.verify_chain(job.id)
    finally:
        store.close()

    document = html.render(
        job=job,
        meta=meta,
        score=score,
        static=static,
        genai=genai,
        trace=dynamic,
        chain=chain,
    )
    log.info(
        "report_rendered",
        job_id=job.id,
        band=score.band.value,
        chain_ok=chain.ok,
        nodes=chain.node_count,
    )
    return HTMLResponse(content=document)


@router.get("/{job_id}/artifacts/yara", response_class=PlainTextResponse)
def get_yara(job: JobDep, runner: RunnerDep) -> PlainTextResponse:
    """A YARA rule built from repack-resistant artefacts (T6.1).

    Returned as text/plain so it can be piped straight into `yara -C`. A rule the
    generator does not trust is still returned, but commented out and carrying the
    reason — silently withholding it would hide that we tried.
    """
    meta, score, static, _genai, _dynamic = _bundle_inputs(runner, job)
    rule = yara.build_rule(meta=meta, score=score, static=static)
    log.info(
        "yara_generated",
        job_id=job.id,
        rule=rule.name,
        enabled=rule.enabled,
        strings=rule.string_count,
    )
    return PlainTextResponse(content=rule.text)


@router.get("/{job_id}/artifacts/dossier")
def get_dossier(job: JobDep, runner: RunnerDep, settings: SettingsDep) -> dict:
    """The reporting package for a cyber cell or a bank fraud desk (contract A12).

    **This does not file anything.** The National Cyber Crime Reporting Portal has no
    public submission API, so `submission_is_manual` is always True and the response
    carries a deep link for a human rather than a receipt. The sample itself never
    leaves the analysis project — the dossier is hashes and derived facts.
    """
    meta, score, static, genai, dynamic = _bundle_inputs(runner, job)

    store = open_ledger(settings)
    try:
        store.open(job.id)
        chain = store.verify_chain(job.id)
    finally:
        store.close()

    pack = dossier.build(
        meta=meta,
        score=score,
        static=static,
        genai=genai,
        dynamic=dynamic,
        chain=chain,
    )
    log.info(
        "dossier_built",
        job_id=job.id,
        reportable=pack.reportable,
        indicators=len(pack.indicators),
        techniques=len(pack.techniques),
    )
    return {
        "sha256": pack.sha256,
        "reportable": pack.reportable,
        "reason": pack.reason,
        "summary": pack.summary,
        "facts": pack.facts,
        "indicators": pack.indicators,
        "techniques": pack.techniques,
        "caveats": pack.caveats,
        "portal_url": pack.portal_url,
        "helpline": pack.helpline,
        "submission_is_manual": pack.submission_is_manual,
        "text": pack.as_text(),
    }


@router.get("/{job_id}/artifacts/stix")
def get_stix(job: JobDep, runner: RunnerDep) -> dict:
    """A STIX 2.1 bundle for machine-to-machine sharing (T6.2)."""
    meta, score, static, genai, dynamic = _bundle_inputs(runner, job)
    bundle = stix.build_bundle(meta=meta, score=score, static=static, genai=genai, dynamic=dynamic)
    log.info("stix_exported", job_id=job.id, objects=len(bundle["objects"]))
    return bundle


@router.post("/{job_id}/actions/{action}/confirm")
def confirm_action(
    job: JobDep,
    action: str,
    settings: SettingsDep,
    confirmed_by: Annotated[str, Body(embed=True)],
) -> ProposedAction:
    """Record a human confirmation. **Nothing is executed here.**

    This endpoint writes an `ANALYST_ACTION` ledger node naming who confirmed and
    returns the action marked confirmed. Actually blocking an app, notifying customers
    or pushing an IOC is someone else's system; DRISHTI proposes and records.

    `requires_confirmation` stays True on the returned object. It describes the
    action's nature — consequential actions always need a human — not whether this
    particular one has been signed off, which is what `confirmed_by` says.
    """
    if action not in CONFIRMABLE:
        raise HTTPException(status_code=400, detail=f"unknown action {action!r}")
    if not confirmed_by.strip():
        raise HTTPException(status_code=400, detail="confirmed_by must not be empty")

    store = open_ledger(settings)
    try:
        store.open(job.id)
        node = store.append(
            type=EvidenceType.ANALYST_ACTION,
            source_tool="api:human",
            content={
                "action": action,
                "confirmed_by": confirmed_by,
                "job_id": job.id,
                "executed": False,
            },
            confidence=1.0,
        )
    finally:
        store.close()

    log.info(
        "action_confirmed",
        job_id=job.id,
        action=action,
        confirmed_by=confirmed_by,
        ledger_seq=node.seq,
    )
    return ProposedAction(
        action=action,  # type: ignore[arg-type]
        rationale=f"Confirmed by {confirmed_by}; recorded as evidence {node.id}.",
        requires_confirmation=True,
        confirmed_by=confirmed_by,
        confirmed_at=now(),
    )
