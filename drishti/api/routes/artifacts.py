"""Report, YARA, STIX, the case-file archive, and the human-confirmation gate.

docs/PHASE_0_FOUNDATIONS.md T0.6.

The three export routes are implemented: report (T6.3), YARA (T6.1), STIX (T6.2).
They still 404-pending when the job has not produced `ingest` and `score` yet, which
is a different thing from "this build cannot do it" and is deliberately not conflated
with it (see `deps.py`).

None of the three invents anything it was not given. The report's Limitations section
is derived from provenance flags, the YARA rule declares itself disabled when too few
distinctive strings survived filtering, and the STIX bundle publishes only verified
claims and observed — never synthesised — network infrastructure.

`bundle.zip` serves all of them at once. It is the same bytes, assembled — an archive
an analyst can keep, with a manifest that says what is in it and whether the evidence
chain verified at the moment it was taken.

The confirmation route, by contrast, is fully implemented from P0 — because "nothing
executes without a human" is a safety property, not a feature, and it should not be
possible to reach a demo where a consequential action has no gate.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

from drishti.api.deps import (
    JobDep,
    RunnerDep,
    SettingsDep,
    artefact_or_pending,
    open_ledger,
)
from drishti.api.jobs import JobRunner
from drishti.api.routes.analysis import observed_trace
from drishti.config import Settings
from drishti.contracts.evidence import ChainVerification, EvidenceType
from drishti.contracts.job import Job
from drishti.contracts.score import CompositeScore, ProposedAction
from drishti.contracts.static_report import FileMeta
from drishti.contracts.verdict import build_verdict
from drishti.logging import get_logger
from drishti.m7_report import case_file, dossier, html, stix, yara
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


def _verify_chain(settings: Settings, job_id: str) -> ChainVerification:
    """Walk the job's chain now.

    The chain state is read live rather than cached: a document that asserts its own
    evidence is intact must prove that at render time, not quote an older check.
    """
    store = open_ledger(settings)
    try:
        store.open(job_id)
        return store.verify_chain(job_id)
    finally:
        store.close()


def _export_ledger(settings: Settings, job_id: str) -> dict[str, Any]:
    """Everything a third party needs to re-verify the chain themselves."""
    store = open_ledger(settings)
    try:
        store.open(job_id)
        return store.export(job_id)
    finally:
        store.close()


@router.get("/{job_id}/report.html", response_class=HTMLResponse)
def get_report(job: JobDep, runner: RunnerDep, settings: SettingsDep) -> HTMLResponse:
    """The full investigation report as one self-contained HTML document (T6.3)."""
    meta, score, static, genai, dynamic = _bundle_inputs(runner, job)
    chain = _verify_chain(settings, job.id)

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
    chain = _verify_chain(settings, job.id)

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
    return _dossier_payload(pack)


def _dossier_payload(pack: dossier.Dossier) -> dict[str, Any]:
    """The wire shape of a dossier. One definition, so the archive cannot drift."""
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


def _json_bytes(payload: Any) -> bytes:
    """Pretty JSON, key-sorted — the archive is read by people, and diffed by them."""
    return json.dumps(payload, indent=2, sort_keys=True, default=str).encode()


@router.get("/{job_id}/artifacts/bundle.zip")
def get_bundle(job: JobDep, runner: RunnerDep, settings: SettingsDep) -> Response:
    """Every deliverable for this job in one archive, for keeping (contract A20).

    The same bytes the single-file routes serve, plus `MANIFEST.json` recording the
    sample hash, a SHA-256 per entry, the chain verification as read at build time, and
    anything that could not be produced together with the reason. It 404-pends before
    `ingest` and `score` exist, like every other export — an empty archive would read
    as a finished one.

    Each export is assembled independently. One that raises is named in `omitted` and
    the rest of the archive is still served: a failed STIX build must not cost an
    analyst the report and the ledger.
    """
    meta, score, static, genai, dynamic = _bundle_inputs(runner, job)
    chain = _verify_chain(settings, job.id)

    def dossier_bytes() -> bytes:
        pack = dossier.build(
            meta=meta, score=score, static=static, genai=genai, dynamic=dynamic, chain=chain
        )
        return _json_bytes(_dossier_payload(pack))

    builders = {
        "report.html": lambda: html.render(
            job=job,
            meta=meta,
            score=score,
            static=static,
            genai=genai,
            trace=dynamic,
            chain=chain,
        ).encode(),
        "complaint-package.json": dossier_bytes,
        "yara.yar": lambda: yara.build_rule(meta=meta, score=score, static=static).text.encode(),
        "stix.json": lambda: _json_bytes(
            stix.build_bundle(meta=meta, score=score, static=static, genai=genai, dynamic=dynamic)
        ),
        "ledger.json": lambda: _json_bytes(_export_ledger(settings, job.id)),
        "verdict.json": lambda: _json_bytes(
            build_verdict(
                meta=meta,
                score=score,
                static=static,
                genai=genai,
                trace=observed_trace(dynamic),
            ).model_dump(mode="json")
        ),
    }

    files: dict[str, bytes] = {}
    omitted: dict[str, str] = {}
    for name in case_file.CASE_FILE_NAMES:
        try:
            files[name] = builders[name]()
        # Broad by design: one exporter's failure degrades to an omission with a
        # reason, and never costs the analyst the rest of the archive.
        except Exception as exc:
            omitted[name] = f"{type(exc).__name__}: {exc}"
            log.warning("case_file_entry_failed", job_id=job.id, entry=name, error=str(exc))

    archive = case_file.build(
        job_id=job.id,
        meta=meta,
        files=files,
        chain=chain,
        generated_at=now(),
        omitted=omitted,
    )
    log.info(
        "case_file_built",
        job_id=job.id,
        entries=len(files),
        omitted=sorted(omitted),
        bytes=len(archive),
        chain_ok=chain.ok,
    )
    return Response(
        content=archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{job.id}-case-file.zip"'},
    )


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
