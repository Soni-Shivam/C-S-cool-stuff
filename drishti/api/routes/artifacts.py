"""Report, YARA, STIX, and the human-confirmation gate.

docs/PHASE_0_FOUNDATIONS.md T0.6.

The three export routes are frozen here but **return 501** until their phases land
(report T6.3, YARA T6.1, STIX T6.2). A 501 with the owning task is honest; serving a
placeholder that looks like a report would be exactly the kind of thing CLAUDE.md's
honesty requirements exist to prevent.

The confirmation route, by contrast, is fully implemented from P0 — because "nothing
executes without a human" is a safety property, not a feature, and it should not be
possible to reach a demo where a consequential action has no gate.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException

from drishti.api.deps import JobDep, SettingsDep, not_implemented, open_ledger
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.score import ProposedAction
from drishti.logging import get_logger
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


@router.get("/{job_id}/report.html")
def get_report(job: JobDep) -> str:
    not_implemented("HTML report rendering", "T6.3")


@router.get("/{job_id}/artifacts/yara")
def get_yara(job: JobDep) -> str:
    not_implemented("YARA rule generation", "T6.1")


@router.get("/{job_id}/artifacts/stix")
def get_stix(job: JobDep) -> dict:
    not_implemented("STIX 2.1 export", "T6.2")


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
