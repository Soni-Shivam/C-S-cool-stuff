"""Ledger query, chain verification, and single-node drill-down.

docs/PHASE_0_FOUNDATIONS.md T0.6.

The drill-down route is what turns "every score point traces back to an artefact"
from a claim into a click path: `F_AI 41.5` -> `P_cal 0.71` -> the SHAP features ->
the `PERMISSION_COMBO` node -> `AndroidManifest.xml#L42`. That path is the strongest
twenty seconds of the demo, so the endpoint behind it exists from P0.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from drishti.api.deps import JobDep, SettingsDep, open_ledger
from drishti.contracts.evidence import ChainVerification, EvidenceNode, EvidenceType

router = APIRouter(prefix="/api", tags=["ledger"])


@router.get("/jobs/{job_id}/ledger")
def query_ledger(
    job: JobDep,
    settings: SettingsDep,
    type: Annotated[EvidenceType | None, Query()] = None,
    source_tool: Annotated[str | None, Query()] = None,
    since_seq: Annotated[int, Query(ge=0)] = 0,
) -> list[EvidenceNode]:
    """Nodes for one job, oldest first.

    `since_seq` exists so the UI's ledger tab can poll incrementally instead of
    re-fetching a 400-node chain on every tick.
    """
    store = open_ledger(settings)
    try:
        return store.query(job_id=job.id, type=type, source_tool=source_tool, since_seq=since_seq)
    finally:
        store.close()


@router.get("/jobs/{job_id}/ledger/verify")
def verify_ledger(job: JobDep, settings: SettingsDep) -> JSONResponse:
    """Verify a job's hash chain and signatures.

    A broken chain returns **200 with `ok: false`**, not an error status: that is a
    successful report about a bad state, and the caller decides what it means. An HTTP
    error would make "the ledger is compromised" indistinguishable from "the request
    failed".
    """
    store = open_ledger(settings)
    try:
        result: ChainVerification = store.verify_chain(job.id)
    finally:
        store.close()
    return JSONResponse(result.model_dump(mode="json"))


@router.get("/jobs/{job_id}/ledger/export")
def export_ledger(job: JobDep, settings: SettingsDep) -> JSONResponse:
    """Everything a third party needs to re-verify the chain without our code.

    Carries the public key, the algorithm, and the float precision used to
    canonicalise — the last one matters, because a verifier that rounds differently
    computes different hashes and would wrongly report tampering.
    """
    store = open_ledger(settings)
    try:
        return JSONResponse(store.export(job.id))
    finally:
        store.close()


@router.get("/evidence/{node_id}")
def get_evidence_node(node_id: str, settings: SettingsDep) -> EvidenceNode:
    """One node, by id. The drill-down target for every evidence chip in the UI."""
    store = open_ledger(settings)
    try:
        node = store.get(node_id)
    finally:
        store.close()
    if node is None:
        raise HTTPException(status_code=404, detail="unknown evidence node")
    return node
