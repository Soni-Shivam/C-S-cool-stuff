"""Per-job analysis artefacts. Frozen surface — docs/PHASE_0_FOUNDATIONS.md T0.6.

Each route serves the output of one module. Until that module's phase lands, the
pipeline records a stub carrying `partial=True` and an `errors` entry naming the phase
that will replace it — so the response is honest about what it is rather than looking
like a real analysis that found nothing.
"""

from __future__ import annotations

from fastapi import APIRouter

from drishti.api.deps import JobDep, RunnerDep, artefact_or_pending
from drishti.contracts.dynamic_trace import DynamicTrace
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import CompositeScore, MLPrediction
from drishti.contracts.static_report import FileMeta, StaticReport

router = APIRouter(prefix="/api/jobs", tags=["analysis"])


@router.get("/{job_id}/ingest")
def get_ingest(job: JobDep, runner: RunnerDep) -> FileMeta:
    result: FileMeta = artefact_or_pending(runner, job, "ingest")
    return result


@router.get("/{job_id}/static")
def get_static(job: JobDep, runner: RunnerDep) -> StaticReport:
    result: StaticReport = artefact_or_pending(runner, job, "static")
    return result


@router.get("/{job_id}/ml")
def get_ml(job: JobDep, runner: RunnerDep) -> MLPrediction:
    result: MLPrediction = artefact_or_pending(runner, job, "ml")
    return result


@router.get("/{job_id}/genai")
def get_genai(job: JobDep, runner: RunnerDep) -> GenAIVerdict:
    """The latest GenAI verdict.

    GENAI_STATIC produces a partial verdict and GENAI_FULL replaces it once dynamic
    behaviour exists. One route, latest-wins, because the UI panel is one panel and
    exposing both would invite showing a stale verdict beside a fresh score.
    """
    result: GenAIVerdict = artefact_or_pending(runner, job, "genai")
    return result


@router.get("/{job_id}/dynamic")
def get_dynamic(job: JobDep, runner: RunnerDep) -> DynamicTrace:
    result: DynamicTrace = artefact_or_pending(runner, job, "dynamic")
    return result


@router.get("/{job_id}/score")
def get_score(job: JobDep, runner: RunnerDep) -> CompositeScore:
    """The current verdict: preliminary until SCORE_FINAL replaces it.

    `gamma` tells a caller which one it is holding — it rises as evidence completes —
    so the UI can badge "deep analysis running" without a second endpoint.
    """
    result: CompositeScore = artefact_or_pending(runner, job, "score")
    return result
