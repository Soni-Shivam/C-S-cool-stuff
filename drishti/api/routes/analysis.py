"""Per-job analysis artefacts. Frozen surface — docs/PHASE_0_FOUNDATIONS.md T0.6.

Each route serves the output of one module. Until that module's phase lands, the
pipeline records a stub carrying `partial=True` and an `errors` entry naming the phase
that will replace it — so the response is honest about what it is rather than looking
like a real analysis that found nothing.
"""

from __future__ import annotations

from fastapi import APIRouter

from drishti.api.deps import JobDep, RunnerDep, artefact_or_pending
from drishti.contracts.dynamic_trace import DynamicTrace, TraceSourceKind
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import CompositeScore, MLPrediction
from drishti.contracts.static_report import FileMeta, StaticReport
from drishti.contracts.verdict import Verdict, build_verdict

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


@router.get("/{job_id}/verdict")
def get_verdict(job: JobDep, runner: RunnerDep) -> Verdict:
    """The shared `Verdict` projection — contract addendum A15/A16.

    A projection endpoint, not a computation: the whole body is one call to
    `build_verdict()` over artefacts the runner already holds. Every surface (the
    consumer phone screen, the analyst portal, the demo scripts) reads this one shape,
    so nothing here may decide a field. A second place that decides `provenance` is
    precisely the drift the shared contract exists to prevent.

    Pending until both `ingest` and `score` exist, because a `Verdict` without a score
    would have to invent a band.
    """
    meta: FileMeta = artefact_or_pending(runner, job, "ingest")
    composite: CompositeScore = artefact_or_pending(runner, job, "score")
    return build_verdict(
        meta=meta,
        score=composite,
        static=runner.artefact(job.id, "static"),
        genai=runner.artefact(job.id, "genai"),
        trace=observed_trace(runner.artefact(job.id, "dynamic")),
    )


def observed_trace(trace: DynamicTrace | None) -> DynamicTrace | None:
    """Drop the declared stub the pipeline records when nothing could observe the sample.

    `_sandbox()` records a trace with `source=unavailable`, `synthetic=True` and
    `partial=True` when no trace source could produce anything — degradation expressed
    in data rather than as an empty result. Forwarding that as a trace would project
    `provenance="REPLAY"` over a run in which nothing was ever replayed, and a
    `dynamic_trace` view of `detonated=false` with three empty lists, which the contract
    defines as *the app ran and did nothing observable*. Neither is true; `STATIC_ONLY`
    with no trace is. The stub itself stays fully visible on `GET .../dynamic`.
    """
    if trace is None or trace.source is TraceSourceKind.UNAVAILABLE:
        return None
    return trace
