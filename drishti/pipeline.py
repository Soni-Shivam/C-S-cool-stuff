"""THE orchestrator. Phase order lives here and nowhere else.

docs/PHASE_0_FOUNDATIONS.md T0.5, docs/01_DATA_CONTRACTS.md §7.1.

In P0 every stage is a **stub** that returns a schema-valid empty object and appends
one ledger node. The point is not the analysis — it is that the skeleton is
load-bearing: 11 stages transition, the ledger chains, SSE emits, and the conditional
frontier branch is exercised. Later phases replace stub bodies one at a time without
touching this file's structure.

Critical invariant (00_GUIDING_MAP.md §7): **M6 never reads from M2/M3/M4/M5
directly. It reads from the ledger.** That is what makes "every score point traces to
an artefact" true rather than marketing. Enforce it in review.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from drishti.config import Settings
from drishti.contracts.dynamic_trace import (
    DynamicTrace,
    EvasionObservation,
    TraceSourceKind,
)
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.job import Job, JobStage, StageEvent
from drishti.contracts.score import CompositeScore, MLPrediction, SeverityBand
from drishti.contracts.static_report import CertificateInfo, FileMeta, StaticReport
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger
from drishti.util import new_id, now

log = get_logger(__name__)

#: One ledger node per executed stage. `PHASE_0` T0.5 says "13 ledger nodes"; the
#: canonical order in §7.1 has 11 stages, and the stub walk appends exactly one node
#: each. Recorded as a deviation in STATUS.md rather than padding the count.
STAGES_IN_ORDER: tuple[JobStage, ...] = (
    JobStage.INGEST,
    JobStage.STATIC,
    JobStage.ML,
    JobStage.GENAI_STATIC,
    JobStage.SCORE_PRELIM,
    JobStage.SANDBOX_1,
    JobStage.FRONTIER,
    JobStage.SANDBOX_2,
    JobStage.GENAI_FULL,
    JobStage.SCORE_FINAL,
    JobStage.REPORT,
)


@dataclass
class Context:
    """Everything a stage may touch. Passed explicitly, never global.

    `on_event` is how the API streams progress. The pipeline does not know about SSE,
    HTTP, or the UI — it emits `StageEvent`s and something else decides what to do
    with them.
    """

    settings: Settings
    ledger: LedgerStore
    on_event: Callable[[StageEvent], None] | None = None
    artefacts: dict[str, Any] = field(default_factory=dict)

    def emit(self, event: StageEvent) -> None:
        if self.on_event is not None:
            self.on_event(event)


class StageFailedError(Exception):
    """A stage raised. Recorded as an ERROR node; the job ends FAILED."""


@dataclass
class _Run:
    """Mutable bookkeeping for one pipeline run.

    `Job` is a frozen contract, so progress accumulates here and a new `Job` is built
    from it. Evidence must be immutable; a run's *progress* is not evidence.
    """

    job: Job
    history: list[StageEvent] = field(default_factory=list)

    def with_stage(self, stage: JobStage, **changes: Any) -> None:
        self.job = self.job.model_copy(
            update={"stage": stage, "stage_history": tuple(self.history), **changes}
        )


@contextmanager
def stage(run: _Run, ctx: Context, which: JobStage) -> Iterator[None]:
    """Time a stage, transition the job, and turn a crash into evidence.

    An exception becomes an `ERROR` ledger node and `JobStage.FAILED` — never a
    traceback into the API. A failing stage is a finding about the run, and the
    evidence trail should show it (00_GUIDING_MAP.md §9.2).
    """
    started = time.perf_counter()
    run.history.append(StageEvent(stage=which, status="started", at=now()))
    run.with_stage(which)
    ctx.emit(run.history[-1])
    log.info("stage_started", stage=which.value, job_id=run.job.id)

    try:
        yield
    except Exception as exc:
        elapsed = int((time.perf_counter() - started) * 1000)
        node = ctx.ledger.append(
            type=EvidenceType.ERROR,
            source_tool="pipeline",
            content={
                "stage": which.value,
                "error": f"{type(exc).__name__}: {exc}",
            },
            confidence=1.0,
        )
        event = StageEvent(
            stage=which,
            status="failed",
            at=now(),
            duration_ms=elapsed,
            message=f"{which.value} failed: {type(exc).__name__}",
            ledger_seq=node.seq,
        )
        run.history.append(event)
        run.with_stage(JobStage.FAILED, error=f"{which.value}: {exc}")
        ctx.emit(event)
        log.error("stage_failed", stage=which.value, job_id=run.job.id, error=str(exc))
        raise StageFailedError(which.value) from exc

    elapsed = int((time.perf_counter() - started) * 1000)
    event = StageEvent(stage=which, status="completed", at=now(), duration_ms=elapsed)
    run.history.append(event)
    run.with_stage(which)
    ctx.emit(event)
    log.info("stage_completed", stage=which.value, job_id=run.job.id, duration_ms=elapsed)


# ─── P0 stubs ────────────────────────────────────────────────────────────────
# Each returns a schema-valid empty object and appends exactly one ledger node.
# Replaced module by module in later phases; the signatures are the contract.

_EMPTY_CERT = CertificateInfo(
    sha256="0" * 64,
    subject="",
    issuer="",
    not_before="",
    not_after="",
    age_days=0,
    self_signed=True,
)


def _stub_ingest(ctx: Context, apk_path: Path, sha256: str, filename: str) -> FileMeta:
    node = ctx.ledger.append(
        type=EvidenceType.FILE_META,
        source_tool="m1_ingest:stub",
        content={"sha256": sha256, "filename": filename},
        confidence=1.0,
    )
    size = apk_path.stat().st_size if apk_path.exists() else 0
    return FileMeta(
        sha256=sha256,
        size_bytes=size,
        filename=filename,
        partial=True,
        errors=("stub: M1 lands in T0.10",),
        ledger_refs=(node.id,),
    )


def _stub_static(ctx: Context, meta: FileMeta) -> StaticReport:
    node = ctx.ledger.append(
        type=EvidenceType.MANIFEST_ENTRY,
        source_tool="m2_static:stub",
        content={"note": "stub"},
        confidence=1.0,
    )
    return StaticReport(
        sha256=meta.sha256,
        package="",
        app_label="",
        version_name="",
        version_code=0,
        min_sdk=0,
        target_sdk=0,
        certificate=_EMPTY_CERT,
        partial=True,
        errors=("stub: M2 lands in P1",),
        ledger_refs=(node.id,),
    )


def _stub_ml(ctx: Context, static: StaticReport) -> MLPrediction:
    node = ctx.ledger.append(
        type=EvidenceType.ML_PREDICTION,
        source_tool="m5_ml:stub",
        content={"note": "stub"},
        confidence=0.0,
    )
    return MLPrediction(
        p_malicious_raw=0.0,
        p_calibrated=0.0,
        model_version="stub",
        feature_schema_version="stub",
        partial=True,
        errors=("stub: M5 lands in P2",),
        ledger_refs=(node.id,),
    )


def _stub_genai(ctx: Context, sha256: str, which: JobStage) -> GenAIVerdict:
    node = ctx.ledger.append(
        type=EvidenceType.TECHNIQUE_MAP,
        source_tool="m4_genai:stub",
        content={"stage": which.value, "note": "stub"},
        confidence=0.0,
    )
    return GenAIVerdict(
        sha256=sha256,
        partial=True,
        errors=(f"stub: M4 {which.value} lands in P3",),
        ledger_refs=(node.id,),
    )


def _stub_score(ctx: Context, which: JobStage, gamma: float) -> CompositeScore:
    node = ctx.ledger.append(
        type=EvidenceType.SCORE_FACTOR,
        source_tool="m6_score:stub",
        content={"stage": which.value, "note": "stub", "gamma": gamma},
        confidence=1.0,
    )
    return CompositeScore(
        S=0,
        band=SeverityBand.LOW,
        C=0.0,
        gamma=gamma,
        explanation="stub: M6 lands in P2",
        limitations=("Scoring is a stub; no analysis has run.",),
        ledger_refs=(node.id,),
    )


def _stub_sandbox(ctx: Context, which: JobStage, *, with_evasion: bool) -> DynamicTrace:
    """Stub trace. `with_evasion` drives the conditional frontier branch.

    Pass 1 reports an evasion observation so the FRONTIER branch is actually
    exercised in P0. A skeleton that never takes its conditional path has not been
    tested — and this is the branch the whole demo narrative hangs on.
    """
    node = ctx.ledger.append(
        type=EvidenceType.API_TRACE,
        source_tool="m3_dynamic:stub",
        content={"stage": which.value, "note": "stub"},
        confidence=0.0,
    )
    observations: tuple[EvasionObservation, ...] = ()
    if with_evasion:
        observations = (
            EvasionObservation(
                probe_kind="installed_package",
                queried="com.example.stub",
                result="MISS",
                t_ms=0,
                followed_by_stall=True,
                inferred_requirement="stub: a target package must be present",
            ),
        )
    return DynamicTrace(
        run_id=new_id("run"),
        source=TraceSourceKind.UNAVAILABLE,
        detonated=False,
        outcome="inconclusive",
        evasion_observations=observations,
        partial=True,
        errors=(f"stub: M3 {which.value} lands in P4",),
        ledger_refs=(node.id,),
    )


def _stub_frontier(ctx: Context, trace: DynamicTrace) -> str:
    node = ctx.ledger.append(
        type=EvidenceType.MORPH_ACTION,
        source_tool="m5_frontier:stub",
        content={
            "note": "stub",
            "derived_from_observations": len(trace.evasion_observations),
        },
        confidence=0.0,
    )
    return node.id


def _stub_report(ctx: Context, sha256: str) -> str:
    node = ctx.ledger.append(
        type=EvidenceType.ANALYST_ACTION,
        source_tool="m7_report:stub",
        content={"sha256": sha256, "note": "stub"},
        confidence=1.0,
    )
    return node.id


# ─── the pipeline ────────────────────────────────────────────────────────────
def run_pipeline(
    job: Job,
    ctx: Context,
    *,
    apk_path: Path,
) -> Job:
    """Walk the canonical stage order for one job.

    Two-verdict design is a product requirement, not an implementation detail
    (§7): `SCORE_PRELIM` is emitted before the sandbox so the UI can show a verdict
    immediately with a "deep analysis running" badge. That is what makes the
    "<5 min initial verdict" claim honest rather than an average.
    """
    ctx.ledger.open(job.id)
    run = _Run(job=job)

    try:
        with stage(run, ctx, JobStage.INGEST):
            meta = _stub_ingest(ctx, apk_path, job.sha256, job.filename)

        with stage(run, ctx, JobStage.STATIC):
            static = _stub_static(ctx, meta)

        with stage(run, ctx, JobStage.ML):
            _stub_ml(ctx, static)

        with stage(run, ctx, JobStage.GENAI_STATIC):
            _stub_genai(ctx, job.sha256, JobStage.GENAI_STATIC)

        with stage(run, ctx, JobStage.SCORE_PRELIM):
            preliminary = _stub_score(ctx, JobStage.SCORE_PRELIM, gamma=0.7)
        # Emitted the moment it exists, not at the end of the run.
        run.with_stage(JobStage.SCORE_PRELIM, preliminary=preliminary)

        with stage(run, ctx, JobStage.SANDBOX_1):
            trace = _stub_sandbox(ctx, JobStage.SANDBOX_1, with_evasion=True)

        # §7.1: the frontier runs only when pass 1 did not detonate AND there is an
        # observed evasion check to respond to. Morphing without an observation would
        # be a guess, which is precisely the claim the frontier is not making.
        if not trace.detonated and trace.evasion_observations:
            with stage(run, ctx, JobStage.FRONTIER):
                _stub_frontier(ctx, trace)

            with stage(run, ctx, JobStage.SANDBOX_2):
                trace = _stub_sandbox(ctx, JobStage.SANDBOX_2, with_evasion=False)

        with stage(run, ctx, JobStage.GENAI_FULL):
            _stub_genai(ctx, job.sha256, JobStage.GENAI_FULL)

        with stage(run, ctx, JobStage.SCORE_FINAL):
            final = _stub_score(ctx, JobStage.SCORE_FINAL, gamma=1.0)
        run.with_stage(JobStage.SCORE_FINAL, final=final)

        with stage(run, ctx, JobStage.REPORT):
            _stub_report(ctx, job.sha256)

    except StageFailedError:
        # The stage contextmanager already recorded the ERROR node and set FAILED.
        return run.job

    run.with_stage(JobStage.DONE)
    log.info(
        "job_done",
        job_id=run.job.id,
        stages=len(run.history),
        ledger_nodes=ctx.ledger.count(run.job.id),
    )
    return run.job
