"""Job and pipeline contracts.

docs/01_DATA_CONTRACTS.md §7. `StageEvent` is an addition under the §0 rule —
`Job.stage_history` referenced it without definition.

The two-verdict design is a PRODUCT requirement, not an implementation detail:
`SCORE_PRELIM` fires before the sandbox and the UI shows it immediately with a
"deep analysis running" badge. That is what makes the "<5 min initial verdict,
15-30 min deep analysis" claim honest rather than an average of the two.
"""

from __future__ import annotations

from enum import StrEnum

from drishti.contracts.base import DrishtiModel
from drishti.contracts.score import CompositeScore


class JobStage(StrEnum):
    QUEUED = "queued"
    INGEST = "ingest"
    STATIC = "static"
    ML = "ml"
    GENAI_STATIC = "genai_static"
    SCORE_PRELIM = "score_prelim"
    SANDBOX_1 = "sandbox_pass1"
    FRONTIER = "frontier"
    SANDBOX_2 = "sandbox_pass2"
    GENAI_FULL = "genai_full"
    SCORE_FINAL = "score_final"
    REPORT = "report"
    DONE = "done"
    FAILED = "failed"


#: Canonical order (§7.1). FRONTIER and SANDBOX_2 are conditional — they run only
#: when pass 1 did not detonate and evasion observations are non-empty.
PIPELINE_ORDER: tuple[JobStage, ...] = (
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


class StageEvent(DrishtiModel):
    """One stage transition, streamed to the UI over SSE.

    `message` is user-facing on the demo screen, so it is written for a human:
    `[M3] sample queried PackageManager('com.sbi.yono') -> MISS -> stall detected`,
    not a struct dump.
    """

    stage: JobStage
    status: str
    at: str
    duration_ms: int | None = None
    message: str | None = None
    ledger_seq: int | None = None


class Job(DrishtiModel):
    """One analysis run.

    `preliminary` and `final` are separate fields rather than one mutated score, so
    the UI can animate the transition and a reader can see that the deep analysis
    changed the verdict — which is the whole demo narrative.
    """

    id: str
    sha256: str
    filename: str
    stage: JobStage
    created_at: str
    stage_history: tuple[StageEvent, ...] = ()
    preliminary: CompositeScore | None = None
    final: CompositeScore | None = None
    error: str | None = None
