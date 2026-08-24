"""M4 GenAI contracts.

docs/01_DATA_CONTRACTS.md §4. `VisionMatch` is an addition under the §0 rule —
`GenAIVerdict.impersonation` referenced it without definition.

The load-bearing design decision in this file: **the LLM never emits the score.**
`behavioural_risk_B` is computed in Python from an enumerated behaviour checklist
via a deterministic weight table (T3.6). If you find yourself parsing a number out
of model output for anything that reaches `S`, stop.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from drishti.contracts.base import AnalyserResult, DrishtiModel


class VerifierStatus(StrEnum):
    """Outcome of mechanically checking one claim's citations.

    Note there is no `WARN`. A claim either resolves to real evidence of a plausible
    type, or it is rejected and shown as rejected.
    """

    PASS = "PASS"
    REJECTED_NO_EVIDENCE = "REJECTED_NO_EVIDENCE"
    REJECTED_BAD_REF = "REJECTED_BAD_REF"
    REJECTED_TYPE_MISMATCH = "REJECTED_TYPE_MISMATCH"


class GroundedClaim(DrishtiModel):
    """One AI sentence plus the evidence it cites and its verification result.

    Rejected claims are RETAINED, not dropped. The count of rejections feeds the
    report's Limitations section, and a verifier that silently deleted its failures
    would make the system look more certain than it is.
    """

    text: str
    evidence_refs: tuple[str, ...] = ()
    agent: str
    verifier_status: VerifierStatus


class ToolCallRecord(DrishtiModel):
    """One validated, read-only model-requested analysis operation."""

    id: str
    name: str
    arguments: dict = Field(default_factory=dict)
    status: Literal["ok", "rejected", "error"]
    result_summary: str = ""
    evidence_refs: tuple[str, ...] = ()
    duration_ms: int = 0


class VerifiedString(DrishtiModel):
    """A model-proposed transform with the deterministic verifier's verdict."""

    ciphertext: str
    transform: str
    plaintext: str = ""
    verified: bool
    reason: str
    evidence_refs: tuple[str, ...] = ()


class CodeInterpretation(DrishtiModel):
    """Grounded explanation of one decompiled method; never a classification score."""

    method_signature: str
    summary: str
    claims: tuple[GroundedClaim, ...] = ()
    renamed_symbols: dict[str, str] = Field(default_factory=dict)
    confidence: Literal["high", "medium", "low"] = "low"
    insufficient_evidence: bool = False
    cited_lines: tuple[int, ...] = ()


class TechniqueMapping(DrishtiModel):
    """A MITRE ATT&CK Mobile mapping.

    `layer` records whether the technique was inferred from static capability or
    actually observed at runtime. An observed technique is far stronger evidence than
    a statically-possible one, and collapsing the distinction would overstate the
    dynamic findings.
    """

    technique_id: str
    name: str
    tactic: str
    layer: Literal["static", "dynamic", "both"]
    evidence_refs: tuple[str, ...] = ()


class VictimProfile(DrishtiModel):
    """Who this sample is aimed at, and how it manipulates them."""

    language: str | None = None
    tactic: str | None = None
    segment: str | None = None
    impersonated_target: str | None = None
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()


class VisionMatch(DrishtiModel):
    """Result of comparing the app's icon/screenshot against a brand reference set.

    `similarity` is a raw comparison score; `matched_brand` is only populated above
    the decision threshold. Both are kept so the report can say "closest match was
    X at 0.62, below threshold" rather than silently claiming no impersonation.
    """

    matched_brand: str | None = None
    similarity: float = 0.0
    threshold: float = 0.0
    method: Literal["vlm", "perceptual_hash"] = "perceptual_hash"
    icon_path: str | None = None
    screenshot_path: str | None = None
    evidence_refs: tuple[str, ...] = ()


class GenAIVerdict(AnalyserResult):
    """M4 output.

    `disagreement_flag` is the meta-check: the model is shown the fused numbers and
    asked whether they contradict the evidence. When it does, **confidence drops and
    the score does not move** (T3.11). That asymmetry is deliberate — a sample that
    scores 90 with C=0.4 because it refused to detonate is surfaced honestly rather
    than quietly downgraded.
    """

    sha256: str
    summary: str = ""
    claims: tuple[GroundedClaim, ...] = ()
    behavioural_risk_B: float = 0.0
    B_rationale: str = ""
    behaviours: dict[str, bool] = Field(default_factory=dict)
    techniques: tuple[TechniqueMapping, ...] = ()
    victim: VictimProfile | None = None
    impersonation: VisionMatch | None = None
    interpretations: tuple[CodeInterpretation, ...] = ()
    tool_calls: tuple[ToolCallRecord, ...] = ()
    verified_strings: tuple[VerifiedString, ...] = ()
    elicitation_deployed: tuple[str, ...] = ()
    disagreement_flag: bool = False
    disagreement_note: str | None = None
    llm_calls: int = 0
    provider: str = "mock"
    ledger_refs: tuple[str, ...] = ()

    @property
    def verified_claims(self) -> tuple[GroundedClaim, ...]:
        """Only the claims that survived verification. What the report may assert."""
        return tuple(c for c in self.claims if c.verifier_status == VerifierStatus.PASS)

    @property
    def rejected_claims(self) -> tuple[GroundedClaim, ...]:
        """Claims the verifier refused. Drives the Limitations section."""
        return tuple(c for c in self.claims if c.verifier_status != VerifierStatus.PASS)
