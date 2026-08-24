"""Tool-using interpreter for bounded, sink-reachable decompiled methods."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from drishti.contracts.genai_verdict import (
    CodeInterpretation,
    GroundedClaim,
    ToolCallRecord,
    VerifiedString,
    VerifierStatus,
)
from drishti.contracts.static_report import StaticReport
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.tools import AnalysisToolbox

log = get_logger(__name__)
MAX_METHODS_INTERPRETED = 6
_PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


class ClaimOut(BaseModel):
    text: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class InterpretationOut(BaseModel):
    method_signature: str
    summary: str = ""
    claims: list[ClaimOut] = Field(default_factory=list)
    renamed_symbols: dict[str, str] = Field(default_factory=dict)
    confidence: str = "low"
    insufficient_evidence: bool = False
    cited_lines: list[int] = Field(default_factory=list)


class InterpretationSet(BaseModel):
    interpretations: list[InterpretationOut] = Field(default_factory=list)


def _system_prompt() -> str:
    environment = Environment(
        loader=FileSystemLoader(_PROMPTS),
        autoescape=select_autoescape(enabled_extensions=(), default=False),
    )
    return environment.get_template("code_interpreter_tools.jinja").render()


def interpret_methods(
    static: StaticReport,
    ledger: LedgerStore,
    job_id: str,
    client: LLMClient,
) -> tuple[tuple[CodeInterpretation, ...], tuple[ToolCallRecord, ...], tuple[VerifiedString, ...]]:
    """Interpret bounded methods through audited read-only tools."""
    methods = static.decompiled_methods[:MAX_METHODS_INTERPRETED]
    if not methods:
        return (), (), ()
    toolbox = AnalysisToolbox(static, ledger, job_id)
    catalogue = "\n".join(
        f"- {method.signature} evidence={method.evidence_ref} lines="
        f"{method.line_start}-{method.line_end} truncated={method.truncated}"
        for method in methods
    )
    response = client.complete_with_tools_as(
        system=_system_prompt(),
        user=(
            "Bounded sink-path method catalogue. Use read_method before interpreting a method.\n"
            f"{catalogue}\n\nReturn the required JSON object after gathering sufficient evidence."
        ),
        tools=toolbox.definitions,
        execute=toolbox.execute,
        schema=InterpretationSet,
    )
    if response is None:
        log.warning("code_interpreter_unavailable", methods=len(methods))
        return (), tuple(toolbox.records), tuple(toolbox.verified_strings)

    known = {method.signature: method for method in methods}
    interpretations: list[CodeInterpretation] = []
    for item in response.interpretations[:MAX_METHODS_INTERPRETED]:
        method = known.get(item.method_signature)
        if method is None:
            continue
        confidence = item.confidence if item.confidence in {"high", "medium", "low"} else "low"
        claims = tuple(
            GroundedClaim(
                text=claim.text.strip()[:500],
                evidence_refs=tuple(claim.evidence_refs[:8]),
                agent="code_interpreter",
                verifier_status=VerifierStatus.PASS,
            )
            for claim in item.claims[:8]
            if claim.text.strip()
        )
        lines = tuple(
            line for line in item.cited_lines[:40] if method.line_start <= line <= method.line_end
        )
        interpretations.append(
            CodeInterpretation(
                method_signature=method.signature,
                summary=item.summary.strip()[:1_000],
                claims=claims,
                renamed_symbols={
                    str(key)[:512]: str(value)[:120]
                    for key, value in list(item.renamed_symbols.items())[:20]
                },
                confidence=confidence,
                insufficient_evidence=item.insufficient_evidence,
                cited_lines=lines,
            )
        )
    return tuple(interpretations), tuple(toolbox.records), tuple(toolbox.verified_strings)


def explain_paths(
    static: StaticReport,
    ledger: LedgerStore,
    job_id: str,
    client: LLMClient,
) -> tuple[GroundedClaim, ...]:
    """Compatibility surface returning claims from the richer method interpreter."""
    interpretations, _, _ = interpret_methods(static, ledger, job_id, client)
    return tuple(claim for interpretation in interpretations for claim in interpretation.claims)
