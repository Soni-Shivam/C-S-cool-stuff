"""M4 controller: StaticReport in, grounded GenAIVerdict out.

docs/PHASE_3_GENAI_CORE.md T3.3, T3.6.

The controller owns three responsibilities and delegates everything else:

  * assemble evidence into a prompt **within budget**, wrapping every sample-derived
    string in an `<untrusted_artifact>` block
  * turn the model's enumerated answers into `B` via `safety.behavioural_risk`, never
    by reading a number out of the response
  * emit `AI_CLAIM` ledger nodes that cite the static nodes they rest on, so the
    verifier can reject anything ungrounded

It degrades rather than raises. A provider outage yields a `partial` verdict with the
static report intact, because losing M2's work to an LLM timeout would be absurd.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from drishti.config import Settings
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import GenAIVerdict, GroundedClaim, VerifierStatus
from drishti.contracts.static_report import StaticReport
from drishti.ledger.store import LedgerStore
from drishti.ledger.verifier import Verifier
from drishti.logging import get_logger
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.safety import BEHAVIOUR_WEIGHTS, behavioural_risk, wrap_untrusted

log = get_logger(__name__)

_PROMPTS = Path(__file__).parent / "prompts"

#: Caps on how much sample-derived text reaches the prompt. The budget is 12k tokens in
#: (00_GUIDING_MAP.md §12) and a real APK carries far more strings than that.
#: Node types that carry no behavioural information and so cannot ground a claim on
#: their own. Listing them here keeps them out of the catalogue entirely, rather than
#: offering the model bait it will be rejected for taking.
_NON_CITABLE = {EvidenceType.AI_CLAIM, EvidenceType.SCORE_FACTOR, EvidenceType.ERROR}

MAX_CATALOGUE_ENTRIES = 60
MAX_URLS = 15
MAX_STRINGS = 20
MAX_PATHS = 8


class ClaimOut(BaseModel):
    """One claim the model made, before verification."""

    text: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    behaviour: str = ""


class ChecklistResponse(BaseModel):
    """Exactly what the model is allowed to return.

    `extra` is left permissive so a chatty model does not fail validation outright —
    unknown keys are dropped here and ignored again by `behavioural_risk`, which is the
    layer that actually matters.
    """

    summary: str = ""
    behaviours: dict[str, bool] = Field(default_factory=dict)
    claims: list[ClaimOut] = Field(default_factory=list)


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(_PROMPTS),
        autoescape=select_autoescape(enabled_extensions=(), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def build_system_prompt() -> str:
    """Render the checklist instructions. Contains no sample-derived text."""
    template = _environment().get_template("behaviour_checklist.jinja")
    return template.render(behaviour_names=sorted(BEHAVIOUR_WEIGHTS))


def build_evidence_catalogue(ledger: LedgerStore, job_id: str) -> tuple[str, set[str]]:
    """List the ledger nodes the model may cite, with ids it must copy verbatim.

    Giving the model the real ids is what makes grounding checkable. Without a
    catalogue it can only invent plausible-looking references, every one of which the
    verifier then rejects — which produces a report with no assertable content and
    looks like the model failed rather than like it was never given anything to cite.
    """
    lines: list[str] = []
    valid: set[str] = set()
    for node in ledger.query(job_id=job_id):
        if node.type in _NON_CITABLE:
            continue
        summary = _describe(node)
        if summary is None:
            continue
        lines.append(f"  {node.id}  [{node.type.value}]  {summary}")
        valid.add(node.id)
        if len(lines) >= MAX_CATALOGUE_ENTRIES:
            break
    if not lines:
        return "", set()
    return "EVIDENCE CATALOGUE (cite these ids verbatim):\n" + "\n".join(lines), valid


def _describe(node: Any) -> str | None:
    """A one-line, non-attacker-controlled description of a node."""
    content = node.content
    kind = node.type.value
    if kind == "manifest_entry":
        name = str(content.get("name", ""))[:60]
        return f"{content.get('kind', 'entry')}: {name}" if name else None
    if kind == "permission_combo":
        return f"rule {content.get('rule_id')} severity {content.get('severity')}"
    if kind == "sink_hit":
        return f"sink {content.get('sink_id')}"
    if kind == "call_path":
        return f"{content.get('sink_id')} reachable from {str(content.get('entrypoint', ''))[-40:]}"
    if kind == "certificate":
        return f"age_days={content.get('age_days')} debug={content.get('debug_cert')}"
    if kind == "string_const":
        return "extracted string constant"
    if kind == "decompiled_method":
        return f"bounded source for {str(content.get('signature', 'method'))[-80:]}"
    if kind == "ai_tool_call":
        return f"validated tool call {content.get('name')} status={content.get('status')}"
    if kind == "threat_intel":
        return f"verdict {content.get('verdict')}"
    return None


def build_user_turn(static: StaticReport) -> str:
    """Assemble the evidence turn.

    Structured facts we derived (permission names, sink ids, counts) are stated plainly.
    Anything whose *content* came from the sample — URLs, string constants, package and
    method names — goes inside an `<untrusted_artifact>` block, because that is the text
    an attacker controls.
    """
    parts: list[str] = [
        "Static analysis facts (derived by our analyser, trusted):",
        f"  package: {static.package}",
        f"  min_sdk={static.min_sdk} target_sdk={static.target_sdk}",
        f"  permissions ({len(static.permissions)}): "
        f"{', '.join(sorted(p.rsplit('.', 1)[-1] for p in static.permissions)) or 'none'}",
        f"  permission combos fired: "
        f"{', '.join(c.rule_id for c in static.permission_combos) or 'none'}",
        f"  sinks reached: {', '.join(static.sink_hits) or 'none'}",
        f"  sinks reachable from a lifecycle entrypoint: "
        f"{', '.join(sorted({p.sink_id for p in static.call_paths if p.reachable_from_lifecycle})) or 'none'}",
        f"  dex_count={static.dex_count} entropy_mean={static.entropy_mean:.2f} "
        f"native_libs={len(static.native_libs)} packer_hints={len(static.packer_hints) or 'none'}",
        f"  certificate: age_days={static.certificate.age_days} "
        f"brand_mismatch={static.certificate.brand_mismatch} debug={static.certificate.debug_cert}",
        f"  over-privilege: declared_not_used={len(static.declared_not_used)} "
        f"used_not_declared={len(static.used_not_declared)}",
    ]

    if static.urls:
        parts.append("\nURL constants extracted from the sample:")
        parts.append(wrap_untrusted("\n".join(static.urls[:MAX_URLS]), kind="url_constant"))
    if static.crypto_constants:
        parts.append("\nCrypto-related constants:")
        parts.append(
            wrap_untrusted("\n".join(static.crypto_constants[:MAX_STRINGS]), kind="string_constant")
        )
    if static.call_paths:
        rendered = "\n".join(
            f"{path.entrypoint} -> ... -> {path.sink_signature} "
            f"(depth {len(path.path)}, reachable={path.reachable_from_lifecycle})"
            for path in static.call_paths[:MAX_PATHS]
        )
        parts.append("\nCall paths from entrypoints to sinks:")
        parts.append(wrap_untrusted(rendered, kind="call_path"))

    parts.append("\nAnswer the checklist as specified. JSON only.")
    return "\n".join(parts)


def analyse(
    static: StaticReport,
    ledger: LedgerStore,
    settings: Settings,
    *,
    client: LLMClient | None = None,
) -> GenAIVerdict:
    """Run the behaviour checklist over a static report and ground the result.

    Returns a `partial` verdict rather than raising when the provider is unavailable —
    the static report is worth far more than the LLM layer and must survive its failure.
    """
    llm = client or LLMClient(settings)
    static_refs = tuple(static.ledger_refs)
    job_id = ledger._job_id or ""
    catalogue, citable = build_evidence_catalogue(ledger, job_id)

    # No static evidence means any claim would be ungrounded, and ledger.append() refuses
    # an AI_CLAIM with empty evidence_refs — that refusal IS the product (CLAUDE.md rule
    # 5). Reasoning anyway and then being rejected would fail the whole job, so the
    # honest move is not to make a claim at all.
    if not static_refs:
        return GenAIVerdict(
            sha256=static.sha256,
            partial=True,
            errors=("no static evidence to ground a claim on; GenAI skipped",),
            provider=settings.llm_provider,
        )

    user_turn = build_user_turn(static)
    if catalogue:
        user_turn = f"{catalogue}\n\n{user_turn}"
    response = llm.complete_as(
        system=build_system_prompt(),
        user=user_turn,
        schema=ChecklistResponse,
    )
    if response is None:
        log.warning("genai_unavailable", sha256=static.sha256, provider=settings.llm_provider)
        return GenAIVerdict(
            sha256=static.sha256,
            partial=True,
            errors=("GenAI unavailable: no valid response after one repair attempt",),
            provider=settings.llm_provider,
            llm_calls=llm.calls_made,
        )

    # B is computed here, from the enumerated answers. The model never supplies it.
    b_value, contributing = behavioural_risk(dict(response.behaviours))

    # Every claim is checked against the ledger. Rejected claims are RETAINED, not
    # dropped: the rejection count feeds the report's Limitations section, and a
    # verifier that quietly deleted its failures would make the system look more
    # certain than it is.
    verifier = Verifier(ledger, job_id or None)
    claims: list[GroundedClaim] = []
    for item in response.claims[:20]:
        candidate = GroundedClaim(
            text=item.text[:500],
            evidence_refs=tuple(item.evidence_refs[:8]),
            agent="behaviour_checklist",
            verifier_status=VerifierStatus.PASS,
        )
        status = verifier.check_claim(candidate)
        claims.append(candidate.model_copy(update={"verifier_status": status}))

    # ── agents ───────────────────────────────────────────────────────────────
    # Two agents, per 00_GUIDING_MAP 10 item 6, which pre-agreed collapsing six to
    # interpreter + mapper when time is short. Two that work beat six that are stubs.
    from drishti.m4_genai.agents.code_interpreter import interpret_methods
    from drishti.m4_genai.agents.technique_mapper import map_techniques

    techniques = map_techniques(static, ledger, job_id)

    interpretations, tool_calls, verified_strings = interpret_methods(static, ledger, job_id, llm)
    verified_interpretations = []
    for interpretation in interpretations:
        checked = tuple(
            claim.model_copy(update={"verifier_status": verifier.check_claim(claim)})
            for claim in interpretation.claims
        )
        claims.extend(checked)
        verified_interpretations.append(interpretation.model_copy(update={"claims": checked}))

    verified = [c for c in claims if c.verifier_status is VerifierStatus.PASS]
    log.info(
        "genai_claims_verified",
        total=len(claims),
        passed=len(verified),
        rejected=len(claims) - len(verified),
        citable_nodes=len(citable),
    )

    content: dict[str, Any] = {
        "behaviours_true": list(contributing),
        "behavioural_risk_B": b_value,
        "summary": response.summary[:2000],
        "model": settings.resolved_llm_model,
        "claims_total": len(claims),
        "claims_verified": len(verified),
        "techniques": [t.technique_id for t in techniques],
        # The static nodes this rests on. ledger.append() rejects an AI_CLAIM whose
        # evidence_refs are empty or unresolvable — that rejection IS the product.
        "evidence_refs": list(static_refs),
    }
    node = ledger.append(
        type=EvidenceType.AI_CLAIM,
        source_tool=f"m4_genai:{settings.llm_provider}",
        content=content,
        parents=static_refs,
        confidence=0.7,
    )

    return GenAIVerdict(
        sha256=static.sha256,
        summary=response.summary[:2000],
        claims=tuple(claims),
        techniques=techniques,
        interpretations=tuple(verified_interpretations),
        tool_calls=tool_calls,
        verified_strings=verified_strings,
        behavioural_risk_B=b_value,
        B_rationale=(
            f"{len(contributing)} enumerated behaviours asserted: {', '.join(contributing)}"
            if contributing
            else "no enumerated behaviour was asserted"
        ),
        behaviours=dict(response.behaviours),
        provider=settings.llm_provider,
        llm_calls=llm.calls_made,
        ledger_refs=(node.id, *static_refs),
    )
