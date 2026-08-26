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

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from drishti.config import Settings
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import (
    CodeInterpretation,
    GenAIVerdict,
    GroundedClaim,
    ToolCallRecord,
    VerifiedString,
    VerifierStatus,
)
from drishti.contracts.static_report import StaticReport
from drishti.ledger.store import LedgerStore
from drishti.ledger.verifier import NON_BEHAVIOURAL_TYPES, Verifier
from drishti.logging import get_logger
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.resources import UiString, extract_ui_strings, record_ui_strings
from drishti.m4_genai.retrieval import select
from drishti.m4_genai.safety import (
    BEHAVIOUR_WEIGHTS,
    CONTEXT_WEIGHTS,
    LLM_CONTEXT_KEYS,
    behavioural_risk,
    wrap_untrusted,
)

log = get_logger(__name__)

_PROMPTS = Path(__file__).parent / "prompts"

#: Derived nodes: our own output, not evidence. Citing one would be circular.
_DERIVED = {EvidenceType.AI_CLAIM, EvidenceType.SCORE_FACTOR, EvidenceType.ERROR}

#: Node types the catalogue must not offer. Anything here is either derived (above) or
#: non-behavioural — a type `Verifier.check_claim` refuses as the sole support for a
#: claim. The second half is imported from the verifier rather than restated, because
#: the two lists drifting apart is exactly the bug this guards: the certificate node
#: used to be offered and then rejected, which recorded a bad-citation against a model
#: that had cited precisely what we told it to. Keep them out of the catalogue rather
#: than offering bait it will be punished for taking.
#: `tests/unit/test_grounded_claims.py` pins the invariant.
_NON_CITABLE = _DERIVED | set(NON_BEHAVIOURAL_TYPES)

#: Caps on how much sample-derived text reaches the prompt. The budget is 12k tokens in
#: (00_GUIDING_MAP.md §12) and a real APK carries far more strings than that.
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
    return template.render(
        behaviour_names=sorted(BEHAVIOUR_WEIGHTS),
        context_names=sorted(LLM_CONTEXT_KEYS),
    )


def static_behaviour_context(static: StaticReport) -> dict[str, bool]:
    """Deterministic context flags for `behavioural_risk` — Python-computed, never model-emitted.

    These carry the exculpatory weight of `B` (see `CONTEXT_WEIGHTS`): they rest on
    evidence the sample cannot cheaply forge — a signing key that has actually existed
    for years, a publisher on the trusted roster, the lookalike assessment's verdict —
    so a prompt injection cannot reach them. The 730-day signer threshold is a priori
    domain knowledge (Android ties upgrades to the signing key, so legitimate publishers
    keep one for years; lookalike.py documents the same discriminator), not a fitted
    cut.
    """
    cert = static.certificate
    lookalike = static.lookalike
    return {
        "cert_signer_stable_years": cert.age_days >= 730 and not cert.debug_cert,
        "debug_certificate": bool(cert.debug_cert),
        "publisher_trusted": bool(lookalike and lookalike.publisher_trusted),
        "lookalike_legitimate_privileged": bool(
            lookalike and lookalike.verdict == "legitimate_privileged"
        ),
        "targets_installed_financial_apps": bool(
            lookalike and lookalike.targeted_financial_packages
        ),
    }


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


T = TypeVar("T")


def _guarded(name: str, run: Callable[[], T], *, default: T, errors: list[str] | None = None) -> T:
    """Run one sub-analyser; a failure inside it degrades the verdict, never the job.

    CLAUDE.md rule 2. The rule names a `@degrades_gracefully` decorator that does not
    exist anywhere in this repository — every module implements the property inline
    instead. This is that property at the one boundary where it matters most: the
    agents are the newest code in the system and the demo runs at hour 71.

    `errors` is the verdict's error sink. Logging alone is not degrading gracefully:
    a swallowed 413 used to leave the dashboard saying "no model tool call was made in
    this run", which reads as the model *choosing* idleness rather than the provider
    failing. The reason a stage is empty must reach `GenAIVerdict.errors`, because the
    Limitations section is generated from real flags, never from someone remembering.
    """
    try:
        return run()
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"[:300]
        log.error("subagent_failed", agent=name, error=detail)
        if errors is not None:
            errors.append(f"{name} failed: {detail}")
        return default


def _ui_strings(apk_path: Path | None, ledger: LedgerStore) -> tuple[UiString, ...]:
    """Extract and record the sample's user-facing strings, or return nothing.

    Absence is reported by the victim profile being `None`; it is never filled in with
    DEX constants pretending to be UI text.
    """
    if apk_path is None:
        return ()
    strings, errors = extract_ui_strings(apk_path)
    for error in errors:
        log.warning("ui_strings_unavailable", error=error)
    if not strings:
        return ()
    return record_ui_strings(strings, ledger)


def analyse(
    static: StaticReport,
    ledger: LedgerStore,
    settings: Settings,
    *,
    client: LLMClient | None = None,
    apk_path: Path | None = None,
) -> GenAIVerdict:
    """Run the behaviour checklist over a static report and ground the result.

    `apk_path` is optional and read-only. It exists so the Social-Engineering Analyst
    can reach the resource table for UI strings, which M2 does not surface — parsing
    only, never execution (CLAUDE.md, execution environment table). Without it the
    victim profile is simply absent, and the report says so.

    Returns a `partial` verdict rather than raising when the provider is unavailable —
    the static report is worth far more than the LLM layer and must survive its failure.
    """
    llm = client or LLMClient(settings)
    static_refs = tuple(static.ledger_refs)
    job_id = ledger._job_id or ""

    # UI strings are extracted and recorded BEFORE the catalogue is built, so the ids
    # the model is offered include the strings the victim profile will cite. Building
    # the catalogue first would offer nodes that do not exist yet and hide nodes that
    # do — the same class of bug as 7cd1997.
    ui_strings = _ui_strings(apk_path, ledger)
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

    # B is computed here, from the enumerated answers plus context. The model never
    # supplies it. Context merges two provenances: deterministic static facts computed
    # in Python (which carry the exculpatory weight — the model cannot be talked into
    # them), and the model's two enumerated purpose answers, which are separated out of
    # `behaviours` here so a model-supplied value can never masquerade as a
    # deterministic fact (`static_behaviour_context` keys win the merge).
    behaviour_context: dict[str, bool] = {
        **{k: response.behaviours.get(k) is True for k in LLM_CONTEXT_KEYS},
        **static_behaviour_context(static),
    }
    checklist = {k: v for k, v in response.behaviours.items() if k not in LLM_CONTEXT_KEYS}
    b_value, contributing = behavioural_risk(dict(checklist), context=behaviour_context)
    context_fired = tuple(name for name in CONTEXT_WEIGHTS if behaviour_context.get(name) is True)

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
    from drishti.m4_genai.agents.social_engineering import profile_victim
    from drishti.m4_genai.agents.technique_mapper import map_techniques

    techniques = map_techniques(static, ledger, job_id)

    # Code-graph RAG: walk backwards from the sinks, keep the highest-risk chains, and
    # send only those. Selected once and shared, so the workspace the model reads is
    # exactly the workspace the report and the UI describe.
    pack = select(static)
    log.info(
        "retrieval_selected",
        chains=len(pack.chains),
        considered=pack.chains_considered,
        methods=pack.method_count,
        estimated_tokens=pack.estimated_tokens,
        budget=pack.token_budget,
    )

    # Annotated rather than inline: a bare `((), (), ())` makes mypy infer T from the
    # DEFAULT (three empty tuples) instead of from the callable's real return type.
    empty_interpretations: tuple[
        tuple[CodeInterpretation, ...],
        tuple[ToolCallRecord, ...],
        tuple[VerifiedString, ...],
    ] = ((), (), ())
    degradations: list[str] = []
    interpretations, tool_calls, verified_strings = _guarded(
        "code_interpreter",
        lambda: interpret_methods(static, ledger, job_id, llm, pack=pack),
        default=empty_interpretations,
        errors=degradations,
    )
    # The other silent-empty path: `interpret_methods` degrades to no interpretations
    # WITHOUT raising when the provider returns nothing valid (it logs
    # `code_interpreter_unavailable`). Chains were selected, so emptiness here is a
    # provider failure, not the model declining its tools — say so in `errors`.
    if (
        pack.chains
        and not interpretations
        and not any("code_interpreter" in e for e in degradations)
    ):
        degradations.append(
            f"code_interpreter returned no interpretations for {len(pack.chains)} selected "
            "chains: provider unavailable or response invalid after retry"
        )

    victim = _guarded(
        "social_engineering",
        lambda: profile_victim(static, ui_strings, ledger, job_id, llm),
        default=None,
        errors=degradations,
    )
    verified_interpretations: list[CodeInterpretation] = []
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
        "behaviour_context": list(context_fired),
        "behavioural_risk_B": b_value,
        "summary": response.summary[:2000],
        "model": settings.resolved_llm_model,
        "claims_total": len(claims),
        "claims_verified": len(verified),
        "techniques": [t.technique_id for t in techniques],
        "retrieval": {
            "chains_selected": len(pack.chains),
            "chains_considered": pack.chains_considered,
            "methods_read": pack.method_count,
            "estimated_prompt_tokens": pack.estimated_tokens,
        },
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
        victim=victim,
        behavioural_risk_B=b_value,
        B_rationale=_b_rationale(contributing, context_fired),
        behaviours=dict(checklist),
        behaviour_context=behaviour_context,
        provider=settings.llm_provider,
        llm_calls=llm.calls_made,
        # NOT `partial`: the checklist itself succeeded, and the scorer drops B from
        # the fusion entirely when `partial` is set (`has_behavioural`). A failed
        # sub-agent degrades the narrative, not the term — `errors` carries the reason.
        errors=tuple(degradations),
        ledger_refs=(node.id, *static_refs),
    )


def _b_rationale(contributing: tuple[str, ...], context_fired: tuple[str, ...]) -> str:
    """One sentence saying what moved `B`, in both directions.

    The exculpatory half is the product owner's stated objective: a genuine app using a
    risky capability for a fair purpose must be SAID to be doing so, not silently
    down-weighted.
    """
    if not contributing:
        return "no weighted behaviour was asserted"
    parts = [f"{len(contributing)} weighted behaviours asserted: {', '.join(contributing)}"]
    exculpatory = [n for n in context_fired if CONTEXT_WEIGHTS[n] < 0]
    aggravating = [n for n in context_fired if CONTEXT_WEIGHTS[n] > 0]
    if exculpatory:
        parts.append(f"reduced by exculpatory context: {', '.join(exculpatory)}")
    if aggravating:
        parts.append(f"raised by aggravating context: {', '.join(aggravating)}")
    return "; ".join(parts)
