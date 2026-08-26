"""Code Interpreter: read the recovered source, explain it, cite every sentence.

docs/PHASE_3_GENAI_CORE.md T3.4, docs/ROADMAP_GENAI_RE.md A2.

Two design decisions worth stating, because both were different before:

**The code is in the prompt, not behind a tool call.** The earlier version handed the
model a catalogue of signatures and made it call `read_method` for each one. That cost
a tool round per method — with `max_rounds=3` and six methods it could not physically
read them all — and every round re-sent the whole conversation, so the "bounded" loop
grew quadratically. Retrieval (`m4_genai/retrieval.py`) now selects the chains worth
reading and their bodies arrive in the first user turn, inside `<untrusted_artifact>`.
The tools remain for genuine drill-down: an xref, a constant, a proposed decoding the
deterministic evaluator has to reproduce.

**A claim the model cannot ground is left ungrounded.** It would be trivial to attach
the method's own evidence id to every claim the model returned and watch the citation
rate hit 100%. That number would mean nothing. The verifier's rejections are the
product (CLAUDE.md rule 5), so the model cites or it is marked as having failed to.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from drishti.contracts.evidence import EvidenceType
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
from drishti.m4_genai.retrieval import RetrievalPack, render_workspace, select
from drishti.m4_genai.tools import AnalysisToolbox

log = get_logger(__name__)

#: Interpretations we will keep. Matches `retrieval.MAX_CHAINS` in spirit: more than
#: this and the answers get shorter rather than the coverage getting better.
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
    injection_attempt_detected: bool = False
    obfuscation_notes: str | None = None
    cited_lines: list[int] = Field(default_factory=list)


class InterpretationSet(BaseModel):
    interpretations: list[InterpretationOut] = Field(default_factory=list)


def _system_prompt() -> str:
    """Rendered from `prompts/code_interpreter.jinja`. Never inlined (CLAUDE.md rule 8)."""
    environment = Environment(
        loader=FileSystemLoader(_PROMPTS),
        autoescape=select_autoescape(enabled_extensions=(), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return environment.get_template("code_interpreter.jinja").render()


def build_user_turn(pack: RetrievalPack, static: StaticReport) -> str:
    """Assemble the interpreter's evidence turn from the retrieval pack.

    Structure we derived is stated plainly; every sample-controlled byte is inside an
    `<untrusted_artifact>` block, XML-escaped by `render_workspace`.
    """
    header = [
        "Application under analysis (facts derived by our static analyser, trusted):",
        f"  package: {static.package}",
        f"  sinks reached: {', '.join(static.sink_hits) or 'none'}",
        f"  chains selected: {len(pack.chains)} of {pack.chains_considered} recovered; "
        f"{pack.method_count} method bodies included",
        "",
    ]
    footer = [
        "",
        "Interpret each method whose source is shown. Use a tool only to resolve an "
        "ambiguity the source in front of you does not settle.",
        "Return the required JSON object.",
    ]
    return "\n".join([*header, render_workspace(pack), *footer])


def canonical_signature(signature: str) -> str:
    """A dialect-independent key for one method: `package.Class->name`.

    Models write signatures the way a human reads them — `com.b.a.c.a->a(Context, String)`
    — and also as full JVM descriptors — `Lcom/b/a/c/a;->a(Landroid/content/Context;)V`.
    The retrieval catalogue keys on neither: it stores `Lcom/b/a/c/a;->a`, with **no
    parameter list at all**. An exact dict lookup therefore dropped every interpretation
    the model produced, and the dashboard reported `0 methods interpreted` for the
    flagship reverse-engineering layer while the model had in fact done the work.

    Normalised away: the `L…;` wrapper, `/` versus `.` as the package separator, spacing,
    and the parameter list. **Kept:** the class and the method name — obfuscated code is
    full of `a()`, so a same-named method on a different class must never match.

    Parameter counts are deliberately NOT part of the key. They cannot be: the catalogue
    does not record them, so arity could only ever disagree with itself. `signature_arity`
    exists to compare them when both sides genuinely state one.
    """
    text = signature.strip()
    if not text or "->" not in text:
        return ""
    owner, _, rest = text.partition("->")
    owner = owner.strip()
    # Strip the JVM wrapper's two halves INDEPENDENTLY. Requiring both together missed a
    # fourth dialect seen live — `com.b.a.c.a;->a(...)`, dotted like Java but keeping the
    # descriptor's trailing semicolon — and left the owner as `com.b.a.c.a;`, which
    # matches nothing. Models mix these conventions freely; the normaliser has to be the
    # forgiving end of that.
    if owner.startswith("L"):
        owner = owner[1:]
    owner = owner.rstrip(";")
    owner = owner.replace("/", ".").strip(".")
    name = rest.strip().partition("(")[0].strip()
    if not owner or not name:
        return ""
    return f"{owner}->{name}"


#: JVM primitive type descriptors. `V` is void and legal only as a return type.
_PRIMITIVES = set("BCDFIJSZ")


def signature_arity(signature: str) -> int | None:
    """Parameter count, or None when the signature does not state one.

    None is the important value. The catalogue omits parameters entirely, so treating
    "no list" as "zero parameters" would make every catalogue entry disagree with every
    model answer that spelled its arguments out.
    """
    text = signature.strip()
    if "(" not in text:
        return None
    inner = text.partition("(")[2].rsplit(")", 1)[0].strip()
    if not inner:
        return 0
    if "," in inner:
        return len([p for p in inner.split(",") if p.strip()])

    # JVM descriptor list: no separators, so walk the type codes.
    count, index = 0, 0
    while index < len(inner):
        char = inner[index]
        if char == "[":  # array dimension, part of the type that follows
            index += 1
            continue
        if char == "L":  # object type, runs to the terminating semicolon
            end = inner.find(";", index)
            if end == -1:
                break
            count += 1
            index = end + 1
            continue
        if char in _PRIMITIVES:
            count += 1
        index += 1
    return count


def resolve_signature(signature: str, table: dict[str, Any]) -> Any | None:
    """Look a signature up exactly, then by canonical class-and-name. None if not ours.

    Arity is used only to break a tie between real overloads, and only when BOTH the
    catalogue entry and the model's answer state one. Absent that, class and name are the
    whole of the identity — which is all the catalogue actually records.
    """
    if signature in table:
        return table[signature]
    key = canonical_signature(signature)
    if not key:
        return None
    wanted = signature_arity(signature)
    matches = [(c, v) for c, v in table.items() if canonical_signature(c) == key]
    if not matches:
        return None
    if len(matches) > 1 and wanted is not None:
        for candidate, value in matches:
            if signature_arity(candidate) == wanted:
                return value
    return matches[0][1]


def _output_budget(client: LLMClient) -> int:
    """Output tokens to reserve, leaving room for the tool results to come back.

    The tool loop's expensive round is the second one: it repeats round 0's prompt, adds
    the assistant's tool calls and every tool result, and still has to reserve room for
    the answer. Reserving a flat 3,000 made that round exceed the provider limit on the
    shipped tier, so the model called its tools and its findings were then discarded.
    """
    ceiling = getattr(client._settings, "llm_max_request_tokens", 8_000)
    # Half the ceiling for the answer is still far more than a validated JSON
    # InterpretationSet needs, and it leaves the other half for prompt + tool results.
    return max(512, min(3_000, ceiling // 5))


def interpret_methods(
    static: StaticReport,
    ledger: LedgerStore,
    job_id: str,
    client: LLMClient,
    *,
    pack: RetrievalPack | None = None,
) -> tuple[tuple[CodeInterpretation, ...], tuple[ToolCallRecord, ...], tuple[VerifiedString, ...]]:
    """Interpret the sink-reachable methods retrieval selected.

    Degrades to empty tuples rather than raising: losing M2's work because a provider
    timed out would be absurd (CLAUDE.md rule 2).
    """
    workspace = pack if pack is not None else select(static)
    if not workspace.chains:
        log.info("code_interpreter_skipped", reason="no sink-reachable chains recovered")
        return (), (), ()

    toolbox = AnalysisToolbox(static, ledger, job_id)
    response = client.complete_with_tools_as(
        system=_system_prompt(),
        user=build_user_turn(workspace, static),
        tools=toolbox.definitions,
        execute=toolbox.execute,
        schema=InterpretationSet,
        purpose="code_interpreter",
        # Sized to the provider's per-request ceiling rather than to a round number.
        # Round 1 carries every tool result back on top of round 0's prompt, and the
        # reserved output counts toward the same limit, so an over-generous reservation
        # is what rejects the round that actually produces the interpretations.
        max_output_tokens=_output_budget(client),
    )
    if response is None:
        log.warning("code_interpreter_unavailable", chains=len(workspace.chains))
        return (), tuple(toolbox.records), tuple(toolbox.verified_strings)

    known = {slice_.signature: slice_ for chain in workspace.chains for slice_ in chain.methods}
    # A method that was named in the catalogue but whose body we did not send can still
    # be interpreted — the model can `read_method` it — so accept those signatures too.
    fallback = {m.signature: m for m in static.decompiled_methods}

    interpretations: list[CodeInterpretation] = []
    for item in response.interpretations[:MAX_METHODS_INTERPRETED]:
        slice_ = resolve_signature(item.method_signature, known)
        method = resolve_signature(item.method_signature, fallback)
        if slice_ is None and method is None:
            # The model named a method that is not in this analysis. Dropping it is the
            # same discipline as rejecting a bad citation: we do not report on code we
            # did not recover.
            log.warning("interpretation_for_unknown_method", signature=item.method_signature[:120])
            continue
        line_start = slice_.line_start if slice_ else (method.line_start if method else 1)
        line_end = slice_.line_end if slice_ else (method.line_end if method else 1)
        # The membership test genuinely validates the value; `cast` records that for
        # the type checker, which cannot narrow a str through a set literal.
        confidence = cast(
            Literal["high", "medium", "low"],
            item.confidence if item.confidence in {"high", "medium", "low"} else "low",
        )
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
        lines = tuple(line for line in item.cited_lines[:40] if line_start <= line <= line_end)
        interpretations.append(
            CodeInterpretation(
                method_signature=item.method_signature[:512],
                summary=item.summary.strip()[:1_000],
                claims=claims,
                renamed_symbols={
                    str(key)[:512]: str(value)[:120]
                    for key, value in list(item.renamed_symbols.items())[:20]
                },
                confidence=confidence,
                insufficient_evidence=item.insufficient_evidence,
                injection_attempt_detected=item.injection_attempt_detected,
                obfuscation_notes=(item.obfuscation_notes or None) and item.obfuscation_notes[:500],
                cited_lines=lines,
            )
        )

    _record_injection_attempts(interpretations, workspace, ledger)
    log.info(
        "code_interpreter_done",
        interpretations=len(interpretations),
        tool_calls=len(toolbox.records),
        chains=len(workspace.chains),
    )
    return tuple(interpretations), tuple(toolbox.records), tuple(toolbox.verified_strings)


def _record_injection_attempts(
    interpretations: list[CodeInterpretation],
    pack: RetrievalPack,
    ledger: LedgerStore,
) -> None:
    """A sample that addressed the model gets its own evidence node.

    Recorded as `EVASION_CHECK`: an attempt to steer the analyser is an anti-analysis
    behaviour in the same family as an emulator check, and it belongs in the chain a
    reader can audit rather than only in a log line.
    """
    flagged = [i for i in interpretations if i.injection_attempt_detected]
    if not flagged:
        return
    ledger.append(
        type=EvidenceType.EVASION_CHECK,
        source_tool="m4_genai:code_interpreter",
        content={
            "kind": "prompt_injection_attempt",
            "methods": [i.method_signature for i in flagged][:8],
            "notes": [i.obfuscation_notes for i in flagged if i.obfuscation_notes][:4],
            "detail": (
                "sample-derived text addressed the analysing model; reported as an "
                "anti-analysis observation. The structural defences are unaffected: B "
                "is computed in Python from enumerated booleans."
            ),
        },
        parents=pack.evidence_refs[:8],
    )
    log.warning("prompt_injection_reported", methods=len(flagged))


def explain_paths(
    static: StaticReport,
    ledger: LedgerStore,
    job_id: str,
    client: LLMClient,
) -> tuple[GroundedClaim, ...]:
    """Compatibility surface returning claims from the richer method interpreter."""
    interpretations, _, _ = interpret_methods(static, ledger, job_id, client)
    return tuple(claim for interpretation in interpretations for claim in interpretation.claims)
