"""Code-graph RAG: choose the few method chains worth reading, and nothing else.

docs/ROADMAP_GENAI_RE.md A1/A2, docs/PHASE_3_GENAI_CORE.md T3.3-T3.4,
docs/00_GUIDING_MAP.md §12.

The retrieval substrate is `m2_static/callgraph.backward_paths`, which walks
**backwards from a dangerous sink** to a lifecycle entrypoint. That already answers
"which code can reach `sendTextMessage`". This module answers the next question:
*of everything that can, what do we put in front of the model?*

Three properties, each with a specific failure behind it:

  * **Pure and deterministic.** No I/O, no clock, no randomness. Given the same
    `StaticReport` it selects the same chains in the same order, so a cached run and
    a live run are comparable and a regression is a diff rather than a mood.
  * **Ranked by sink severity, lifecycle reachability and proximity.** Prompt budget
    is finite and a `dex_load` reachable from `onCreate` matters more than a
    `pkg_resolve` in dead library code. Selection is the whole value of having a
    call graph — otherwise we would just concatenate the decompiled APK, which is
    400k tokens and worse answers.
  * **Budget is an assert, not a hope.** `select()` fills greedily to
    `token_budget` and records exactly what it dropped. If the pack does not fit,
    the retrieval is wrong and the pack shrinks; the budget never rises.

Nearest-to-sink methods win the ties. The method that actually calls the dangerous
API is where the interesting code is; the lifecycle entrypoint three frames up is
usually `onCreate` doing nothing but delegating.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drishti.config import Settings

from dataclasses import dataclass, field

from drishti.contracts.static_report import CallPath, DecompiledMethod, Severity, StaticReport
from drishti.m2_static.sinks import SINK_BY_ID
from drishti.m4_genai.client import CHARS_PER_TOKEN
from drishti.m4_genai.safety import wrap_untrusted

#: How much of the 12k input budget the code workspace may consume. The rest pays for
#: the system prompt, the evidence catalogue, the manifest facts and the tool schemas.
#: Workspace budget. Lowered from 5,000 once the tool loop was measured end to end: the
#: pack is only round 0's cost, and round 1 carries the tool results as well. The binding
#: constraint is the provider's per-request ceiling, not the prompt budget in config.
DEFAULT_TOKEN_BUDGET = 1_800

#: Room the tool loop needs on top of the workspace itself, in tokens. Measured against
#: the live endpoint: the system prompt and six tool declarations cost ~1,400, and round 1
#: carries every tool result back on top of round 0's prompt.
_LOOP_OVERHEAD_TOKENS = 2_600

#: Room for the tool results round 1 carries back. Bounded by `MAX_TOOL_CALLS` x
#: `MAX_TOOL_RESULT_CHARS`, so it is a constant rather than a share of the ceiling.
_TOOL_RESULT_RESERVE = 1_500


def workspace_budget(settings: Settings) -> int:
    """How much decompiled code to put in front of the model, given the provider.

    `DEFAULT_TOKEN_BUDGET` was cut from 5,000 to 1,800 so the tool loop would fit Groq's
    8,000-token-per-minute ceiling, where prompt plus reserved output share one budget.
    That was correct for Groq and became the thing starving the reverse-engineering
    layer the moment the provider changed: on Gemini the ceiling is 1,048,576 and the
    workspace was still 1,800, so a job with 12 sink-reachable methods showed the model
    about three of them and reported the other nine as uninterpreted.

    Two ceilings bind, and the smaller wins:

      * the PROVIDER's per-request limit (`llm_max_request_tokens`), which is a hard
        rejection — exceed it and the round carrying the tool results is refused;
      * OUR prompt budget (`llm_max_prompt_tokens`), which is a deliberate assert, not a
        provider constraint. CLAUDE.md rule 10 fixes it at 12k, and a bigger provider is
        not a reason to spend more of a job's tokens on one stage.
    """
    ceiling = min(
        getattr(settings, "llm_max_request_tokens", 8_000),
        getattr(settings, "llm_max_prompt_tokens", 12_000),
    )
    # Reserve the pieces that actually compete for the ceiling, rather than a flat
    # fraction. Tool results do NOT grow with the ceiling — they are capped by
    # MAX_TOOL_CALLS x MAX_TOOL_RESULT_CHARS — so treating them as a proportion wastes
    # most of a large provider's headroom, which is how a 1M-token model ended up reading
    # three method bodies.
    answer = min(3_000, ceiling // 5)
    return max(500, ceiling - _LOOP_OVERHEAD_TOKENS - answer - _TOOL_RESULT_RESERVE)


#: Never send more than this many chains however small they are — a model given
#: twenty shallow chains produces twenty shallow answers.
MAX_CHAINS = 6

#: Per chain. Beyond three frames the extra methods are almost always framework glue.
MAX_METHODS_PER_CHAIN = 3

#: Sample-derived strings offered alongside the code, so a decoded constant can be
#: tied to the method that consumes it.
MAX_STRINGS = 12

#: Severity ordering as a number, so ranking is arithmetic rather than a chain of ifs.
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.3,
}

#: A sink sitting in code no entrypoint reaches is much weaker evidence. It is not
#: zero — an unreachable `DexClassLoader` is still worth a sentence — but it must
#: never outrank a reachable one.
_UNREACHABLE_FACTOR = 0.35


@dataclass(frozen=True)
class MethodSlice:
    """One decompiled method, positioned on the chain that selected it."""

    signature: str
    body: str
    evidence_ref: str
    line_start: int
    line_end: int
    truncated: bool
    #: 1 = calls the sink directly. Larger = further up towards the entrypoint.
    distance_to_sink: int

    @property
    def chars(self) -> int:
        return len(self.body) + len(self.signature)


@dataclass(frozen=True)
class SinkChain:
    """One backward path from a sink, with whatever source we recovered along it."""

    sink_id: str
    sink_signature: str
    entrypoint: str
    entrypoint_kind: str
    reachable_from_lifecycle: bool
    path: tuple[str, ...]
    severity: Severity
    mitre: str
    risk: float
    methods: tuple[MethodSlice, ...] = ()

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        return tuple(m.evidence_ref for m in self.methods)


@dataclass(frozen=True)
class RetrievalPack:
    """What the reverse-engineering agents are allowed to see, and what it cost."""

    chains: tuple[SinkChain, ...] = ()
    strings: tuple[str, ...] = ()
    token_budget: int = DEFAULT_TOKEN_BUDGET
    estimated_tokens: int = 0
    chains_considered: int = 0
    chains_dropped: int = 0
    methods_dropped: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def method_count(self) -> int:
        return sum(len(chain.methods) for chain in self.chains)

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        seen: list[str] = []
        for chain in self.chains:
            for ref in chain.evidence_refs:
                if ref not in seen:
                    seen.append(ref)
        return tuple(seen)

    @property
    def has_source(self) -> bool:
        """False when nothing decompiled — the agents then narrate, and must say so."""
        return self.method_count > 0


def rank_paths(call_paths: tuple[CallPath, ...]) -> tuple[tuple[float, CallPath], ...]:
    """Score every recovered backward path. Highest risk first, deterministic ties.

    `risk = severity x reachability x 1/(1 + depth)`. Depth discounts because a long
    chain to a sink is usually framework plumbing, and because a short chain is
    cheaper to explain in the tokens we have.
    """
    scored: list[tuple[float, CallPath]] = []
    for path in call_paths:
        sink = SINK_BY_ID.get(path.sink_id)
        severity = sink.severity if sink else Severity.LOW
        weight = _SEVERITY_WEIGHT.get(severity, 0.3)
        reach = 1.0 if path.reachable_from_lifecycle else _UNREACHABLE_FACTOR
        depth = max(len(path.path) - 1, 0)
        risk = weight * reach / (1.0 + depth)
        scored.append((round(risk, 6), path))
    # Sort by risk desc, then by a stable textual key so equal-risk paths never swap
    # order between runs (PYTHONHASHSEED has bitten this repo before — see 7cd1997).
    scored.sort(key=lambda item: (-item[0], item[1].sink_id, item[1].entrypoint))
    return tuple(scored)


def select(
    static: StaticReport,
    *,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    max_chains: int = MAX_CHAINS,
    max_methods_per_chain: int = MAX_METHODS_PER_CHAIN,
) -> RetrievalPack:
    """Choose the sink chains and method bodies that fit the budget.

    Never raises: a report with no call paths yields an empty pack, and the caller
    degrades by saying it had no code to read rather than by inventing one.
    """
    by_signature: dict[str, DecompiledMethod] = {m.signature: m for m in static.decompiled_methods}
    ranked = rank_paths(static.call_paths)
    notes: list[str] = []

    seen_keys: set[tuple[str, str]] = set()
    candidates: list[tuple[float, CallPath]] = []
    for risk, path in ranked:
        key = (path.sink_id, path.entrypoint)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        candidates.append((risk, path))

    # Constants are charged first: they are cheap, they are the same for every chain,
    # and paying for them up front keeps the running total honest.
    strings = _select_strings(static)
    spent = sum(len(value) + 40 for value in strings) // CHARS_PER_TOKEN
    chains: list[SinkChain] = []
    methods_dropped = 0
    for risk, path in candidates:
        if len(chains) >= max_chains:
            break
        # Charge the chain's own header — sink, entrypoint, every step — before its
        # bodies. Counting only method text is how a "bounded" prompt quietly grows:
        # thirty chains of pure structure still cost real tokens.
        structural = _chain_overhead(path) // CHARS_PER_TOKEN
        if spent + structural > token_budget:
            break
        spent += structural
        slices, dropped, spent = _fill_chain(
            path,
            by_signature,
            spent=spent,
            token_budget=token_budget,
            max_methods=max_methods_per_chain,
        )
        methods_dropped += dropped
        sink = SINK_BY_ID.get(path.sink_id)
        chains.append(
            SinkChain(
                sink_id=path.sink_id,
                sink_signature=path.sink_signature,
                entrypoint=path.entrypoint,
                entrypoint_kind=path.entrypoint_kind,
                reachable_from_lifecycle=path.reachable_from_lifecycle,
                path=path.path,
                severity=sink.severity if sink else Severity.LOW,
                mitre=sink.mitre if sink else "",
                risk=risk,
                methods=slices,
            )
        )

    dropped_chains = max(len(candidates) - len(chains), 0)
    if dropped_chains:
        notes.append(
            f"{dropped_chains} lower-risk sink chains were not sent; selection is by "
            "sink severity, lifecycle reachability and depth"
        )
    if methods_dropped:
        notes.append(
            f"{methods_dropped} method bodies on selected chains did not fit the "
            f"{token_budget}-token workspace budget"
        )
    if static.call_paths and not any(chain.methods for chain in chains):
        notes.append(
            "no decompiled source was recovered for the selected chains; the agents "
            "see call-graph structure only"
        )

    estimated = _estimate(chains, strings)
    return RetrievalPack(
        chains=tuple(chains),
        strings=strings,
        token_budget=token_budget,
        estimated_tokens=estimated,
        chains_considered=len(candidates),
        chains_dropped=dropped_chains,
        methods_dropped=methods_dropped,
        notes=tuple(notes),
    )


def _chain_overhead(path: CallPath) -> int:
    """Characters one chain costs before any source body is attached."""
    return (
        len(path.sink_signature)
        + len(path.entrypoint)
        + 120
        + sum(len(step) + 4 for step in path.path)
    )


def _fill_chain(
    path: CallPath,
    by_signature: dict[str, DecompiledMethod],
    *,
    spent: int,
    token_budget: int,
    max_methods: int,
) -> tuple[tuple[MethodSlice, ...], int, int]:
    """Attach method bodies nearest the sink first, stopping at the budget."""
    slices: list[MethodSlice] = []
    dropped = 0
    # `path` runs entrypoint -> ... -> sink, so reversed() is "walk back from the sink",
    # which is the order an analyst reads it in and the order value decreases in.
    for distance, signature in enumerate(reversed(path.path)):
        if signature == path.sink_signature:
            continue
        method = by_signature.get(signature)
        if method is None:
            continue
        if len(slices) >= max_methods:
            dropped += 1
            continue
        # +160 for the wrapper, the evidence-id line and the untrusted_artifact tags,
        # so the accounting matches `_estimate` and the budget assert means something.
        cost = (len(method.body) + len(method.signature) + 160) // CHARS_PER_TOKEN
        if spent + cost > token_budget:
            dropped += 1
            continue
        spent += cost
        slices.append(
            MethodSlice(
                signature=method.signature,
                body=method.body,
                evidence_ref=method.evidence_ref,
                line_start=method.line_start,
                line_end=method.line_end,
                truncated=method.truncated,
                distance_to_sink=distance,
            )
        )
    return tuple(slices), dropped, spent


def _select_strings(static: StaticReport) -> tuple[str, ...]:
    """Constants worth showing beside the code: URLs first, then crypto material."""
    values: list[str] = []
    for value in (*static.urls, *static.crypto_constants):
        if value not in values:
            values.append(value)
        if len(values) >= MAX_STRINGS:
            break
    return tuple(values)


def _estimate(chains: list[SinkChain], strings: tuple[str, ...]) -> int:
    chars = sum(len(s) + 40 for s in strings)
    for chain in chains:
        chars += len(chain.sink_signature) + len(chain.entrypoint) + 120
        chars += sum(len(step) + 4 for step in chain.path)
        chars += sum(slice_.chars + 160 for slice_ in chain.methods)
    return chars // CHARS_PER_TOKEN


def render_workspace(pack: RetrievalPack) -> str:
    """Render the pack for the USER turn. Sample text is wrapped, never inlined.

    Chain structure (signatures, depth, sink id) is derived by our analyser and is
    stated plainly; method **bodies** are attacker-controlled and go inside
    `<untrusted_artifact>` blocks, XML-escaped (CLAUDE.md rule 6).
    """
    if not pack.chains:
        return "No sink-reachable call chains were recovered for this sample."

    parts: list[str] = ["SINK CHAINS SELECTED BY BACKWARD CALL-GRAPH TRAVERSAL:"]
    for index, chain in enumerate(pack.chains):
        parts.append(
            f"\n[chain {index}] sink={chain.sink_id} severity={chain.severity.value} "
            f"mitre={chain.mitre or 'n/a'} "
            f"reachable_from_lifecycle={chain.reachable_from_lifecycle} "
            f"depth={max(len(chain.path) - 1, 0)}"
        )
        parts.append(f"  entrypoint: {chain.entrypoint} ({chain.entrypoint_kind})")
        parts.append(f"  sink: {chain.sink_signature}")
        if not chain.methods:
            parts.append("  (no source recovered for this chain)")
            continue
        for slice_ in chain.methods:
            parts.append(
                f"\n  source for {slice_.signature} "
                f"(evidence id {slice_.evidence_ref}, lines "
                f"{slice_.line_start}-{slice_.line_end}, "
                f"{slice_.distance_to_sink} frame(s) from the sink"
                f"{', TRUNCATED' if slice_.truncated else ''}):"
            )
            parts.append(wrap_untrusted(slice_.body, kind="decompiled_method"))

    if pack.strings:
        parts.append("\nString constants extracted from this sample:")
        parts.append(wrap_untrusted("\n".join(pack.strings), kind="string_constant"))

    for note in pack.notes:
        parts.append(f"\nRetrieval note: {note}")
    return "\n".join(parts)
