"""Technique Mapper: evidence -> MITRE ATT&CK Mobile, without inventing techniques.

docs/PHASE_3_GENAI_CORE.md T3.7, docs/00_GUIDING_MAP.md §10 item 6.

**The mapping is deterministic; the LLM is not in this path at all.**

Every sink in `m2_static/sinks.py` and every rule in `permission_combos.yaml` already
carries a MITRE id, chosen by a human when the detection was written. Asking a language
model to produce technique ids instead would be strictly worse: it would hallucinate
plausible-looking ids like `T1499` that no evidence supports, and a technique id is
exactly the sort of authoritative-looking token a reader does not think to check.

So this agent walks the evidence, looks each id up in `data/kb/mitre_mobile.json`, and
attaches the ledger nodes that justify it. An id absent from the KB is dropped rather
than passed through with a blank name — a technique we cannot describe is one we should
not be asserting.

`layer` is `static` here by construction. Only M3 can raise a technique to `dynamic`,
and conflating "the app could do this" with "we watched it do this" would overstate
every finding in the report.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import TechniqueMapping
from drishti.contracts.static_report import StaticReport
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger
from drishti.m2_static.sinks import SINK_BY_ID

log = get_logger(__name__)

KB_PATH = Path(__file__).resolve().parents[3] / "data" / "kb" / "mitre_mobile.json"


@lru_cache(maxsize=1)
def load_kb(path: str | None = None) -> dict[str, dict[str, str]]:
    """The MITRE cheat-sheet. Cached: it is a small static file read once per process.

    This is the whole of the RAG story, and deliberately so — `00_GUIDING_MAP.md` §10
    item 7 pre-agreed that retrieval gets cut in favour of an inlined cheat-sheet. A
    vector store over 21 techniques would be machinery without a purpose.
    """
    target = Path(path) if path else KB_PATH
    if not target.exists():
        log.warning("mitre_kb_missing", path=str(target))
        return {}
    payload = json.loads(target.read_text())
    techniques: dict[str, dict[str, str]] = payload.get("techniques", {})
    return techniques


def map_techniques(
    static: StaticReport,
    ledger: LedgerStore,
    job_id: str,
    *,
    kb_path: str | None = None,
) -> tuple[TechniqueMapping, ...]:
    """Derive grounded technique mappings from static evidence.

    Each mapping cites the ledger nodes that produced it, so a reader can click from a
    technique back to the permission combo or sink hit that justified it.
    """
    kb = load_kb(kb_path)
    if not kb:
        return ()

    # technique id -> the evidence nodes that support it
    support: dict[str, set[str]] = {}

    nodes = ledger.query(job_id=job_id)
    by_type: dict[EvidenceType, list] = {}
    for node in nodes:
        by_type.setdefault(node.type, []).append(node)

    for node in by_type.get(EvidenceType.PERMISSION_COMBO, []):
        technique = str(node.content.get("mitre") or "")
        if technique in kb:
            support.setdefault(technique, set()).add(node.id)

    for node in by_type.get(EvidenceType.SINK_HIT, []):
        sink = SINK_BY_ID.get(str(node.content.get("sink_id") or ""))
        if sink and sink.mitre in kb:
            support.setdefault(sink.mitre, set()).add(node.id)

    # A call path is stronger evidence than a bare sink hit: it shows the sink is
    # reachable from a lifecycle entrypoint rather than sitting in dead code.
    for node in by_type.get(EvidenceType.CALL_PATH, []):
        sink = SINK_BY_ID.get(str(node.content.get("sink_id") or ""))
        if sink and sink.mitre in kb:
            support.setdefault(sink.mitre, set()).add(node.id)

    # Fall back to the report when the ledger holds no citable node for a sink, so a
    # technique is not silently lost. It still only appears if the KB describes it.
    for sink_id in static.sink_hits:
        sink = SINK_BY_ID.get(sink_id)
        if sink and sink.mitre in kb:
            support.setdefault(sink.mitre, set())

    mappings = [
        TechniqueMapping(
            technique_id=technique,
            name=kb[technique]["name"],
            tactic=kb[technique]["tactic"],
            # `static` by construction. Only M3 may raise this to dynamic.
            layer="static",
            evidence_refs=tuple(sorted(refs)),
        )
        for technique, refs in sorted(support.items())
    ]
    log.info(
        "techniques_mapped",
        count=len(mappings),
        grounded=sum(1 for m in mappings if m.evidence_refs),
    )
    return tuple(mappings)
