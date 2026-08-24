"""The evidence ledger — the spine everything else references.

docs/01_DATA_CONTRACTS.md §1.

The ledger is what makes "every score point traces back to an artefact" true
rather than marketing. Two invariants live in the *store* (T0.4), not here,
because a schema cannot enforce them: append-only via SQL triggers, and the
rejection of an `AI_CLAIM` whose `evidence_refs` are empty or unresolvable.
"""

from __future__ import annotations

from enum import StrEnum

from drishti.contracts.base import DrishtiModel


class EvidenceType(StrEnum):
    """Node types, grouped by producing module.

    `StrEnum` so the ledger's JSON is human-readable — someone reading raw rows at
    3am should not have to decode integers.
    """

    # M1 ingest
    FILE_META = "file_meta"
    SPLIT_APK = "split_apk"
    THREAT_INTEL = "threat_intel"

    # M2 static
    MANIFEST_ENTRY = "manifest_entry"
    PERMISSION_COMBO = "permission_combo"
    CERTIFICATE = "certificate"
    STRING_CONST = "string_const"
    CODE_METHOD = "code_method"
    DECOMPILED_METHOD = "decompiled_method"
    DEOBFUSCATED_STRING = "deobfuscated_string"
    CALL_PATH = "call_path"
    SINK_HIT = "sink_hit"
    OVERPRIVILEGE = "overprivilege"

    # M3 dynamic
    API_TRACE = "api_trace"
    NETWORK_FLOW = "network_flow"
    DECRYPTED_BLOB = "decrypted_blob"
    FILE_WRITE = "file_write"
    DEX_LOAD = "dex_load"
    SCREENSHOT = "screenshot"

    # P5 frontier
    EVASION_CHECK = "evasion_check"
    MORPH_ACTION = "morph_action"
    GENERATIVE_C2 = "generative_c2"
    DETONATION = "detonation"

    # M4 genai
    AI_CLAIM = "ai_claim"
    AI_HYPOTHESIS = "ai_hypothesis"
    TECHNIQUE_MAP = "technique_map"
    VISION_MATCH = "vision_match"
    AI_TOOL_CALL = "ai_tool_call"

    # M7
    #: Attests that a report was rendered from a given chain at a given time. Added in
    #: T0.6: the REPORT stage was previously mis-typed as ANALYST_ACTION, which means
    #: "a human confirmed something" and made a rendering step indistinguishable from
    #: a human decision in the ledger.
    REPORT_GENERATED = "report_generated"

    # M5 / M6
    ML_PREDICTION = "ml_prediction"
    ANOMALY_SIGNAL = "anomaly_signal"
    SCORE_FACTOR = "score_factor"

    # meta
    ERROR = "error"
    ANALYST_ACTION = "analyst_action"


#: Node types whose content is produced by an LLM and therefore must cite
#: evidence. `store.append()` rejects one of these with empty or unresolvable
#: `evidence_refs` — that rejection is the product (CLAUDE.md rule 5).
GROUNDING_REQUIRED: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.AI_CLAIM,
    }
)


class EvidenceNode(DrishtiModel):
    """One immutable, signed link in a job's hash chain.

    `confidence` is the *producer's* confidence, not a consensus value — an
    androguard fact is 1.0, an LLM inference is not.

    `parents` are DAG edges recording what this node was derived from. The chain
    (`prev_hash`) proves nothing was tampered with; `parents` proves *why* a node
    exists. The provenance path static hypothesis -> hook -> observed event is the
    "closed loop" claim in evidence form, and it lives in this field.
    """

    id: str
    job_id: str
    seq: int
    type: EvidenceType
    source_tool: str
    content: dict
    location: str | None = None
    confidence: float
    parents: tuple[str, ...] = ()
    timestamp: str
    prev_hash: str
    node_hash: str
    signature: str


class ChainVerification(DrishtiModel):
    """Result of walking a job's chain from genesis.

    `first_bad_seq` is exact, not a boolean — "the ledger is broken somewhere" is
    not a useful answer to an auditor, and the tamper test asserts the precise seq.
    """

    ok: bool
    node_count: int
    first_bad_seq: int | None = None
    reason: str | None = None
