"""M3 dynamic analysis contracts.

docs/01_DATA_CONTRACTS.md §3. `DecryptedBlob`, `DexLoadEvent` and `FileWrite` are
additions under the §0 rule — `DynamicTrace` referenced them without definition.

`ObservationEvent` and `ObservationArtifact` are the detonator *wire* contract and
are deliberately stricter than the rest of the package: they cross a trust boundary
out of a VM that just executed malware. Ported from v1, which got this right (see
docs/SALVAGE.md — the one place v1 is stricter than the v2 spec).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StringConstraints, field_validator

from drishti.contracts.base import AnalyserResult, DrishtiModel

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: MITRE ATT&CK Mobile technique id, e.g. T1582 or T1641.001.
MitreId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(?:\.\d{3})?$")]


class TraceSourceKind(StrEnum):
    LIVE = "live"
    REPLAY = "replay"
    UNAVAILABLE = "unavailable"


class ApiEvent(DrishtiModel):
    """One hooked call. Args are stringified and truncated to 256 chars each.

    A chatty app calls `getPackageInfo` hundreds of times; the normaliser collapses
    identical (api, args) pairs and keeps distinct-argument events, so this model
    represents a *deduplicated* observation rather than a raw hook firing.
    """

    t_ms: int
    api: str
    args: tuple[str, ...] = ()
    retval: str | None = None
    thread: str = "main"
    stack: tuple[str, ...] = ()
    count: int = 1


class NetworkFlow(DrishtiModel):
    """A request/response pair from mitmproxy.

    `synthesised=True` means *we* served this response from the Generative C2, not
    real attacker infrastructure. The distinction has to survive into the report:
    a dead C2 stays dead, and claiming otherwise would be a lie about provenance.
    """

    t_ms: int
    method: str
    url: str
    host: str
    req_headers: dict = Field(default_factory=dict)
    req_body_preview: str = ""
    req_body_sha256: str | None = None
    status: int | None = None
    resp_body_preview: str | None = None
    synthesised: bool = False
    tls_intercepted: bool = False


class DecryptedBlob(DrishtiModel):
    """Plaintext captured from `Cipher.doFinal` before encryption.

    This is what neutralises custom-crypto exfil (T1521): TLS interception shows
    ciphertext, but the memory hook has the cleartext. One real sample called
    `doFinal` 1,925 times in 60s doing byte-at-a-time deobfuscation, which is why
    `occurrences` exists rather than 1,925 separate rows.
    """

    t_ms: int
    algorithm: str | None = None
    plaintext_preview: str
    plaintext_sha256: str | None = None
    length_bytes: int = 0
    contains_url: bool = False
    contains_dex_magic: bool = False
    occurrences: int = 1


class SyntheticC2Response(DrishtiModel):
    """One response DRISHTI synthesised and served in place of a dead C2.

    This is *our* content injected into the analysis, so every field a reader needs to
    audit it is here: the request that triggered it, the shape we chose, the body we
    served, and — the honest metric — whether the sample's behaviour changed after it.

    `provably_inert` is not a hope. It is set by `assert_inert`, which sanitises the
    body against a fixed allowlist of response shapes and neutralises anything that
    could resolve, execute or load. `neutralisations` records every change that guard
    made, so "we served an inert response" is a claim with a diff behind it.
    """

    t_ms: int = 0
    host: str = ""
    url: str = ""
    request_method: str = "GET"
    response_kind: str = ""
    inferred_schema: dict = Field(default_factory=dict)
    served_status: int = 200
    served_content_type: str = "application/json"
    served_body: str = ""
    reasoning: str = ""
    #: Set only by the deterministic inertness gate. Never by the model, never by a flag.
    provably_inert: bool = False
    neutralisations: tuple[str, ...] = ()
    #: The honest "did it work" field. None until a second pass observes the effect.
    behaviour_changed: bool | None = None
    evidence_refs: tuple[str, ...] = ()


class DexLoadEvent(DrishtiModel):
    """Runtime code loading — the dropper signal (T1407).

    `in_original_apk=False` means the sample produced code that static analysis
    never saw, which is the strongest single input to the `D` drift term.
    """

    t_ms: int
    loader: str
    path: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    in_original_apk: bool = False
    dumped_to: str | None = None


class FileWrite(DrishtiModel):
    t_ms: int
    path: str
    size_bytes: int | None = None
    sha256: str | None = None
    is_executable_content: bool = False
    deleted_after: bool = False


class EvasionObservation(DrishtiModel):
    """A probe -> miss -> stall pattern. The bridge to P5.

    This is the highest-value observation in M3: it is what lets the demo say *"the
    sample asked whether the SBI app was installed, got no, and went to sleep — here
    is the exact timestamp and stack frame."* Without it, morphing is a guess.
    """

    probe_kind: str
    queried: str
    result: Literal["HIT", "MISS"]
    t_ms: int
    followed_by_stall: bool = False
    stall_duration_ms: int | None = None
    inferred_requirement: str | None = None
    stack: tuple[str, ...] = ()


class DynamicTrace(AnalyserResult):
    """M3 output, normalised from Frida + mitmproxy + logcat.

    `detonated` is computed by a written-down deterministic rule (PHASE_4 T4.6), not
    by judgement, because the UI headlines it and the `gamma` confidence term reads
    it. `detonation_reason` records which rule fired first.

    An empty trace is `inconclusive`, never benign: environment-aware stalling is
    indistinguishable from a clean app if you let it be (CARRIED_FINDINGS.md H1/H2).
    """

    run_id: str
    source: TraceSourceKind
    detonated: bool = False
    detonation_reason: str | None = None
    outcome: Literal["completed", "inconclusive", "failed", "timeout", "crashed"] = "inconclusive"
    api_events: tuple[ApiEvent, ...] = ()
    network_flows: tuple[NetworkFlow, ...] = ()
    decrypted_blobs: tuple[DecryptedBlob, ...] = ()
    dex_loads: tuple[DexLoadEvent, ...] = ()
    file_writes: tuple[FileWrite, ...] = ()
    evasion_observations: tuple[EvasionObservation, ...] = ()
    screenshots: tuple[str, ...] = ()
    morphs_applied: tuple[str, ...] = ()
    ledger_refs: tuple[str, ...] = ()

    # Provenance. Replay-vs-live in the UI is derived from these fields, never from
    # a config flag someone might forget to flip (CLAUDE.md honesty requirements).
    emulator_image: str | None = None
    vm_instance_id: str | None = None
    harness_version: str | None = None
    containment_verified: bool = False
    captured_at: str | None = None

    #: True when this trace was **hand-authored**, not captured from a real execution.
    #:
    #: `source == REPLAY` only says the trace came from a fixture — and replaying a
    #: real captured trace is legitimate and disclosed. This field separates that from
    #: the P0 case, where the fixture contains plausible values somebody typed. The
    #: report's Limitations section is generated from flags like this one, so a
    #: hand-authored trace cannot silently present itself as a measurement.
    synthetic: bool = False


# ─── Detonator wire contract ────────────────────────────────────────────────────
# Stricter than DrishtiModel on purpose: `strict=True` refuses type coercion, so a
# malformed artifact from the VM fails loudly instead of being silently massaged
# into something plausible.


class StrictWireModel(DrishtiModel):
    """Base for the artifact that crosses out of the detonation VM.

    `strict=True` is the point: no type coercion, so a malformed artifact fails loudly
    instead of being massaged into something plausible. `"true"` must not become
    `True` and `"42"` must not become `42` on a path carrying malware observations.

    Caveat that bites: strict mode also refuses `list -> tuple`, so a strict model
    with tuple fields **cannot parse its own JSON**. Collection fields therefore carry
    an explicit `Field(strict=False)`. Scalar strictness is what matters here;
    container-shape coercion is not a correctness risk, and the round-trip test in
    tests/contract/test_roundtrip.py is what surfaced this.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ObservationEvent(StrictWireModel):
    """One redacted observation, as emitted by the detonation harness.

    Redaction happens twice — inside the Frida hook before the value leaves the
    guest, and again here as a validator that REFUSES TO CONSTRUCT if unredacted
    sensitive text is present. Belt and braces: a hook bug must not become a data
    leak, and validation that only warns is validation nobody notices failing.
    """

    type: Literal["observation"] = "observation"
    technique: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    mitre: MitreId
    detail: Annotated[str, StringConstraints(max_length=512)] = ""
    source_hook: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    redacted: Literal[True] = True
    occurred_at: str

    @field_validator("detail")
    @classmethod
    def _reject_unredacted(cls, value: str) -> str:
        from drishti.m3_dynamic.redaction import contains_sensitive_text

        if contains_sensitive_text(value):
            raise ValueError("observation detail contains unredacted sensitive text")
        return value


#: Why a detonation produced no observations. Named rather than inlined so the harness
#: that RAISES these and the wire contract that RECORDS them cannot drift apart — the
#: same one-source-of-truth rule the evidence catalogue and verifier follow.
FailureCode = Literal[
    "containment_failed",
    "snapshot_restore_failed",
    "install_failed",
    "install_unsupported",
    "frida_failed",
    "hook_error",
    "sample_crashed",
    "timeout",
    "cleanup_failed",
    "emulator_unhealthy",
    "internal_error",
]


class FailureRecord(StrictWireModel):
    """Why a run did not produce observations.

    `install_unsupported` is separate from `install_failed` deliberately: v1 scored
    a tooling limitation (API 30 refusing an ancient APK) as sample evasion, which
    inflated its evasion numbers (CARRIED_FINDINGS.md defect 11).
    """

    code: FailureCode
    stage: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    message: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    occurred_at: str


class SnapshotLifecycle(StrictWireModel):
    """Snapshot restore is asserted, not assumed.

    A dirty marker must vanish after restore. v1 proved these semantics rather than
    trusting them, and that check is why cross-sample contamination can be ruled out.
    """

    name: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    before_restore: Literal["passed", "failed", "not_run"]
    after_restore: Literal["passed", "failed", "not_run"]
    package_absent_after: bool = False


class HarnessMetadata(StrictWireModel):
    """What produced an artifact. Every field here is a provenance claim."""

    harness_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    hook_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    emulator_image: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    emulator_serial: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    avd_name: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    sample_kind: Literal["inert_fixture", "benign", "vetted_malware"] = "inert_fixture"
    containment_manifest_sha256: Sha256 | None = None
    containment_verified: bool = False
    containment_verified_at: str | None = None


class ObservationArtifact(StrictWireModel):
    """The ONLY artifact allowed off the detonator.

    `simulated` is pinned to `False` at the type level. v1 shipped a simulated
    behaviour generator alongside the real one; making "simulated" unrepresentable
    on this path means a synthetic observation can never be mistaken for a measured
    one, no matter what a caller passes.
    """

    schema_version: Literal["1.0"] = "1.0"
    sha256: Sha256
    package: str | None = None
    simulated: Literal[False] = False
    outcome: Literal["completed", "inconclusive", "failed", "timeout", "crashed"]
    # strict=False on the collections only — see StrictWireModel's docstring: strict
    # mode refuses list->tuple, which would make this model unable to read its own
    # serialised form.
    observations: tuple[ObservationEvent, ...] = Field(default=(), strict=False)
    failures: tuple[FailureRecord, ...] = Field(default=(), strict=False)
    snapshot: SnapshotLifecycle | None = None
    metadata: HarnessMetadata
    started_at: str
    finished_at: str
    # ── fields the real harness emits (reconciled from 14 rescued artifacts, A8) ──
    # `extra="forbid"` rejected every real artifact until these existed. A contract
    # that cannot read the data it was designed for is the wrong contract.
    #
    #: Wall-clock seconds spent on this sample. Redundant with started_at/finished_at,
    #: but the harness reports it and a reader should not have to recompute it.
    duration_s: float | None = Field(default=None, strict=False)
    #: Free-text harness notes, e.g. "containment:<manifest-id>; hooks completed".
    #: Kept because it carries the containment reference for the run.
    diagnostics: tuple[str, ...] = Field(default=(), strict=False)
    #: Distinct MITRE technique ids seen in this run — a summary of `observations`,
    #: emitted by the harness so a batch report does not have to re-derive it.
    mitre_observed: tuple[str, ...] = Field(default=(), strict=False)

    @property
    def safe_for_ingestion(self) -> bool:
        """True only for a contained run with clean state before and after."""
        return bool(
            self.outcome in {"completed", "inconclusive"}
            and self.package
            and self.metadata.containment_verified
            and self.metadata.containment_manifest_sha256
            and self.snapshot is not None
            and self.snapshot.before_restore == "passed"
            and self.snapshot.after_restore == "passed"
            and self.snapshot.package_absent_after
        )
