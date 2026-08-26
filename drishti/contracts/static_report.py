"""M1 ingest + M2 static analysis contracts.

docs/01_DATA_CONTRACTS.md §2. `FileMeta`, `ThreatIntel` and `PermissionCombo` are
additions made under the §0 rule (add the field to the doc first, then implement) —
they were referenced by the pipeline and the scorer signature without being defined.
See the addendum in 01_DATA_CONTRACTS.md, contract version 1.1.0.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from drishti.contracts.base import AnalyserResult, DrishtiModel


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ComponentKind(StrEnum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class Component(DrishtiModel):
    name: str
    kind: ComponentKind
    exported: bool
    permission: str | None = None
    intent_filters: tuple[str, ...] = ()


class PermissionCombo(DrishtiModel):
    """A matched high-risk permission combination rule.

    Mirrors the `PERMISSION_COMBO` ledger content shape (§1.3). A *combination* is
    the signal, not any single permission: `RECEIVE_SMS` alone is a messaging app,
    while `RECEIVE_SMS + INTERNET + no launcher activity` is an OTP exfil surface.
    """

    rule_id: str
    permissions: tuple[str, ...]
    severity: Severity
    description: str
    mitre: str | None = None


class CertificateInfo(DrishtiModel):
    """Signing certificate facts.

    `self_signed` is informational only — every Android APK is self-signed, so
    treating it as a risk signal produces a 100% false-positive rate. It is here
    because its *absence* would look like an oversight; `brand_mismatch` and
    `known_bad_reuse` are the fields that carry signal.
    """

    sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    age_days: int
    self_signed: bool
    known_bad_reuse: bool = False
    brand_mismatch: bool = False
    brand_claimed: str | None = None
    debug_cert: bool = False


class CallPath(DrishtiModel):
    """A source-to-sink chain through the call graph.

    `reachable_from_lifecycle` is the field that separates "this code exists in the
    APK" from "this code can actually run" — dead library code reaches sinks all the
    time and must not score.
    """

    sink_id: str
    sink_signature: str
    path: tuple[str, ...]
    entrypoint: str
    entrypoint_kind: str
    reachable_from_lifecycle: bool


class DecompiledMethod(DrishtiModel):
    """Bounded source recovered for a method on a dangerous sink path."""

    signature: str
    body: str
    line_start: int = 1
    line_end: int = 1
    call_path_indexes: tuple[int, ...] = ()
    evidence_ref: str
    truncated: bool = False


class HypothesisKind(StrEnum):
    SECONDARY_PAYLOAD = "secondary_payload"
    OTP_EXFIL = "otp_exfil"
    OVERLAY_ATTACK = "overlay_attack"
    ACCESSIBILITY_ABUSE = "accessibility_abuse"
    TARGET_APP_PROBE = "target_app_probe"
    C2_BEACON = "c2_beacon"
    LOGIC_BOMB = "logic_bomb"
    CLIPBOARD_SWAP = "clipboard_swap"


class Hypothesis(DrishtiModel):
    """The static -> dynamic bridge. §2.1.

    This is the object that makes the "closed loop" real rather than rhetorical:
    static analysis decides what to watch, and the sandbox watches exactly that.
    `target_methods` become Frida hooks at runtime; `suggested_probe` becomes a
    morph plan in P5.
    """

    id: str
    kind: HypothesisKind
    statement: str
    target_methods: tuple[str, ...] = ()
    target_apis: tuple[str, ...] = ()
    suggested_probe: dict = Field(default_factory=dict)
    priority: int
    evidence_refs: tuple[str, ...] = ()


class BenignLookalikeVerdict(StrEnum):
    """Outcome of separating a trojan from an app that is legitimately privileged.

    There is deliberately no `BENIGN`. The best available verdict is `INDETERMINATE`,
    matching the rule used everywhere else here that absence of evidence is not
    evidence of innocence. `LEGITIMATE_PRIVILEGED` is a statement about the *signer*,
    not a certification of the code.
    """

    TROJAN_SHAPE = "trojan_shape"
    LEGITIMATE_PRIVILEGED = "legitimate_privileged"
    INDETERMINATE = "indeterminate"


class LookalikeSignal(DrishtiModel):
    """One discriminator, its weight, and why it did or did not fire.

    Absent signals are retained, not dropped. "We looked for a banking roster and found
    none" is a finding a reader needs; silently omitting it would make the assessment
    look like it only ever collects evidence in one direction.
    """

    id: str
    present: bool
    weight: float
    detail: str
    evidence_refs: tuple[str, ...] = ()


class LookalikeAssessment(DrishtiModel):
    """Why this app is, or is not, the trojan its permissions would allow it to be.

    `shared_permissions` is the honest half: the capabilities this sample holds that
    Truecaller, SMS-backup tools and anti-spam apps hold too. Naming them stops the
    report from presenting a dual-use permission as though it were itself the finding.
    """

    verdict: BenignLookalikeVerdict
    trojan_score: float
    signals: tuple[LookalikeSignal, ...] = ()
    shared_permissions: tuple[str, ...] = ()
    targeted_financial_packages: tuple[str, ...] = ()
    publisher_trusted: bool = False
    rationale: str = ""


class ThreatIntel(AnalyserResult):
    """Reputation lookup for one hash. Feeds the scorer's `R` term.

    `R` is a floor-raiser only: a clean result must never *reduce* a score, because
    absence of detections is absence of evidence, not evidence of benignity. A fresh
    zero-day is unknown to every engine.

    `label_derived` is an evaluation-integrity guard. AndroZoo labels are themselves
    derived from VirusTotal counts, so feeding those counts into `R` leaks the label
    and any precision/recall over the composite score becomes circular. See
    docs/CARRIED_FINDINGS.md Part 4.
    """

    sha256: str
    known_bad_hash: bool = False
    detections: int | None = None
    total_engines: int | None = None
    source: str = "none"
    verdict: Literal["confirmed_bad", "suspected_bad", "grey", "unknown"] = "unknown"
    family: str | None = None
    c2_domains: tuple[str, ...] = ()
    label_derived: bool = False


class FileMeta(AnalyserResult):
    """M1 output: what the uploaded file *is*, before any analysis of what it does."""

    sha256: str
    size_bytes: int
    filename: str
    package: str | None = None
    app_label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    is_split: bool = False
    split_names: tuple[str, ...] = ()
    dedupe_hit: bool = False
    intel: ThreatIntel | None = None
    ledger_refs: tuple[str, ...] = ()


class StaticReport(AnalyserResult):
    """M2 output. The input to M5 features, M4 reasoning, and M3 hook selection."""

    sha256: str
    package: str
    app_label: str
    version_name: str
    version_code: int
    min_sdk: int
    target_sdk: int
    permissions: tuple[str, ...] = ()
    permission_combos: tuple[PermissionCombo, ...] = ()
    components: tuple[Component, ...] = ()
    exported_unprotected: tuple[Component, ...] = ()
    deep_link_schemes: tuple[str, ...] = ()
    certificate: CertificateInfo
    declared_not_used: tuple[str, ...] = ()
    used_not_declared: tuple[str, ...] = ()
    native_libs: tuple[str, ...] = ()
    dex_count: int = 1
    entropy_mean: float = 0.0
    packer_hints: tuple[str, ...] = ()
    dcl_indicators: tuple[str, ...] = ()
    reflection_count: int = 0
    urls: tuple[str, ...] = ()
    #: Package-shaped string constants. M2 has always extracted these to derive
    #: hypotheses, but never surfaced them - so any rule looking for a roster of
    #: targeted apps searched a haystack that could not contain one.
    package_strings: tuple[str, ...] = ()
    crypto_constants: tuple[str, ...] = ()
    call_paths: tuple[CallPath, ...] = ()
    decompiled_methods: tuple[DecompiledMethod, ...] = ()
    sink_hits: tuple[str, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    lookalike: LookalikeAssessment | None = None
    ledger_refs: tuple[str, ...] = ()
