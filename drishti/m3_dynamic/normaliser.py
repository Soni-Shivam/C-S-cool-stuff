"""Raw Frida hook output -> the DynamicTrace contract, aggregated before it lands.

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.6, CLAUDE.md rule 11.

**Aggregation is not tidiness, it is a hard requirement.** One real sample in v1 called
`Cipher.doFinal` 1,925 times in 103 seconds. Appending a node per event would have put
1,925 near-identical nodes in the ledger — against a 50-400 sanity band — and blown the
12k-token prompt budget on its own.

So events are grouped by `(technique, mitre, hook)` with an occurrence count, capped at
`MAX_OBSERVATION_GROUPS`. The rule that makes this safe is that **`b_dynamic` must be
unchanged by aggregation**: the behavioural signal keys on which *distinct* techniques
were observed and how severe they are, never on how many times each fired. A sample that
encrypts once and a sample that encrypts 1,925 times are doing the same thing.

Counts are retained because they are genuinely interesting to a human reader — 1,925
crypto operations in 103 seconds is 18.6/second, and that rate is a finding — they just
must not move a score.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from drishti.contracts.static_report import Severity
from drishti.logging import get_logger

log = get_logger(__name__)

#: Hard cap on grouped observations reaching the ledger or a prompt.
MAX_OBSERVATION_GROUPS = 40

#: Severity per technique, used to derive the dynamic behavioural signal. Ordered by
#: what the capability lets an attacker actually do to a victim.
TECHNIQUE_SEVERITY: dict[str, Severity] = {
    "T1407": Severity.CRITICAL,  # runtime code loading
    "T1417": Severity.CRITICAL,  # input injection / accessibility
    "T1582": Severity.CRITICAL,  # SMS control
    "T1636": Severity.HIGH,  # protected user data
    "T1412": Severity.HIGH,  # SMS capture
    "T1414": Severity.HIGH,  # clipboard
    "T1513": Severity.HIGH,  # screen capture
    "T1623": Severity.HIGH,  # command execution
    "T1626": Severity.HIGH,  # elevation abuse
    "T1628": Severity.MEDIUM,  # hide artifacts
    "T1521": Severity.MEDIUM,  # encrypted channel
    "T1437": Severity.MEDIUM,  # C2 over app-layer protocol
    "T1095": Severity.MEDIUM,  # non-application-layer C2
    "T1426": Severity.MEDIUM,  # system information discovery
    "T1430": Severity.MEDIUM,  # location
    "T1418": Severity.MEDIUM,  # software discovery
    "T1406": Severity.MEDIUM,  # obfuscation
    "T1429": Severity.MEDIUM,  # audio capture
}

_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 0.85,
    Severity.HIGH: 0.65,
    Severity.MEDIUM: 0.40,
    Severity.LOW: 0.15,
}


@dataclass(frozen=True)
class ObservationGroup:
    """Distinct observed behaviour, with how often it fired."""

    technique: str
    mitre: str
    hook: str
    occurrences: int
    first_detail: str = ""

    @property
    def severity(self) -> Severity:
        return TECHNIQUE_SEVERITY.get(self.mitre, Severity.LOW)


@dataclass
class NormalisedTrace:
    """What the pipeline consumes after a detonation."""

    groups: tuple[ObservationGroup, ...] = ()
    total_events: int = 0
    dropped_groups: int = 0
    techniques: tuple[str, ...] = ()
    b_dynamic: float = 0.0
    errors: tuple[str, ...] = field(default_factory=tuple)


def _key(event: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(event.get("technique") or "unknown"),
        str(event.get("mitre") or ""),
        str(event.get("source_hook") or event.get("hook") or "unknown"),
    )


def aggregate(events: list[dict[str, Any]]) -> NormalisedTrace:
    """Group raw hook events, cap them, and derive the dynamic behavioural signal.

    Groups are ordered by severity then occurrence count, so if the cap drops anything
    it drops the least interesting observations rather than an arbitrary tail.
    """
    if not events:
        return NormalisedTrace()

    counts: Counter[tuple[str, str, str]] = Counter()
    details: dict[tuple[str, str, str], str] = {}
    for event in events:
        key = _key(event)
        counts[key] += 1
        if key not in details:
            details[key] = str(event.get("detail") or "")[:512]

    groups = [
        ObservationGroup(
            technique=technique,
            mitre=mitre,
            hook=hook,
            occurrences=count,
            first_detail=details[(technique, mitre, hook)],
        )
        for (technique, mitre, hook), count in counts.items()
    ]
    groups.sort(key=lambda g: (-_SEVERITY_WEIGHT[g.severity], -g.occurrences, g.technique))

    dropped = max(0, len(groups) - MAX_OBSERVATION_GROUPS)
    kept = tuple(groups[:MAX_OBSERVATION_GROUPS])
    if dropped:
        log.warning("observation_groups_capped", dropped=dropped, cap=MAX_OBSERVATION_GROUPS)

    errors: tuple[str, ...] = ()
    if dropped:
        errors = (f"{dropped} observation group(s) dropped at the {MAX_OBSERVATION_GROUPS} cap",)

    return NormalisedTrace(
        groups=kept,
        total_events=len(events),
        dropped_groups=dropped,
        techniques=tuple(sorted({g.mitre for g in kept if g.mitre})),
        b_dynamic=behavioural_signal(kept),
        errors=errors,
    )


def behavioural_signal(groups: tuple[ObservationGroup, ...]) -> float:
    """Dynamic behavioural signal in [0,1] from DISTINCT observed techniques.

    Keys on distinct technique severities and never on occurrence counts. That is what
    makes aggregation safe: grouping 1,925 events into one group must not change this
    number, because a sample that encrypts once and one that encrypts 1,925 times are
    doing the same thing. Fusion is noisy-OR for the same reason it is elsewhere —
    three correlated observations should read as strong, not as 2.1 clipped to 1.0.
    """
    severities = {g.mitre: g.severity for g in groups if g.mitre}
    if not severities:
        return 0.0
    complement = 1.0
    for severity in severities.values():
        complement *= 1.0 - _SEVERITY_WEIGHT[severity]
    return round(1.0 - complement, 6)
