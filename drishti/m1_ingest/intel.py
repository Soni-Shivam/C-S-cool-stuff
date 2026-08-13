"""Threat-intel fast pass. An accelerator, never the sole verdict.

docs/PHASE_0_FOUNDATIONS.md T0.10, and ADAPTed from v1's `ingestion/reputation.py`
(docs/SALVAGE.md) — v1's graded bands are strictly better than the binary hit the v2
spec sketched, and they exist because of a measurement:

> `R` was `1.0 if intel_hit else 0.05` against a **6-entry** known-bad list, so 24 of
> the 25 reputation points were dead and a 39/40-detection banking trojan scored
> **64/100 "Medium"** instead of **88/100 "Critical"** — for a fraud desk, the
> difference between monitor and block.

Two rules that are easy to get wrong and expensive to get wrong:

**A clean result must never lower a score.** `R` is a floor-raiser only. Absence of
detections is absence of evidence — a fresh zero-day is unknown to every engine — so
"unknown" maps to a small positive floor, never to zero.

**A label-derived feed is refused by default.** AndroZoo's malware labels *are*
VirusTotal detection counts, so feeding those same counts into `R` leaks the label and
makes any precision/recall over the composite score circular. Production lookups
against a live feed pass `allow_label_derived=True`, because there the count is
genuinely independent evidence about an unknown file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol

from drishti.contracts.static_report import ThreatIntel

#: R for a file no feed has an opinion about. Deliberately non-zero.
R_UNKNOWN = 0.05

#: Detection-count thresholds -> R, highest first. Graded rather than binary so a
#: weak/adware-grey consensus cannot masquerade as confirmed-malicious, or vice versa.
BANDS: tuple[tuple[int, float, str], ...] = (
    (25, 1.00, "confirmed_bad"),  # overwhelming multi-engine consensus
    (10, 0.90, "confirmed_bad"),  # strong consensus; matches the corpus threshold
    (5, 0.65, "suspected_bad"),  # meaningful but not decisive
    (1, 0.35, "grey"),  # single/low detections: often adware or heuristics
)

Verdict = Literal["confirmed_bad", "suspected_bad", "grey", "unknown"]


def band_for(detections: int) -> tuple[float, Verdict]:
    """Map a detection count onto (R, verdict)."""
    for threshold, r, verdict in BANDS:
        if detections >= threshold:
            return r, verdict  # type: ignore[return-value]
    return R_UNKNOWN, "unknown"


class ReputationFeed(Protocol):
    """A source of detection counts for a hash."""

    #: True when this feed's numbers are the same numbers our labels came from.
    label_derived: bool
    name: str

    def lookup(self, sha256: str) -> int | None: ...


def load_known_bad(path: Path) -> dict[str, str]:
    """Load the curated `sha256,family` list.

    This is the only feed permitted to trigger the `S=100` override, because it is an
    exact hash match on a file someone deliberately curated — not a threshold on a
    third party's score.
    """
    feed: dict[str, str] = {}
    if not path.exists():
        return feed
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "," not in line:
            continue
        sha, family = line.split(",", 1)
        feed[sha.strip().lower()] = family.strip()
    return feed


def lookup(
    sha256: str,
    *,
    known_bad: dict[str, str] | None = None,
    feed: ReputationFeed | None = None,
    allow_label_derived: bool = False,
) -> ThreatIntel:
    """Resolve reputation for one hash into a `ThreatIntel`.

    Always returns a result. "No feed knew this file" is itself a finding a reviewer
    needs, and a downstream claim must be able to cite it — so the caller writes a
    `THREAT_INTEL` node either way.
    """
    digest = sha256.lower()
    family = (known_bad or {}).get(digest)
    if family is not None:
        return ThreatIntel(
            sha256=digest,
            known_bad_hash=True,
            source="known_bad_list",
            verdict="confirmed_bad",
            family=family,
        )

    if feed is None:
        return ThreatIntel(sha256=digest, source="none", verdict="unknown")

    if feed.label_derived and not allow_label_derived:
        # Refused, and the refusal is recorded rather than silently treated as unknown:
        # a reader must be able to tell "no feed had an opinion" from "we declined to
        # use the opinion because it would make the benchmark circular".
        return ThreatIntel(
            sha256=digest,
            source=feed.name,
            verdict="unknown",
            label_derived=True,
            partial=True,
            errors=(
                f"reputation feed {feed.name!r} is label-derived and was refused; "
                "using it would make composite-score metrics circular",
            ),
        )

    detections = feed.lookup(digest)
    if detections is None:
        return ThreatIntel(sha256=digest, source=feed.name, verdict="unknown")

    _r, verdict = band_for(detections)
    return ThreatIntel(
        sha256=digest,
        detections=detections,
        source=feed.name,
        verdict=verdict,
        label_derived=feed.label_derived,
    )


def r_term(intel: ThreatIntel | None) -> float:
    """The scorer's `R` input. Floor-raiser only — never returns 0.

    Kept here beside the bands so the mapping cannot drift from the verdicts, but note
    the scorer itself stays pure: this is a lookup, not I/O.
    """
    if intel is None:
        return R_UNKNOWN
    if intel.known_bad_hash:
        return 1.0
    if intel.detections is None:
        return R_UNKNOWN
    r, _verdict = band_for(intel.detections)
    return r
