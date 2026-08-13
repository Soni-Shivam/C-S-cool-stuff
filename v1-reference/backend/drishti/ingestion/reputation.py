"""Graded threat-intelligence reputation for the M6 score's R term.

WHY THIS EXISTS
    The scoring engine weights reputation at W_R = 0.25, but M1 previously produced only a
    BINARY `intel_hit` against a curated known-bad list. That list ships with 6 entries, so
    in practice R = 0.05 for essentially every sample and 24 of the 25 available reputation
    points were dead. Measured consequence: a real banking trojan
    (us.mobileandroidangryfix.mbankingfixflash, 39/40 VirusTotal detections) scored
    64/100 "Medium" instead of 88/100 "Critical" -- for a bank's fraud desk, the difference
    between monitor and block.

        R = 0.05  ->  0.25*0.05 + 0.50*0.995 + 0.15*0.80 + 0.10*0.10 = 0.64
        R = 1.00  ->  0.25*1.00 + 0.50*0.995 + 0.15*0.80 + 0.10*0.10 = 0.88

    This module maps a multi-engine detection count onto a graded R in [0, 1], which is what
    paper Table 4 describes ("Reputation / threat intel (VT, MalwareBazaar, URLhaus)").

EVALUATION INTEGRITY -- READ BEFORE USING THIS IN A BENCHMARK
    Our AndroZoo ground-truth labels are themselves derived from VirusTotal detection counts
    (malware := vt_detection >= 10). Feeding those same counts into R therefore leaks the
    label into the composite score. Any precision/recall computed over S with R enabled is
    CIRCULAR and must not be reported as a detection result.

    Consequently:
      * ML metrics (paper 9.1) must be computed from M5 features alone -- `drishti.ml.evaluate`
        never sees R, so those numbers stay clean.
      * When scoring a labelled evaluation corpus, pass `allow_label_derived=False` (the
        default) so an offline VT-derived feed is REFUSED and R falls back to unknown.
        Production lookups against a live feed pass `allow_label_derived=True`, because there
        the detection count is genuinely independent evidence about an unknown file.

    A zero detection count is NOT evidence of benignity -- a fresh zero-day is unknown to
    every engine. Unknown therefore maps to a small positive floor, never to 0.0, so a novel
    sample cannot be argued down to Low on reputation grounds.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

#: R for a file no feed has an opinion about. Deliberately non-zero: absence of detections
#: is absence of evidence, and a zero-day must not be discounted.
R_UNKNOWN = 0.05

#: Detection-count thresholds -> R. Graded rather than binary so weak/adware-grey consensus
#: cannot masquerade as confirmed-malicious, and vice versa.
_BANDS: tuple[tuple[int, float], ...] = (
    (25, 1.00),   # overwhelming multi-engine consensus
    (10, 0.90),   # strong consensus; matches the corpus malware threshold
    (5, 0.65),    # meaningful but not decisive
    (1, 0.35),    # single/low detections: often adware or a grey-zone heuristic
)


@dataclass(frozen=True)
class Reputation:
    """What a threat-intel feed knows about one hash."""
    sha256: str
    r: float
    detections: int | None
    source: str
    verdict: Literal["confirmed_bad", "suspected_bad", "grey", "unknown"]
    family: str | None = None

    @property
    def is_confirmed(self) -> bool:
        """True only for overwhelming consensus, which alone may trigger the S=100 override."""
        return self.verdict == "confirmed_bad"

    def describe(self) -> str:
        if self.detections is None:
            return f"no threat-intel record ({self.source}); R={self.r:.2f}"
        return (f"{self.detections} engine detections via {self.source}; "
                f"verdict={self.verdict}; R={self.r:.2f}")


def r_from_detections(detections: int | None) -> tuple[float, str]:
    """Map a detection count onto (R, verdict)."""
    if detections is None or detections < 0:
        return R_UNKNOWN, "unknown"
    for threshold, value in _BANDS:
        if detections >= threshold:
            if value >= 1.00:
                return value, "confirmed_bad"
            if value >= 0.65:
                return value, "suspected_bad"
            return value, "grey"
    return R_UNKNOWN, "unknown"


class ReputationFeed:
    """A hash -> detection-count feed.

    `label_derived` marks a feed whose counts also produced our ground-truth labels. Such a
    feed is refused during labelled evaluation to keep the composite score honest.
    """

    def __init__(self, records: dict[str, dict], *, source: str, label_derived: bool):
        self._records = records
        self.source = source
        self.label_derived = label_derived

    def __len__(self) -> int:
        return len(self._records)

    @classmethod
    def from_sample_list(cls, path: str | Path, *, source: str = "androzoo-vt-offline"):
        """Load counts from a `samples.csv`-style list (sha256, vt_detection[, pkg_name]).

        This feed IS label-derived: the same vt_detection column defines our labels.
        """
        records: dict[str, dict] = {}
        with open(path, newline="") as handle:
            for row in csv.DictReader(handle):
                sha = (row.get("sha256") or "").strip().lower()
                if not sha:
                    continue
                try:
                    detections = int(row["vt_detection"])
                except (KeyError, TypeError, ValueError):
                    continue
                records[sha] = {"detections": detections,
                                "family": (row.get("pkg_name") or None)}
        return cls(records, source=source, label_derived=True)

    @classmethod
    def from_bazaar_provenance(cls, path: str | Path, *, source: str = "malwarebazaar"):
        """Load a MalwareBazaar provenance manifest, which carries real family labels.

        Not label-derived: family attribution is independent of our vt_detection labels.
        """
        import json
        payload = json.loads(Path(path).read_text())
        records = {}
        for entry in payload.get("samples", []):
            sha = (entry.get("sha256") or "").strip().lower()
            if sha:
                # Presence in a curated family feed is itself strong consensus.
                records[sha] = {"detections": 25, "family": entry.get("family")}
        return cls(records, source=source, label_derived=False)

    def lookup(self, sha256: str, *, allow_label_derived: bool = False) -> Reputation:
        sha = sha256.strip().lower()
        if self.label_derived and not allow_label_derived:
            # Refuse rather than silently leak the label into the score.
            return Reputation(sha, R_UNKNOWN, None,
                              f"{self.source} (suppressed: label-derived)", "unknown")
        record = self._records.get(sha)
        if record is None:
            return Reputation(sha, R_UNKNOWN, None, self.source, "unknown")
        r, verdict = r_from_detections(record["detections"])
        return Reputation(sha, r, record["detections"], self.source, verdict,
                          family=record.get("family"))


def unknown(sha256: str, source: str = "none") -> Reputation:
    return Reputation(sha256.strip().lower(), R_UNKNOWN, None, source, "unknown")
