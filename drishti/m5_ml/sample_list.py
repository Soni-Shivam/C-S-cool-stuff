"""Build a balanced, time-split, stratified corpus sample list from AndroZoo's index.

docs/01_DATA_CONTRACTS.md A9,
docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md §5.

**This module is laptop-safe.** AndroZoo's `latest.csv` is a metadata index — hashes,
detection counts, dates, sizes. It contains no APK bytes. Only the *output* of this
module is fed to the extractor, and that runs on the GCE VM.

The one non-obvious design choice is that the **download order** is stratified, not just
the extraction order. See `stratify`.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date

from drishti.contracts.corpus import MALWARE_MIN_VT, TIME_BANDS, CorpusSample, Split

#: Below this, `dex_date` is overwhelmingly the ZIP-epoch fallback rather than a real
#: build date. Android 1.0 shipped 2008-09-23.
MIN_PLAUSIBLE_DATE = date(2008, 9, 23)

#: Upper edge of the plausibility window. Anything later is impossible and signals a
#: corrupt timestamp — v1's index carried rows dated 2039, 2081, 2092 and 2107.
MAX_PLAUSIBLE_DATE = date(2026, 12, 31)

#: Band upper edges, inclusive. Parallel to `TIME_BANDS`.
_BAND_EDGES: tuple[tuple[str, date], ...] = (
    ("<=2017", date(2017, 12, 31)),
    ("2018-2020", date(2020, 12, 31)),
    ("2021-2023", date(2023, 12, 31)),
)

#: Split boundaries on `dex_date`. Train is everything older; calib is the year before
#: test. Three-way because calibrating on the test split is a leak (PHASE_2 T2.4).
CALIB_START = date(2024, 1, 1)
TEST_START = date(2025, 1, 1)


@dataclass(frozen=True)
class IndexRow:
    """One raw row of AndroZoo's `latest.csv`, before filtering or labelling."""

    sha256: str
    dex_date: str
    apk_size: int
    pkg_name: str
    vt_detection: int
    markets: str


@dataclass
class SelectionReport:
    """The list, plus everything a reader needs to judge whether it is any good.

    Counts are reported rather than logged because corpus composition is a claim the
    report and the slides both make, and `CLAUDE.md` requires those to trace to a
    measurement.
    """

    rows: list[CorpusSample] = field(default_factory=list)
    scanned: int = 0
    dropped_implausible_date: int = 0
    dropped_grey_zone: int = 0
    dropped_unlabelled: int = 0
    #: `(time_band, label) -> count`, for any cell that could not meet its share.
    undersupplied_cells: dict[tuple[str, int], int] = field(default_factory=dict)
    total_bytes: int = 0

    @property
    def total_gb(self) -> float:
        return self.total_bytes / 1_000_000_000


def parse_date(value: str) -> date | None:
    """AndroZoo dates arrive as `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`. None if unusable."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text.split(" ")[0])
    except ValueError:
        return None


def is_plausible(value: str) -> bool:
    """Inside the plausibility window.

    Without this the time split silently stops meaning what it claims: the ZIP-epoch
    fallback (1980/81) all lands in train and corrupt futures (2039+) all land in test.
    """
    parsed = parse_date(value)
    return parsed is not None and MIN_PLAUSIBLE_DATE <= parsed <= MAX_PLAUSIBLE_DATE


def band_for(dex_date: str) -> str:
    """Which of the four time bands this date falls in."""
    parsed = parse_date(dex_date)
    if parsed is None:
        raise ValueError(f"unparseable dex_date: {dex_date!r}")
    for name, upper in _BAND_EDGES:
        if parsed <= upper:
            return name
    return TIME_BANDS[-1]


def split_for(dex_date: str) -> Split:
    """Time-ordered three-way split.

    A random split would flatter the model. Testing on strictly newer samples measures
    generalisation to unseen families, which is the number worth defending.
    """
    parsed = parse_date(dex_date)
    if parsed is None:
        raise ValueError(f"unparseable dex_date: {dex_date!r}")
    if parsed >= TEST_START:
        return "test"
    if parsed >= CALIB_START:
        return "calib"
    return "train"


def label_for(row: IndexRow) -> int | None:
    """1 malware, 0 benign, None to discard.

    Conservative on both sides. Malware needs strong multi-engine consensus. Benign needs
    zero detections **and** a Play listing — zero detections alone is not evidence of
    benignity, it is often just obscurity. Everything between is an adware grey zone and
    is discarded rather than guessed at, because training on it is training on noise.
    """
    if row.vt_detection >= MALWARE_MIN_VT:
        return 1
    if row.vt_detection == 0 and "play.google.com" in (row.markets or "").lower():
        return 0
    return None


def stratify(rows: list[CorpusSample], *, seed: int) -> list[CorpusSample]:
    """Order rows round-robin across `(time_band, label)` cells.

    **Any prefix of the result is itself balanced across label and time band.** That is
    what makes a metered, multi-hour download interruptible: stop it at any row count and
    the corpus is still balanced and still spans the full time range, so the time split
    remains valid. Bucket order would give thousands of malware rows and no test set —
    and you would only find out after paying for the transfer.

    Deterministic for a given seed, so a corpus build is reproducible and auditable.
    """
    rng = random.Random(seed)
    cells: dict[tuple[str, int], list[CorpusSample]] = defaultdict(list)
    for row in rows:
        cells[(row.time_band, row.label)].append(row)
    for bucket in cells.values():
        rng.shuffle(bucket)

    # Sorted so cell order does not depend on dict insertion order, which would depend on
    # the order the index happened to be read in.
    order = sorted(cells)
    out: list[CorpusSample] = []
    while any(cells[key] for key in order):
        for key in order:
            if cells[key]:
                out.append(cells[key].pop())
    return out


def select_streaming(
    index_rows: Iterable[IndexRow],
    *,
    target: int,
    seed: int,
    max_apk_bytes: int = 60_000_000,
) -> SelectionReport:
    """Same selection as `build_sample_list`, over an iterator, in bounded memory.

    AndroZoo's index is tens of millions of rows, so the CLI cannot materialise it. Each
    `(time_band, label)` cell keeps a **reservoir** of its target size: every qualifying
    row gets an equal chance of ending up in the corpus regardless of where it appeared
    in the file, using memory proportional to `target` rather than to the index.

    Taking the first N per cell instead would silently inherit whatever order AndroZoo
    happens to write, which is not a property anyone has checked.
    """
    rng = random.Random(seed)
    per_cell = max(1, target // (len(TIME_BANDS) * 2))
    reservoirs: dict[tuple[str, int], list[CorpusSample]] = defaultdict(list)
    seen_per_cell: dict[tuple[str, int], int] = defaultdict(int)
    report = SelectionReport()

    for row in index_rows:
        report.scanned += 1
        sample = _to_sample(row, report, max_apk_bytes=max_apk_bytes)
        if sample is None:
            continue

        key = (sample.time_band, sample.label)
        seen_per_cell[key] += 1
        bucket = reservoirs[key]
        if len(bucket) < per_cell:
            bucket.append(sample)
        else:
            # Classic reservoir: replace with probability per_cell / seen.
            index = rng.randrange(seen_per_cell[key])
            if index < per_cell:
                bucket[index] = sample

    for band in TIME_BANDS:
        for label in (0, 1):
            available = len(reservoirs[(band, label)])
            if available < per_cell:
                report.undersupplied_cells[(band, label)] = available

    pooled = [s for bucket in reservoirs.values() for s in bucket]
    report.rows = stratify(pooled, seed=seed)[:target]
    report.total_bytes = sum(r.apk_size for r in report.rows)
    return report


def _to_sample(
    row: IndexRow, report: SelectionReport, *, max_apk_bytes: int
) -> CorpusSample | None:
    """Filter and label one row, recording why it was dropped. None means discard."""
    if not is_plausible(row.dex_date):
        report.dropped_implausible_date += 1
        return None
    if not (0 < row.apk_size <= max_apk_bytes):
        report.dropped_unlabelled += 1
        return None
    label = label_for(row)
    if label is None:
        if 0 < row.vt_detection < MALWARE_MIN_VT:
            report.dropped_grey_zone += 1
        else:
            report.dropped_unlabelled += 1
        return None

    parsed = parse_date(row.dex_date)
    return CorpusSample(
        sha256=row.sha256,
        label=label,
        split=split_for(row.dex_date),
        time_band=band_for(row.dex_date),
        dex_date=parsed.isoformat() if parsed else "",
        pkg_name=row.pkg_name or "",
        vt_detection=row.vt_detection,
        apk_size=row.apk_size,
    )


def build_sample_list(
    index_rows: list[IndexRow],
    *,
    target: int,
    seed: int,
    max_apk_bytes: int = 60_000_000,
) -> SelectionReport:
    """Filter, label, band, split, stratify — and report what was thrown away.

    `target` caps the total row count. Cells that cannot meet their equal share are
    recorded in `undersupplied_cells` rather than quietly compensated for by the others:
    a thin 2024-2026 band is the specific weakness this corpus exists to fix, and hiding
    it would defeat the purpose.
    """
    report = SelectionReport(scanned=len(index_rows))
    selected: list[CorpusSample] = []

    for row in index_rows:
        sample = _to_sample(row, report, max_apk_bytes=max_apk_bytes)
        if sample is not None:
            selected.append(sample)

    per_cell_target = max(1, target // (len(TIME_BANDS) * 2))
    supply: dict[tuple[str, int], int] = defaultdict(int)
    for sample in selected:
        supply[(sample.time_band, sample.label)] += 1
    for band in TIME_BANDS:
        for label in (0, 1):
            available = supply[(band, label)]
            if available < per_cell_target:
                report.undersupplied_cells[(band, label)] = available

    ordered = stratify(selected, seed=seed)[:target]
    report.rows = ordered
    report.total_bytes = sum(r.apk_size for r in ordered)
    return report
