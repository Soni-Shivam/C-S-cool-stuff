"""Corpus sample-list construction: filtering, splitting, and stratified ordering.

docs/01_DATA_CONTRACTS.md A9,
docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md §5.

The property that matters is `test_any_prefix_is_balanced`. A metered, multi-hour
download has to be interruptible: stopped at any row count it must still yield a
balanced, time-spanning corpus. Bucket order gives thousands of malware rows and no test
set, and you only discover that after the transfer.
"""

from __future__ import annotations

from collections import Counter

import pytest

from drishti.contracts.corpus import TIME_BANDS
from drishti.m5_ml.sample_list import (
    IndexRow,
    SelectionReport,
    band_for,
    build_sample_list,
    label_for,
    select_streaming,
    split_for,
    stratify,
)


def _row(sha_seed: int, *, date: str, vt: int, markets: str = "play.google.com") -> IndexRow:
    return IndexRow(
        sha256=f"{sha_seed:064x}",
        dex_date=date,
        apk_size=1_000_000,
        pkg_name=f"com.example.app{sha_seed}",
        vt_detection=vt,
        markets=markets,
    )


# ── labelling ────────────────────────────────────────────────────────────────
def test_label_requires_strong_consensus_for_malware() -> None:
    assert label_for(_row(1, date="2022-01-01", vt=10)) == 1
    assert label_for(_row(2, date="2022-01-01", vt=50)) == 1


def test_benign_requires_zero_detections_and_a_play_store_listing() -> None:
    assert label_for(_row(3, date="2022-01-01", vt=0)) == 0
    # Zero detections but not from Play: not evidence of benignity.
    assert label_for(_row(4, date="2022-01-01", vt=0, markets="appchina")) is None


def test_the_grey_zone_is_discarded() -> None:
    """1..9 detections is adware ambiguity. Training on it is training on label noise."""
    for vt in range(1, 10):
        assert label_for(_row(5, date="2022-01-01", vt=vt)) is None


# ── date plausibility ────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad_date", ["1980-01-01", "1981-06-02", "2039-01-01", "2107-11-30"])
def test_implausible_dex_dates_are_rejected(bad_date: str) -> None:
    """The ZIP-epoch fallback and corrupt futures both parse cleanly as dates.

    Unfiltered, every 1980/81 row lands in train and every far-future row lands in test,
    so the split stops measuring generalisation. In one 6,000-sample v1 build this
    affected 1,235 rows — 20.6%.
    """
    report = build_sample_list(
        [_row(i, date=bad_date, vt=20) for i in range(10)],
        target=10,
        seed=1,
    )
    assert report.rows == []
    assert report.dropped_implausible_date == 10


def test_plausible_dates_survive() -> None:
    report = build_sample_list(
        [_row(i, date="2022-05-01", vt=20) for i in range(4)], target=8, seed=1
    )
    assert report.dropped_implausible_date == 0
    assert len(report.rows) == 4


# ── banding and splitting ────────────────────────────────────────────────────
def test_band_boundaries() -> None:
    assert band_for("2015-01-01") == "<=2017"
    assert band_for("2017-12-31") == "<=2017"
    assert band_for("2018-01-01") == "2018-2020"
    assert band_for("2020-12-31") == "2018-2020"
    assert band_for("2021-01-01") == "2021-2023"
    assert band_for("2023-12-31") == "2021-2023"
    assert band_for("2024-01-01") == "2024-2026"


def test_split_is_three_way_and_time_ordered() -> None:
    """Calibration gets its own split. Calibrating on test is a leak."""
    assert split_for("2015-01-01") == "train"
    assert split_for("2022-01-01") == "train"
    assert split_for("2024-06-01") == "calib"
    assert split_for("2025-06-01") == "test"


def test_every_split_is_reachable() -> None:
    got = {split_for(d) for d in ("2015-01-01", "2024-06-01", "2025-09-01")}
    assert got == {"train", "calib", "test"}


# ── the property this design exists for ──────────────────────────────────────
def _balanced_supply(per_cell: int) -> list[IndexRow]:
    """Equal supply in every (band, label) cell."""
    dates = {
        "<=2017": "2016-03-01",
        "2018-2020": "2019-07-01",
        "2021-2023": "2022-02-01",
        "2024-2026": "2025-04-01",
    }
    rows: list[IndexRow] = []
    seed = 0
    for band in TIME_BANDS:
        for vt in (0, 20):
            for _ in range(per_cell):
                seed += 1
                rows.append(_row(seed, date=dates[band], vt=vt))
    return rows


def _balanced_samples(per_cell: int, *, seed: int = 0) -> list:
    """`_balanced_supply` put through the real pipeline, so tests use real CorpusSamples."""
    supply = _balanced_supply(per_cell)
    return build_sample_list(supply, target=len(supply), seed=seed).rows


def test_any_prefix_is_balanced() -> None:
    """Stop the download at any row count and the corpus is still usable.

    This is the whole argument for stratifying the DOWNLOAD order rather than only the
    extraction order.
    """
    per_cell = 50
    ordered = _balanced_samples(per_cell, seed=42)
    cell_count = len(TIME_BANDS) * 2
    assert len(ordered) == per_cell * cell_count

    for prefix_len in range(cell_count, len(ordered) + 1):
        prefix = ordered[:prefix_len]

        labels = Counter(r.label for r in prefix)
        assert abs(labels[0] - labels[1]) <= cell_count // 2, (
            f"label imbalance {dict(labels)} at prefix {prefix_len}"
        )

        bands = Counter(r.time_band for r in prefix)
        assert set(bands) <= set(TIME_BANDS)
        # Every band must appear once the prefix is at least one full round.
        assert len(bands) == len(TIME_BANDS), f"band {set(TIME_BANDS) - set(bands)} missing"
        assert max(bands.values()) - min(bands.values()) <= 2, (
            f"band imbalance {dict(bands)} at prefix {prefix_len}"
        )


def test_stratify_is_deterministic_for_a_seed() -> None:
    samples = _balanced_samples(20)
    first = [r.sha256 for r in stratify(samples, seed=7)]
    second = [r.sha256 for r in stratify(samples, seed=7)]
    assert first == second
    other = [r.sha256 for r in stratify(samples, seed=8)]
    assert first != other, "a different seed must give a different order"


def test_stratify_emits_every_row_exactly_once() -> None:
    samples = _balanced_samples(13)
    ordered = stratify(samples, seed=3)
    assert Counter(r.sha256 for r in ordered) == Counter(r.sha256 for r in samples)


def test_an_undersupplied_cell_is_reported_not_hidden() -> None:
    """A thin 2024-26 band is the specific weakness this corpus exists to fix.

    Silently rebalancing the other bands to compensate would hide it.
    """
    supply = _balanced_supply(30)
    # Strip the recent malware cell down to almost nothing.
    thin = [
        r for r in supply if not (band_for(r.dex_date) == "2024-2026" and r.vt_detection >= 10)
    ][:]
    thin += [r for r in supply if band_for(r.dex_date) == "2024-2026" and r.vt_detection >= 10][:2]

    report = build_sample_list(thin, target=len(supply), seed=5)
    assert ("2024-2026", 1) in report.undersupplied_cells
    assert report.undersupplied_cells[("2024-2026", 1)] == 2


# ── size is measured, never estimated ────────────────────────────────────────
def test_total_bytes_is_summed_from_the_index() -> None:
    rows = [_row(i, date="2022-01-01", vt=20) for i in range(7)]
    report = build_sample_list(rows, target=7, seed=1)
    assert report.total_bytes == 7 * 1_000_000
    assert isinstance(report, SelectionReport)


def test_target_caps_the_selection() -> None:
    report = build_sample_list(_balanced_supply(40), target=16, seed=1)
    assert len(report.rows) == 16


# ── streaming selection (what the CLI actually uses) ─────────────────────────
def test_streaming_selection_matches_the_in_memory_filters() -> None:
    supply = _balanced_supply(20)
    streamed = select_streaming(iter(supply), target=len(supply), seed=11)
    in_memory = build_sample_list(supply, target=len(supply), seed=11)
    assert streamed.scanned == in_memory.scanned == len(supply)
    assert len(streamed.rows) == len(in_memory.rows)
    assert {r.sha256 for r in streamed.rows} == {r.sha256 for r in in_memory.rows}


def test_streaming_holds_only_the_reservoir_not_the_index() -> None:
    """Memory is proportional to `target`, not to the size of AndroZoo's index."""
    big = _balanced_supply(500)  # 4000 qualifying rows
    report = select_streaming(iter(big), target=80, seed=2)
    assert report.scanned == 4000
    assert len(report.rows) == 80


def test_streaming_prefix_is_balanced_too() -> None:
    report = select_streaming(iter(_balanced_supply(40)), target=160, seed=9)
    cell_count = len(TIME_BANDS) * 2
    for prefix_len in range(cell_count, len(report.rows) + 1):
        bands = Counter(r.time_band for r in report.rows[:prefix_len])
        assert len(bands) == len(TIME_BANDS)
        assert max(bands.values()) - min(bands.values()) <= 2
