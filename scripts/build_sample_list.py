#!/usr/bin/env python3
"""Build the corpus sample list from AndroZoo's `latest.csv` index.

docs/01_DATA_CONTRACTS.md A9,
docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md §5.

**Safe to run on a laptop.** `latest.csv` is a metadata index — sha256, detection counts,
dates, sizes. It carries no APK bytes. Only the *output* of this script is fed to
`corpus_extract.py`, which runs on the GCE extractor VM where the APKs actually land.

    curl -O https://androzoo.uni.lu/static/lists/latest.csv     # ~4GB, metadata only
    python scripts/build_sample_list.py latest.csv data/corpus/samples.csv

The exact corpus size in bytes is printed **before** anything is downloaded, summed from
the index's own `apk_size` column, so the transfer size is measured rather than estimated.

Note from v1: a saved `latest.csv` that is a few KB is an HTTP 404 error page, not the
index. Do not debug it — re-download.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drishti.contracts.corpus import TIME_BANDS
from drishti.m5_ml.sample_list import IndexRow, SelectionReport, select_streaming

OUTPUT_COLUMNS = [
    "sha256",
    "label",
    "split",
    "time_band",
    "dex_date",
    "pkg_name",
    "vt_detection",
    "apk_size",
]


def read_index(path: Path) -> Iterator[IndexRow]:
    """Stream AndroZoo's index. Never materialises it — it is tens of millions of rows."""
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for record in csv.DictReader(handle):
            try:
                yield IndexRow(
                    sha256=(record.get("sha256") or "").strip(),
                    dex_date=(record.get("dex_date") or "").strip(),
                    apk_size=int(float(record.get("apk_size") or 0)),
                    pkg_name=(record.get("pkg_name") or "").strip(),
                    vt_detection=int(float(record.get("vt_detection") or -1)),
                    markets=(record.get("markets") or "").strip(),
                )
            except (TypeError, ValueError):
                # A malformed row is a fact about the index, not a reason to stop.
                continue


def write_report(report: SelectionReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for row in report.rows:
            writer.writerow(row.model_dump())


def summarise(report: SelectionReport, output: Path, seed: int) -> None:
    print(f"\nWrote {len(report.rows):,} samples -> {output}")
    print(f"  seed                     {seed}   (record this in STATUS.md)")
    print(f"  scanned                  {report.scanned:,} index rows")
    print(f"  dropped: implausible date {report.dropped_implausible_date:,}")
    print(f"  dropped: VT grey zone     {report.dropped_grey_zone:,}  (1..9 detections)")
    print(f"  dropped: unlabelled/size  {report.dropped_unlabelled:,}")

    print("\n  composition")
    for band in TIME_BANDS:
        malware = sum(1 for r in report.rows if r.time_band == band and r.label == 1)
        benign = sum(1 for r in report.rows if r.time_band == band and r.label == 0)
        print(f"    {band:<12} malware={malware:<6} benign={benign}")
    empty_splits = []
    for split in ("train", "calib", "test"):
        count = sum(1 for r in report.rows if r.split == split)
        print(f"    {split:<12} {count}")
        if count == 0:
            empty_splits.append(split)

    if empty_splits:
        # PHASE_2 T2.4 calibrates on a held-out third split. An empty calib split does
        # not fail loudly later — it quietly removes the calibration step, and the
        # reliability curve is one of the few things that distinguishes this project
        # from prompting an LLM for a number.
        print(f"\n  WARNING: empty split(s): {', '.join(empty_splits)}")
        print("    An empty 'calib' split means no isotonic calibration and no")
        print("    reliability curve. Widen the date window or adjust CALIB_START/")
        print("    TEST_START in drishti/m5_ml/sample_list.py before downloading.")

    if report.undersupplied_cells:
        print("\n  UNDERSUPPLIED cells (reported, not silently rebalanced):")
        for band, label in sorted(report.undersupplied_cells):
            available = report.undersupplied_cells[(band, label)]
            kind = "malware" if label else "benign"
            print(f"    {band} / {kind}: only {available}")
        print("    A thin 2024-2026 band is the weakness this corpus exists to fix.")
        print("    Backfill from MalwareBazaar rather than rebalancing the other bands.")

    # Measured, never estimated — this is the number that decides whether the download
    # fits the budget, and it is summed from the index rather than guessed.
    print(f"\n  DOWNLOAD SIZE           {report.total_gb:.1f} GB ({report.total_bytes:,} bytes)")
    print("\n  Ordering is stratified: any prefix of this list is balanced across label")
    print("  and time band, so the download can be stopped at any point and still give")
    print("  a valid time split.")
    print("\nNext: copy this file to the extractor VM and run scripts/corpus_extract.py.")
    print("NEVER run the extractor on a personal device.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index_csv", type=Path, help="AndroZoo latest.csv")
    parser.add_argument("output_csv", type=Path, help="sample list to write")
    parser.add_argument("--target", type=int, default=12_000, help="total rows (default 12000)")
    parser.add_argument("--seed", type=int, default=20260817, help="deterministic ordering seed")
    parser.add_argument(
        "--max-apk-mb", type=int, default=60, help="skip larger APKs to bound extraction memory"
    )
    args = parser.parse_args()

    if not args.index_csv.exists():
        print(f"error: {args.index_csv} does not exist", file=sys.stderr)
        return 2
    if args.index_csv.stat().st_size < 1_000_000:
        print(
            f"error: {args.index_csv} is only {args.index_csv.stat().st_size} bytes — "
            "that is an HTTP error page, not the AndroZoo index. Re-download it.",
            file=sys.stderr,
        )
        return 2

    report = select_streaming(
        read_index(args.index_csv),
        target=args.target,
        seed=args.seed,
        max_apk_bytes=args.max_apk_mb * 1_000_000,
    )
    if not report.rows:
        print("No samples matched — check the index and the filters.", file=sys.stderr)
        return 1

    write_report(report, args.output_csv)
    summarise(report, args.output_csv, args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
