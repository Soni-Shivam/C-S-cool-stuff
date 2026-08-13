#!/usr/bin/env python3
"""Isolated AndroZoo -> features extractor (parallel).

RUN THIS IN AN ISOLATED, DISPOSABLE ENVIRONMENT (throwaway cloud VM, container,
or Databricks) — NOT on a personal device. It downloads APKs (which may be live
malware), extracts *static* features only (never executes them), writes a numeric
features CSV, and DELETES each APK immediately after extraction. Only the resulting
CSV should ever leave the isolated environment; feed it to
`drishti.ml.train.train_from_dataframe`.

Input CSV:  columns `sha256,label` (label: 1 = malware, 0 = benign); optional `split`
Output CSV: FEATURE_NAMES columns + `sha256,label,split`

WHY PARALLEL
    The original implementation was strictly serial: one download then one parse. At the
    measured ~8-15 s per sample that is 13-25 hours for a 6000-sample corpus, which does
    not fit a submission deadline. Work is dispatched to a PROCESS pool rather than a
    thread pool because Androguard parsing is CPU-bound Python and would otherwise
    serialise on the GIL; downloads are I/O-bound, so a worker count above the core count
    is normal. Androguard peaks around 400-500 MB per mid-size APK, so budget roughly
    0.5 GB of RAM per worker.

    Be a good citizen: AndroZoo is a shared academic service and rate-limits per API key.
    Start at --workers 16 and only raise it if you see no HTTP 429/503.

Usage:
    ANDROZOO_API_KEY=... python scripts/androzoo_extract.py samples.csv features.csv \\
        --workers 16
"""
from __future__ import annotations

import argparse
import csv
import os
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ProcessPoolExecutor, as_completed

import pandas as pd

from drishti.ml.features import FEATURE_NAMES, extract_features
from drishti.static.androguard_adapter import parse_apk

ANDROZOO_URL = "https://androzoo.uni.lu/api/download"
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def download_apk(sha256: str, api_key: str, dest: str, *, attempts: int = 3,
                 timeout: int = 180) -> None:
    """Download one APK, retrying transient AndroZoo/network failures with backoff."""
    url = f"{ANDROZOO_URL}?apikey={api_key}&sha256={sha256}"
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "DRISHTI-research/1.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                with open(dest, "wb") as handle:
                    while chunk := response.read(1 << 20):
                        handle.write(chunk)
            return
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in RETRYABLE_STATUS:
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
        # Exponential backoff so a rate-limited key recovers instead of hammering.
        time.sleep(2 ** attempt + 0.5 * attempt)
    raise last if last else RuntimeError("download failed")


def extract_one(task: tuple[str, int, str, str]) -> dict | None:
    """Worker entry point: download -> static parse -> features -> delete APK.

    Runs in a child process. The APK lives only inside a TemporaryDirectory and is
    removed before this returns, on success or failure. The APK is never executed.
    """
    sha256, label, split, api_key = task
    # Children must not inherit the parent's SIGINT handler, or Ctrl-C produces noise.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    with tempfile.TemporaryDirectory() as tmp:
        apk_path = os.path.join(tmp, f"{sha256}.apk")
        try:
            download_apk(sha256, api_key, apk_path)
            parsed = parse_apk(apk_path)
            feats = extract_features(parsed)
        except Exception as exc:  # noqa: BLE001 - one bad sample must not stop the batch
            return {"__error__": f"{type(exc).__name__}: {exc}"[:200], "sha256": sha256}
        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)
    feats["sha256"] = sha256
    feats["label"] = int(label)
    feats["split"] = split
    return feats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input_csv", help="CSV with columns sha256,label[,split]")
    ap.add_argument("output_csv", help="destination features CSV")
    ap.add_argument("--workers", type=int, default=16,
                    help="parallel download+parse processes (default 16)")
    ap.add_argument("--limit", type=int, default=0,
                    help="process at most N pending samples (0 = all); use for a smoke test")
    ap.add_argument("--checkpoint-every", type=int, default=50,
                    help="flush the CSV every N completed samples (default 50)")
    args = ap.parse_args()

    api_key = os.environ.get("ANDROZOO_API_KEY")
    if not api_key:
        print("ANDROZOO_API_KEY not set", file=sys.stderr)
        return 2

    samples = pd.read_csv(args.input_csv)
    has_split = "split" in samples.columns
    columns = FEATURE_NAMES + ["sha256", "label", "split"]

    # Resume support: a long batch on a Spot VM can be preempted.
    rows: list[dict] = []
    done: set[str] = set()
    if os.path.exists(args.output_csv):
        try:
            previous = pd.read_csv(args.output_csv)
            rows = previous.to_dict("records")
            done = set(previous["sha256"].astype(str))
            print(f"resuming: {len(done)} rows already extracted")
        except Exception:  # noqa: BLE001
            pass

    pending: list[tuple[str, int, str, str]] = []
    for _, r in samples.iterrows():
        sha = str(r["sha256"])
        if sha in done:
            continue
        pending.append((sha, int(r["label"]),
                        str(r["split"]) if has_split else "train", api_key))

    # Interleave across (split, label) groups so ANY PREFIX of the output is representative.
    # A balanced sample list is normally written grouped by bucket, so processing it in file
    # order yields a wildly skewed partial CSV -- measured: the first 1553 rows were 1487
    # malware / 66 benign with ZERO test-split rows, so `evaluate_time_split` could not run
    # at all. Interleaving means a long extraction can be trained on at any point, which
    # matters when the job takes hours. Round-robin is deterministic, so resume stays stable.
    groups: dict[tuple[str, int], list] = {}
    for task in pending:
        groups.setdefault((task[2], task[1]), []).append(task)
    tasks: list[tuple[str, int, str, str]] = []
    for index in range(max((len(v) for v in groups.values()), default=0)):
        for key in sorted(groups):
            if index < len(groups[key]):
                tasks.append(groups[key][index])
    if groups:
        print("  interleaved groups: "
              + ", ".join(f"{s}/{'mal' if l else 'ben'}={len(v)}"
                          for (s, l), v in sorted(groups.items())))
    if args.limit:
        tasks = tasks[: args.limit]

    total = len(tasks)
    print(f"{total} samples pending | {args.workers} workers | "
          f"output {args.output_csv}")
    if not total:
        print("nothing to do")
        return 0

    def flush() -> None:
        temporary = args.output_csv + ".tmp"
        with open(temporary, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, args.output_csv)

    started = time.monotonic()
    completed = failed = 0
    try:
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(extract_one, t): t[0] for t in tasks}
            for future in as_completed(futures):
                completed += 1
                try:
                    row = future.result()
                except Exception as exc:  # noqa: BLE001 - worker died outright
                    failed += 1
                    print(f"  ! worker crashed on {futures[future][:12]}: "
                          f"{type(exc).__name__}", file=sys.stderr)
                    row = None
                if row and "__error__" in row:
                    failed += 1
                    print(f"  ! skip {row['sha256'][:12]}: {row['__error__']}",
                          file=sys.stderr)
                elif row:
                    rows.append(row)
                if completed % args.checkpoint_every == 0:
                    flush()
                    elapsed = time.monotonic() - started
                    rate = completed / max(elapsed, 1e-9)
                    remaining = (total - completed) / rate if rate else 0
                    print(f"[{completed}/{total}] kept={len(rows)} failed={failed} "
                          f"{rate:.2f}/s eta={remaining / 60:.1f}min", flush=True)
    except KeyboardInterrupt:
        print("\ninterrupted; flushing partial results", file=sys.stderr)
    finally:
        flush()

    elapsed = time.monotonic() - started
    print(f"wrote {len(rows)} feature rows -> {args.output_csv} (no APKs retained)")
    print(f"completed={completed} failed={failed} in {elapsed / 60:.1f} min "
          f"({completed / max(elapsed, 1e-9):.2f}/s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
