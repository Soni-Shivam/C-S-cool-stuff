#!/usr/bin/env python3
"""Re-extract features for rows written under an older schema. **Extractor VM only.**

A certificate-feature fix bumped the extractor schema from 1.1.0 (`cert:age_days`, a
wall-clock-dependent value) to 1.2.0 (`cert:validity_days`, time-invariant). The bump
landed mid-batch, so the corpus carries two epochs. That is not merely untidy: the two
epochs have different class balance, so a naive vocabulary that zero-fills the missing
cert columns encodes WHEN A ROW WAS EXTRACTED — a proxy for the label, the same
circularity as feeding in `vt_detection`. The ML layer guards it by dropping the
divergent columns, which throws the certificate signal away entirely.

The real fix is re-extraction, and it is cheap because the APKs were RETAINED in the
corpus bucket for exactly this (SALVAGE.md). This script, for every input row whose
features still carry `cert:age_days`:

  * pulls the APK from gs://<corpus>/apks/<sha[:2]>/<sha>.apk — GCS, never AndroZoo, so
    no rate limit is touched,
  * re-runs the CURRENT m2_static + m5_ml.features.extract over it,
  * writes the refreshed row (schema 1.2.0) to the output jsonl.

Rows already at 1.2.0 are skipped: the merge dedups by sha256 and this file only needs
to carry the corrections. Same containment discipline as the extractor — APK parsed as
data by androguard, capped by size, deleted immediately, never installed or executed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path.home() / "CyberShield"))

# androguard's loguru DEBUG buries the one useful line per sample.
try:
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:
    pass

BUCKET = "gs://cybershield-505518-corpus/apks"
OLD_FEATURE = "cert:age_days"  # the 1.1.0 marker
NEW_FEATURE = "cert:validity_days"  # the 1.2.0 marker
_local = threading.local()
_lock = threading.Lock()


def require_vm(override: bool) -> None:
    if not override:
        sys.exit("refusing to run: pass --i-am-the-extractor-vm. Samples never leave GCP.")
    product = Path("/sys/class/dmi/id/product_name")
    if not (product.exists() and "Google" in product.read_text()):
        sys.exit("refusing to run: this host does not look like a GCE instance.")


def rows_needing_reextraction(inputs: list[Path]) -> dict[str, dict]:
    """sha256 -> the newest input row that still carries the 1.1.0 cert feature.

    Deduped by sha: if the same sample appears in two shards, the last one read wins,
    which is harmless because only the label/split metadata is carried forward and that
    is identical across shards.
    """
    out: dict[str, dict] = {}
    for path in inputs:
        if not path.exists():
            continue
        with path.open() as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                feats = row.get("features") or {}
                if OLD_FEATURE in feats and NEW_FEATURE not in feats:
                    out[row["sha256"].lower()] = row
    return out


def reextract_one(sha: str, row: dict, root: Path, max_mb: int) -> dict | None:
    """Pull, re-analyse, re-extract, delete. Returns the refreshed row or None."""
    from drishti.ledger.store import LedgerStore
    from drishti.m2_static.engine import analyse
    from drishti.m5_ml.features import extract

    local = root / f"{sha}.apk"
    pull = subprocess.run(
        ["gcloud", "storage", "cp", "--quiet", f"{BUCKET}/{sha[:2]}/{sha}.apk", str(local)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if pull.returncode != 0 or not local.exists():
        with _lock:
            print(f"  miss {sha[:12]} (not retained in bucket)", file=sys.stderr)
        return None
    size_mb = local.stat().st_size // (1024 * 1024)
    if size_mb > max_mb:
        local.unlink(missing_ok=True)
        with _lock:
            print(f"  skip {sha[:12]} ({size_mb}MB > {max_mb}MB)", file=sys.stderr)
        return None
    try:
        with tempfile.TemporaryDirectory(dir=root) as scratch:
            store = LedgerStore(Path(scratch) / "l.db", Path(scratch) / "k.pem")
            store.open(f"reextract_{sha[:12]}")
            try:
                report = analyse(local, store)
            finally:
                store.close()
        features = extract(report).values
    except Exception as exc:
        with _lock:
            print(f"  fail {sha[:12]} ({type(exc).__name__}: {exc})", file=sys.stderr)
        return None
    finally:
        local.unlink(missing_ok=True)

    refreshed = dict(row)
    refreshed["features"] = features
    refreshed["package"] = report.package
    refreshed["static_partial"] = report.partial
    refreshed["reextracted"] = True
    return refreshed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_jsonl", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path, help="feature jsonl shard(s)")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--max-apk-mb", type=int, default=20)
    parser.add_argument("--i-am-the-extractor-vm", action="store_true")
    args = parser.parse_args()

    require_vm(args.i_am_the_extractor_vm)

    todo = rows_needing_reextraction(args.inputs)
    # Resume support: don't redo rows already written to the output.
    done: set[str] = set()
    if args.output_jsonl.exists():
        with args.output_jsonl.open() as handle:
            for line in handle:
                try:
                    done.add(json.loads(line)["sha256"].lower())
                except (json.JSONDecodeError, KeyError):
                    continue
    pending = {sha: row for sha, row in todo.items() if sha not in done}
    print(
        f"rows needing re-extraction: {len(todo)}  already done: {len(done)}  "
        f"to do now: {len(pending)}"
    )

    written = 0
    with tempfile.TemporaryDirectory(dir="/var/tmp") as tmp:
        root = Path(tmp)
        with (
            args.output_jsonl.open("a") as sink,
            ThreadPoolExecutor(max_workers=args.workers) as pool,
        ):
            futures = [
                pool.submit(reextract_one, sha, row, root, args.max_apk_mb)
                for sha, row in pending.items()
            ]
            for future in futures:
                result = future.result()
                if result is None:
                    continue
                with _lock:
                    sink.write(json.dumps(result) + "\n")
                    sink.flush()
                    written += 1
                    if written % 25 == 0:
                        print(f"  ... {written} rows re-extracted", flush=True)

    print(f"\nwrote {written} refreshed rows -> {args.output_jsonl}")

    # Verify single-epoch over the output: every row 1.2.0, none 1.1.0.
    bad_old = bad_missing = 0
    with args.output_jsonl.open() as handle:
        for line in handle:
            try:
                feats = json.loads(line).get("features") or {}
            except json.JSONDecodeError:
                continue
            if OLD_FEATURE in feats:
                bad_old += 1
            if NEW_FEATURE not in feats:
                bad_missing += 1
    print(f"verification: rows still carrying {OLD_FEATURE}: {bad_old}")
    print(f"verification: rows missing {NEW_FEATURE}: {bad_missing}")
    if bad_old or bad_missing:
        print("FAIL: output is not a single 1.2.0 epoch", file=sys.stderr)
        return 1
    print("OK: every re-extracted row is schema 1.2.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
