#!/usr/bin/env python3
"""Download corpus APKs, run real M2, extract features. **GCE extractor VM only.**

docs/PHASE_2_ML_AND_SCORING.md T2.2, CLAUDE.md "Execution environment".

    THIS SCRIPT MUST NEVER RUN ON A DEVELOPER MACHINE.

It downloads real malware. It does not execute it — androguard parses DEX and resources
as data, which is why static extraction is allowed off the sealed detonator at all. But
the bytes are real, so the file refuses to start unless `--i-am-the-extractor-vm` is
passed AND the host looks like a GCE instance.

Two rules from `docs/SALVAGE.md`, both learned by v1 the hard way:

  * **Retain the APK in GCS.** v1 deleted every APK after extraction, which is exactly
    why a feature-schema change later cost a full re-download.
  * **Read the sample list on FD 3**, never stdin — a naive loop silently stops after one
    sample and looks like a data problem.

Local disk holds only the batch being worked on: download -> analyse -> upload -> delete.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import urlopen

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ANDROZOO_URL = "https://androzoo.uni.lu/api/download"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

#: MalwareBazaar ships samples inside a zip encrypted with this password, the long-standing
#: convention for handing malware around without a mail scanner eating it.
MB_ZIP_PASSWORD = b"infected"

#: Anything larger is a parser risk and a memory risk for marginal signal.
MAX_APK_BYTES = 60_000_000


def assert_not_a_laptop(override: bool) -> None:
    """Refuse to run anywhere that is not the extractor VM.

    Belt and braces: an explicit flag AND a check that we are actually on GCE. The flag
    alone would be too easy to paste into a local shell while debugging.
    """
    if not override:
        sys.exit(
            "refusing to run: this script downloads real malware and must only run on "
            "the GCE extractor VM. Pass --i-am-the-extractor-vm if that is where you are."
        )
    product = Path("/sys/class/dmi/id/product_name")
    on_gce = product.exists() and "Google" in product.read_text()
    if not on_gce and not os.environ.get("DRISHTI_FORCE_NON_GCE"):
        sys.exit(
            "refusing to run: --i-am-the-extractor-vm was passed but this host does not "
            "look like a GCE instance. Real samples never touch a developer machine."
        )


def download_from_malwarebazaar(sha256: str, api_key: str, dest: Path, timeout: int = 180) -> int:
    """Fetch one sample from MalwareBazaar and unwrap its encrypted zip.

    The API returns a password-protected archive rather than the APK directly. Standard
    zipfile handles ZipCrypto; abuse.ch now uses AES, so pyzipper is tried first and the
    stdlib is the fallback.
    """
    import io

    response = httpx.post(
        MALWAREBAZAAR_URL,
        headers={"Auth-Key": api_key},
        data={"query": "get_file", "sha256_hash": sha256},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.content
    if payload[:1] == b"{":
        raise ValueError(f"MalwareBazaar refused: {payload[:120]!r}")

    def _extract(opener: Any) -> bytes:
        with opener(io.BytesIO(payload)) as archive:
            names = [n for n in archive.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError("empty archive")
            return bytes(archive.read(names[0], pwd=MB_ZIP_PASSWORD))

    try:
        import pyzipper

        blob = _extract(pyzipper.AESZipFile)
    except Exception:
        blob = _extract(zipfile.ZipFile)

    if not blob:
        raise ValueError("archive contained no bytes")
    if len(blob) > MAX_APK_BYTES:
        raise ValueError(f"exceeds {MAX_APK_BYTES} byte cap")
    dest.write_bytes(blob)
    return len(blob)


def download_apk(sha256: str, api_key: str, dest: Path, timeout: int = 180) -> int:
    """Fetch one APK by hash from AndroZoo. Returns bytes written."""
    url = f"{ANDROZOO_URL}?{urlencode({'apikey': api_key, 'sha256': sha256})}"
    written = 0
    with urlopen(url, timeout=timeout) as response, dest.open("wb") as handle:
        while chunk := response.read(1 << 20):
            written += len(chunk)
            if written > MAX_APK_BYTES:
                raise ValueError(f"exceeds {MAX_APK_BYTES} byte cap")
            handle.write(chunk)
    if written == 0:
        raise ValueError("empty response")
    return written


def upload_to_gcs(path: Path, bucket: str, sha256: str) -> None:
    """Retain the sample in GCS. Sharded by hash prefix so no directory holds millions."""
    target = f"gs://{bucket}/apks/{sha256[:2]}/{sha256}.apk"
    subprocess.run(
        ["gcloud", "storage", "cp", "--quiet", str(path), target],
        check=True,
        capture_output=True,
        timeout=300,
    )


def process_one(
    row: dict, api_key: str, bucket: str, workdir: Path, retain: bool, source: str = "androzoo"
) -> dict:
    """Download, analyse, extract, retain, delete. Returns a result record."""
    from drishti.ledger.store import LedgerStore
    from drishti.m2_static.engine import analyse
    from drishti.m5_ml.features import extract

    sha = row["sha256"].lower()
    apk = workdir / f"{sha}.apk"
    started = time.monotonic()
    record: dict = {
        "sha256": sha,
        "label": int(row["label"]),
        "split": row["split"],
        "time_band": row["time_band"],
        "dex_date": row["dex_date"],
        "ok": False,
        "error": "",
        "features": {},
    }
    try:
        if source == "malwarebazaar":
            record["bytes"] = download_from_malwarebazaar(sha, api_key, apk)
        else:
            record["bytes"] = download_apk(sha, api_key, apk)
        # A throwaway ledger per sample: M2 wants somewhere to append, and corpus
        # extraction is not an investigation whose chain anyone will verify.
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            store = LedgerStore(scratch_path / "l.db", scratch_path / "k.pem")
            store.open(f"corpus_{sha[:12]}")
            try:
                report = analyse(apk, store)
            finally:
                store.close()
        record["features"] = extract(report).values
        record["package"] = report.package
        record["static_partial"] = report.partial
        if retain:
            upload_to_gcs(apk, bucket, sha)
        record["ok"] = True
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        # The APK leaves this disk whatever happened. Local storage holds only the
        # working batch, never the corpus.
        apk.unlink(missing_ok=True)
        record["seconds"] = round(time.monotonic() - started, 2)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample_list", type=Path)
    parser.add_argument("output_jsonl", type=Path)
    parser.add_argument("--limit", type=int, default=0, help="stop after N samples")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--bucket", default="cybershield-505518-corpus")
    parser.add_argument("--no-retain", action="store_true", help="skip the GCS upload")
    parser.add_argument("--source", choices=("androzoo", "malwarebazaar"), default="androzoo")
    parser.add_argument("--i-am-the-extractor-vm", action="store_true")
    args = parser.parse_args()

    assert_not_a_laptop(args.i_am_the_extractor_vm)

    key_var = (
        "DRISHTI_MALWAREBAZAAR_API_KEY"
        if args.source == "malwarebazaar"
        else "DRISHTI_ANDROZOO_API_KEY"
    )
    api_key = os.environ.get(key_var, "").strip()
    if not api_key:
        sys.exit(f"{key_var} is not set")

    # Resume support: a batch that dies at sample 900 must not start over.
    done: set[str] = set()
    if args.output_jsonl.exists():
        with args.output_jsonl.open() as handle:
            for line in handle:
                try:
                    done.add(json.loads(line)["sha256"])
                except (json.JSONDecodeError, KeyError):
                    continue
        print(f"resuming: {len(done)} samples already processed", flush=True)

    # FD 3, never stdin (SALVAGE.md): a naive stdin loop stops after one sample.
    with args.sample_list.open() as handle:
        rows = [r for r in csv.DictReader(handle) if r["sha256"].lower() not in done]
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("nothing to do")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="drishti-corpus-"))
    print(
        f"processing {len(rows)} samples, {args.workers} workers, "
        f"retain={'no' if args.no_retain else 'yes'}, workdir={workdir}",
        flush=True,
    )

    started = time.monotonic()
    ok = failed = 0
    total_bytes = 0
    try:
        with (
            args.output_jsonl.open("a") as sink,
            ThreadPoolExecutor(max_workers=args.workers) as pool,
        ):
            futures = {
                pool.submit(
                    process_one,
                    row,
                    api_key,
                    args.bucket,
                    workdir,
                    not args.no_retain,
                    args.source,
                ): row
                for row in rows
            }
            for index, future in enumerate(as_completed(futures), start=1):
                record = future.result()
                sink.write(json.dumps(record) + "\n")
                sink.flush()
                if record["ok"]:
                    ok += 1
                    total_bytes += record.get("bytes", 0)
                else:
                    failed += 1
                if index % 25 == 0 or index == len(rows):
                    elapsed = time.monotonic() - started
                    rate = index / elapsed if elapsed else 0
                    mbps = (total_bytes / 1e6) / elapsed if elapsed else 0
                    print(
                        f"  {index}/{len(rows)}  ok={ok} failed={failed}  "
                        f"{rate:.2f} samples/s  {mbps:.1f} MB/s  "
                        f"eta {(len(rows) - index) / rate / 60:.1f} min"
                        if rate
                        else f"  {index}/{len(rows)}",
                        flush=True,
                    )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    elapsed = time.monotonic() - started
    print(f"\ndone in {elapsed / 60:.1f} min — ok={ok} failed={failed}")
    print(f"downloaded {total_bytes / 1e9:.2f} GB at {(total_bytes / 1e6) / elapsed:.1f} MB/s")
    print(f"workdir removed: {not workdir.exists()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
