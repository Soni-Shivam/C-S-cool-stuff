"""Source family-labelled Android malware for detonation. **Extractor VM only.**

`mb_samples.csv` carries no family column — `malwarebazaar_fetch.py` counts families
for its summary line and then throws them away — so a demo that wants to say "this is
Coper, a banking trojan" cannot get that from the corpus list. This re-queries
MalwareBazaar by `signature`, which is the field the family label lives in.

Two gates decide whether a sample is worth emulator time, and both are cheap:

1. **ABI.** The detonator runs an x86_64 AVD, so an ARM-only APK fails
   `INSTALL_FAILED_NO_MATCHING_ABIS` before a single hook fires — a tooling limit, not
   evasion (`docs/M3_DETONATOR_RUNBOOK.md` §0.0). A sample is accepted when it carries
   no `lib/` at all (pure-Java, the common case for droppers) or when it carries an
   x86 or x86_64 slice.
2. **minSdk.** The AVD is API 33. An APK demanding more will not install.

Accepted samples are uploaded to the private corpus bucket and nowhere else. Nothing
here executes a sample: zipfile and androguard read the APK as data.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

# androguard logs through loguru at DEBUG and emits thousands of lines per APK, which
# buries the one line per sample this script exists to print.
try:
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:  # loguru absent is not a reason to fail
    pass

API = "https://mb-api.abuse.ch/api/v1/"
MB_ZIP_PASSWORD = b"infected"
EMULATOR_ABIS = {"x86", "x86_64"}
EMULATOR_API_LEVEL = 33

COLUMNS = [
    "sha256",
    "family",
    "first_seen",
    "apk_size",
    "abis",
    "pkg_name",
    "min_sdk",
    "verdict",
]


def require_extractor_vm(override: bool) -> None:
    """Refuse to download real malware anywhere but the GCE extractor."""
    if not override:
        sys.exit(
            "refusing to run: this script downloads real malware and must only run on "
            "the GCE extractor VM. Pass --i-am-the-extractor-vm if that is where you are."
        )
    product = Path("/sys/class/dmi/id/product_name")
    if not (product.exists() and "Google" in product.read_text()):
        sys.exit("refusing to run: this host does not look like a GCE instance.")


def query_family(api_key: str, family: str, limit: int) -> list[dict]:
    """Metadata for one MalwareBazaar `signature`, newest first. Downloads nothing."""
    response = httpx.post(
        API,
        headers={"Auth-Key": api_key},
        data={"query": "get_siginfo", "signature": family, "limit": str(limit)},
        timeout=90,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("query_status") != "ok":
        print(f"  {family}: {payload.get('query_status')}", file=sys.stderr)
        return []
    rows = [r for r in (payload.get("data") or []) if (r.get("file_type") or "") == "apk"]
    rows.sort(key=lambda r: r.get("first_seen") or "", reverse=True)
    return rows


def download(sha256: str, api_key: str, dest: Path, max_bytes: int) -> int:
    """Fetch one sample and unwrap its password-protected archive."""
    response = httpx.post(
        API,
        headers={"Auth-Key": api_key},
        data={"query": "get_file", "sha256_hash": sha256},
        timeout=300,
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
    if len(blob) > max_bytes:
        raise ValueError(f"exceeds {max_bytes} byte cap")
    dest.write_bytes(blob)
    return len(blob)


def inspect(path: Path) -> tuple[set[str], str, int] | None:
    """(native ABIs, package name, minSdk), or None if this is not a readable APK.

    MalwareBazaar's `apk` file type is assigned by its own classifier and a handful of
    rows are not zip archives at all. That must skip one sample, not abort the run —
    a `BadZipFile` propagating out of here previously killed a ten-family sourcing pass
    on its sixth sample.
    """
    abis: set[str] = set()
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                parts = name.split("/")
                if len(parts) >= 3 and parts[0] == "lib" and parts[2]:
                    abis.add(parts[1])
    except Exception as exc:
        print(f"    not a readable APK ({type(exc).__name__})", file=sys.stderr)
        return None
    pkg, min_sdk = "", 0
    try:
        from androguard.core.apk import APK  # type: ignore[import-untyped]

        apk = APK(str(path))
        pkg = apk.get_package() or ""
        min_sdk = int(apk.get_min_sdk_version() or 0)
    except Exception as exc:  # a manifest we cannot parse is still detonatable
        print(f"    manifest parse failed ({type(exc).__name__})", file=sys.stderr)
    return abis, pkg, min_sdk


def verdict_for(abis: set[str], min_sdk: int) -> str:
    """Why this sample is or is not worth emulator time."""
    if abis and not (abis & EMULATOR_ABIS):
        return f"skip_abi:{','.join(sorted(abis))}"
    if min_sdk > EMULATOR_API_LEVEL:
        return f"skip_minsdk:{min_sdk}"
    return "detonatable"


def upload(path: Path, bucket: str, sha256: str) -> None:
    """Retain in the private corpus bucket. The only place a sample is ever written."""
    target = f"gs://{bucket}/apks/{sha256[:2]}/{sha256}.apk"
    for attempt in range(4):
        try:
            subprocess.run(
                ["gcloud", "storage", "cp", "--quiet", str(path), target],
                check=True,
                capture_output=True,
                timeout=600,
            )
            return
        except Exception:
            if attempt == 3:
                raise
            time.sleep(5 * (attempt + 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", action="append", required=True)
    parser.add_argument("--per-family", type=int, default=6)
    parser.add_argument("--candidates", type=int, default=40, help="metadata rows to consider")
    parser.add_argument("--max-apk-mb", type=int, default=30)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bucket", default="cybershield-505518-corpus")
    parser.add_argument("--i-am-the-extractor-vm", action="store_true")
    args = parser.parse_args()

    require_extractor_vm(args.i_am_the_extractor_vm)
    api_key = os.environ.get("DRISHTI_MALWAREBAZAAR_API_KEY", "").strip()
    if not api_key:
        sys.exit("DRISHTI_MALWAREBAZAAR_API_KEY is not set")

    max_bytes = args.max_apk_mb * 1_000_000
    seen: set[str] = set()
    rows: list[dict] = []
    workdir = Path(tempfile.mkdtemp(prefix="drishti-deto-"))

    for family in args.family:
        print(f"\n=== {family} ===")
        accepted = 0
        for item in query_family(api_key, family, args.candidates):
            if accepted >= args.per_family:
                break
            sha = (item.get("sha256_hash") or "").lower()
            size = int(item.get("file_size") or 0)
            if not sha or sha in seen or not (0 < size <= max_bytes):
                continue
            seen.add(sha)
            apk = workdir / f"{sha}.apk"
            try:
                download(sha, api_key, apk, max_bytes)
            except Exception as exc:
                print(f"  {sha[:12]} download failed: {exc}", file=sys.stderr)
                continue
            probe = inspect(apk)
            if probe is None:
                apk.unlink(missing_ok=True)
                rows.append(
                    {
                        "sha256": sha,
                        "family": family,
                        "first_seen": (item.get("first_seen") or "")[:10],
                        "apk_size": size,
                        "abis": "",
                        "pkg_name": "",
                        "min_sdk": 0,
                        "verdict": "skip_unreadable",
                    }
                )
                continue
            abis, pkg, min_sdk = probe
            call = verdict_for(abis, min_sdk)
            print(
                f"  {sha[:12]} {call:22s} abis={','.join(sorted(abis)) or '-':16s} "
                f"minSdk={min_sdk or '?'} pkg={pkg or '?'}"
            )
            if call == "detonatable":
                try:
                    upload(apk, args.bucket, sha)
                    accepted += 1
                except Exception as exc:
                    print(f"    upload failed: {type(exc).__name__}", file=sys.stderr)
                    call = "skip_upload_failed"
            apk.unlink(missing_ok=True)
            rows.append(
                {
                    "sha256": sha,
                    "family": family,
                    "first_seen": (item.get("first_seen") or "")[:10],
                    "apk_size": size,
                    "abis": ",".join(sorted(abis)),
                    "pkg_name": pkg,
                    "min_sdk": min_sdk,
                    "verdict": call,
                }
            )
            time.sleep(1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    good = [r for r in rows if r["verdict"] == "detonatable"]
    print(f"\n{len(good)}/{len(rows)} detonatable -> {args.out}")
    for family in args.family:
        n = len([r for r in good if r["family"] == family])
        print(f"  {family}: {n}")
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
