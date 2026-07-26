#!/usr/bin/env python3
"""Isolated AndroZoo -> features extractor.

RUN THIS IN AN ISOLATED, DISPOSABLE ENVIRONMENT (throwaway cloud VM, container,
or Databricks) — NOT on a personal device. It downloads APKs (which may be live
malware), extracts *static* features only (never executes them), writes a numeric
features CSV, and DELETES each APK immediately after extraction. Only the resulting
CSV should ever leave the isolated environment; feed it to
`drishti.ml.train.train_from_dataframe`.

Input CSV:  columns `sha256,label`  (label: 1 = malware, 0 = benign)
Output CSV: FEATURE_NAMES columns + `sha256,label`

Usage:
    ANDROZOO_API_KEY=... python scripts/androzoo_extract.py samples.csv out_features.csv
"""
import argparse
import os
import sys
import tempfile
import urllib.request

import pandas as pd

from drishti.ml.features import FEATURE_NAMES, extract_features
from drishti.static.androguard_adapter import parse_apk

ANDROZOO_URL = "https://androzoo.uni.lu/api/download"


def download_apk(sha256: str, api_key: str, dest: str) -> None:
    url = f"{ANDROZOO_URL}?apikey={api_key}&sha256={sha256}"
    urllib.request.urlretrieve(url, dest)  # noqa: S310 - trusted AndroZoo endpoint


def extract_one(sha256: str, label: int, api_key: str) -> dict | None:
    with tempfile.TemporaryDirectory() as tmp:
        apk_path = os.path.join(tmp, f"{sha256}.apk")
        try:
            download_apk(sha256, api_key, apk_path)
            parsed = parse_apk(apk_path)
            feats = extract_features(parsed)
        except Exception as e:  # noqa: BLE001
            print(f"  ! skip {sha256[:12]}: {type(e).__name__}", file=sys.stderr)
            return None
        finally:
            # APK is inside the TemporaryDirectory and is removed on exit; be explicit.
            if os.path.exists(apk_path):
                os.remove(apk_path)
    feats["sha256"] = sha256
    feats["label"] = int(label)
    return feats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input_csv", help="CSV with columns sha256,label")
    ap.add_argument("output_csv", help="destination features CSV")
    args = ap.parse_args()

    api_key = os.environ.get("ANDROZOO_API_KEY")
    if not api_key:
        print("ANDROZOO_API_KEY not set", file=sys.stderr)
        return 2

    samples = pd.read_csv(args.input_csv)
    rows = []
    for i, r in samples.iterrows():
        print(f"[{i + 1}/{len(samples)}] {str(r['sha256'])[:12]}...")
        row = extract_one(str(r["sha256"]), int(r["label"]), api_key)
        if row:
            rows.append(row)

    cols = FEATURE_NAMES + ["sha256", "label"]
    pd.DataFrame(rows, columns=cols).to_csv(args.output_csv, index=False)
    print(f"wrote {len(rows)} feature rows -> {args.output_csv} (no APKs retained)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
