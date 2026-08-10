#!/usr/bin/env python3
"""Train DRISHTI's M5 model on a real features CSV and print paper-ready metrics.

Runs safely on a laptop: consumes only the numeric features CSV produced by the
isolated extractor. No APKs involved.

Usage:
    python scripts/train_real.py features.csv --save drishti/data/models/androzoo.joblib
"""
import argparse
import json
import sys

import pandas as pd

from drishti.ml.evaluate import evaluate_time_split, format_report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("features_csv")
    ap.add_argument("--save", default=None, help="path to write the trained model")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--metrics-json", default=None, help="write metrics as JSON")
    args = ap.parse_args()

    df = pd.read_csv(args.features_csv)
    print(f"loaded {len(df)} feature rows from {args.features_csv}")
    print(f"  label balance: {df['label'].value_counts().to_dict()}")

    metrics = evaluate_time_split(df, threshold=args.threshold)
    print()
    print(format_report(metrics))

    clf = metrics.pop("classifier")
    if args.save:
        clf.save(args.save)
        print(f"\nsaved model -> {args.save}")
    if args.metrics_json:
        with open(args.metrics_json, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"saved metrics -> {args.metrics_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
