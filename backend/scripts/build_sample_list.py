#!/usr/bin/env python3
"""Build a balanced, time-split AndroZoo sample list from AndroZoo's `latest.csv` index.

This runs on a LAPTOP safely: `latest.csv` is a metadata index (hashes + VirusTotal
detection counts + dates). It contains NO APK bytes. Only the resulting sample list is
fed to `androzoo_extract.py`, which must run in the isolated lab VM.

Get the index (~4 GB, metadata only):
    curl -O https://androzoo.uni.lu/static/lists/latest.csv

`latest.csv` columns:
    sha256,sha1,md5,dex_date,apk_size,pkg_name,vercode,vt_detection,vt_scan_date,dex_size,markets

Labelling policy (conservative, defensible in the paper):
  * malware  : vt_detection >= --malware-min-vt   (default 10 -> strong consensus)
  * benign   : vt_detection == 0 AND distributed via play.google.com
  * DISCARDED: 1 <= vt_detection < threshold  (ambiguous / adware grey zone). Excluding
               these avoids training on label noise, and you should say so in the paper.

Time split (implements paper §9.1 "time-split generalisation"):
  * train : dex_date <  --cutoff
  * test  : dex_date >= --cutoff
  Testing on strictly newer samples measures generalisation to unseen families rather
  than memorisation — a random split would flatter the model.

Usage:
    python scripts/build_sample_list.py latest.csv samples.csv \
        --per-class 1500 --cutoff 2023-01-01
"""
import argparse
import csv
import sys

import pandas as pd

COLS = ["sha256", "dex_date", "apk_size", "pkg_name", "vt_detection", "markets"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("latest_csv", help="AndroZoo latest.csv index")
    ap.add_argument("output_csv", help="sample list to feed androzoo_extract.py")
    ap.add_argument("--per-class", type=int, default=1500,
                    help="samples per class per split half (default 1500)")
    ap.add_argument("--cutoff", default="2023-01-01",
                    help="train/test time boundary on dex_date (default 2023-01-01)")
    ap.add_argument("--malware-min-vt", type=int, default=10,
                    help="min VirusTotal detections to label malware (default 10)")
    ap.add_argument("--max-apk-mb", type=int, default=60,
                    help="skip APKs larger than this to bound extraction memory")
    ap.add_argument("--chunksize", type=int, default=500_000)
    args = ap.parse_args()

    cutoff = pd.Timestamp(args.cutoff)
    max_bytes = args.max_apk_mb * 1_000_000
    buckets: dict[tuple[str, int], list] = {
        ("train", 1): [], ("train", 0): [], ("test", 1): [], ("test", 0): [],
    }
    target = args.per_class
    scanned = 0

    reader = pd.read_csv(
        args.latest_csv, usecols=COLS, chunksize=args.chunksize,
        dtype={"sha256": str, "pkg_name": str, "markets": str},
        low_memory=False, on_bad_lines="skip",
    )

    for chunk in reader:
        scanned += len(chunk)
        chunk = chunk.dropna(subset=["sha256", "dex_date", "vt_detection"])
        chunk["dex_date"] = pd.to_datetime(chunk["dex_date"], errors="coerce")
        chunk = chunk.dropna(subset=["dex_date"])
        chunk["vt_detection"] = pd.to_numeric(chunk["vt_detection"], errors="coerce")
        chunk = chunk.dropna(subset=["vt_detection"])
        chunk["apk_size"] = pd.to_numeric(chunk["apk_size"], errors="coerce").fillna(0)
        chunk = chunk[chunk["apk_size"].between(1, max_bytes)]

        markets = chunk["markets"].fillna("")
        is_mal = chunk["vt_detection"] >= args.malware_min_vt
        is_ben = (chunk["vt_detection"] == 0) & markets.str.contains(
            "play.google.com", case=False, na=False)

        for label, mask in ((1, is_mal), (0, is_ben)):
            sub = chunk[mask]
            for split, smask in (("train", sub["dex_date"] < cutoff),
                                 ("test", sub["dex_date"] >= cutoff)):
                key = (split, label)
                need = target - len(buckets[key])
                if need <= 0:
                    continue
                take = sub[smask].head(need)
                for r in take.itertuples(index=False):
                    buckets[key].append({
                        "sha256": r.sha256,
                        "label": label,
                        "split": split,
                        "dex_date": r.dex_date.date().isoformat(),
                        "pkg_name": getattr(r, "pkg_name", "") or "",
                        "vt_detection": int(r.vt_detection),
                    })

        filled = all(len(v) >= target for v in buckets.values())
        print(f"  scanned {scanned:,} rows | "
              + " ".join(f"{s}/{'mal' if l else 'ben'}={len(v)}"
                         for (s, l), v in buckets.items()), file=sys.stderr)
        if filled:
            break

    rows = [r for v in buckets.values() for r in v]
    if not rows:
        print("No samples matched — check the index path and filters.", file=sys.stderr)
        return 1

    with open(args.output_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["sha256", "label", "split", "dex_date",
                                          "pkg_name", "vt_detection"])
        w.writeheader()
        w.writerows(rows)

    print(f"\nWrote {len(rows)} samples -> {args.output_csv}")
    for (split, label), v in buckets.items():
        print(f"  {split:5s} {'malware' if label else 'benign ':7s}: {len(v)}")
    print("\nNext: copy this file to the isolated lab VM and run "
          "`python scripts/androzoo_extract.py samples.csv features.csv`.")
    print("NEVER run the extractor on a personal device.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
