#!/usr/bin/env python3
"""Emit M7 campaign artifacts (YARA + Frida + STIX) for one or more analysed samples.

This is the operator-facing end of paper 4.7: turn a completed analysis into content a SOC
can deploy immediately. It runs the full M1-M7 pipeline for each APK, then writes the
generated hunt rule, passive Frida observer, and STIX 2.1 bundle to an output directory
alongside a machine-readable index.

Because it parses APKs, run it in the isolated lab, never on a personal device. It never
executes a sample; dynamic evidence must come from a SHA-matched artifact produced earlier
by the sealed detonator.

Usage (single sample, with real detonator observations):
    PYTHONPATH=. python scripts/emit_artifacts.py \\
        --apk /opt/drishti/quarantine/<sha>.apk \\
        --observations /opt/drishti/observations/<sha>.json \\
        --out-dir /opt/drishti/artifacts

Usage (whole quarantine directory, matching observations by SHA-256 filename):
    PYTHONPATH=. python scripts/emit_artifacts.py \\
        --apk-dir /opt/drishti/quarantine \\
        --observations-dir /opt/drishti/observations \\
        --out-dir /opt/drishti/artifacts --reputation samples.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from drishti.ingestion.reputation import ReputationFeed
from drishti.llm import get_provider
from drishti.pipeline.pipeline import run_pipeline
from drishti.reporting.artifacts import generate_all
from drishti.reporting.report import build_android_report


def analyse(apk: Path, observations: Path | None, *, provider, feed, allow_label_derived):
    mode = "observed" if observations is not None else "absent"
    return run_pipeline(
        str(apk), timestamp=datetime.now(timezone.utc).isoformat(),
        provider=provider, dynamic_mode=mode,
        observations=str(observations) if observations else None,
        reputation_feed=feed,
        allow_label_derived_reputation=allow_label_derived,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", type=Path, action="append", default=[])
    ap.add_argument("--apk-dir", type=Path)
    ap.add_argument("--observations", type=Path)
    ap.add_argument("--observations-dir", type=Path)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--reputation", type=Path,
                    help="samples.csv-style feed for the R term (label-derived)")
    ap.add_argument("--allow-label-derived-reputation", action="store_true",
                    help="opt in to a label-derived feed; NOT valid for benchmark reporting")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    apks: list[Path] = list(args.apk)
    if args.apk_dir:
        apks.extend(sorted(p for p in args.apk_dir.glob("*.apk")))
    if not apks:
        print("no APKs given (--apk / --apk-dir)", file=sys.stderr)
        return 2
    if args.limit:
        apks = apks[: args.limit]

    feed = ReputationFeed.from_sample_list(args.reputation) if args.reputation else None
    provider = get_provider()
    args.out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    index: list[dict] = []
    for apk in apks:
        sha_stem = apk.stem.lower()
        observations = args.observations
        if observations is None and args.observations_dir:
            candidate = args.observations_dir / f"{sha_stem}.json"
            observations = candidate if candidate.is_file() else None
        try:
            result = analyse(apk, observations, provider=provider, feed=feed,
                             allow_label_derived=args.allow_label_derived_reputation)
        except Exception as exc:  # noqa: BLE001 - one bad sample must not stop the batch
            print(f"  ! {apk.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            traceback.print_exc(limit=2, file=sys.stderr)
            index.append({"apk": apk.name, "error": f"{type(exc).__name__}: {exc}"})
            continue

        verdict = result.verdict
        sample_dir = args.out_dir / verdict.sha256[:16]
        sample_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        written: list[str] = []
        for artifact in generate_all(result):
            path = sample_dir / artifact.filename
            path.write_text(artifact.content)
            os.chmod(path, 0o600)
            written.append(artifact.filename)

        report = build_android_report(
            result, analysis_id=f"artifacts-{verdict.sha256[:12]}",
            gemini_live=(provider.name == "gemini"))
        (sample_dir / "report.json").write_text(report.model_dump_json(indent=2))
        (sample_dir / "ledger.json").write_text(json.dumps(result.ledger, indent=2))

        escalation = result.escalation or {}
        entry = {
            "sha256": verdict.sha256,
            "package": (result.dynamic or {}).get("package"),
            "threat_score": verdict.threat_score,
            "severity": verdict.severity_band,
            "confidence": verdict.confidence,
            "dynamic_status": verdict.dynamic_status,
            "techniques": verdict.attack_techniques,
            "reputation_r": (result.static or {}).get("reputation_r"),
            "anomaly_score": escalation.get("anomaly_score"),
            "escalated": escalation.get("escalated"),
            "requires_human_review": escalation.get("requires_human_review"),
            "artifacts": written,
            "directory": str(sample_dir),
        }
        index.append(entry)
        print(f"  {verdict.sha256[:12]}  {verdict.severity_band:8s} {verdict.threat_score:3d}/100  "
              f"dyn={verdict.dynamic_status:8s} anomaly={escalation.get('anomaly_score')}  "
              f"-> {len(written)} artifacts")

    index_path = args.out_dir / "index.json"
    index_path.write_text(json.dumps(
        {"generated_at": datetime.now(timezone.utc).isoformat(),
         "provider": provider.name, "samples": index}, indent=2))
    ok = [e for e in index if "error" not in e]
    print(f"\n{len(ok)}/{len(index)} analysed -> {args.out_dir}")
    print(f"index -> {index_path}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
