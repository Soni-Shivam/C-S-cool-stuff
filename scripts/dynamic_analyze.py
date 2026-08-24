#!/usr/bin/env python3
"""CLI for one admitted detonation on the sealed runtime."""

from __future__ import annotations

import argparse
import fcntl
from pathlib import Path

from drishti.m3_dynamic.harness import DynamicHarness, HarnessConfig


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=120, choices=range(1, 1801))
    parser.add_argument(
        "--sample-kind",
        choices=("inert_fixture", "benign", "vetted_malware"),
        default="inert_fixture",
    )
    args = parser.parse_args()
    if not args.apk.is_file():
        raise SystemExit("APK path is not a regular file")

    lock_path = Path("/run/drishti-analysis.lock")
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit("another detonation is already running") from exc
        artifact = DynamicHarness(
            HarnessConfig(
                apk=args.apk,
                output=args.out,
                duration_s=args.duration,
                sample_kind=args.sample_kind,
            )
        ).run()
    print(
        f"artifact={args.out} sha256={artifact.sha256} "
        f"outcome={artifact.outcome} observations={len(artifact.observations)}"
    )
    return 0 if artifact.safe_for_ingestion else 2


if __name__ == "__main__":
    raise SystemExit(main())
