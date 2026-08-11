#!/usr/bin/env python3
"""Validate and publish an inert fixture artifact for parse-only API ingestion."""
from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

from drishti.sandbox.observation import ObservationArtifact


EXPECTED_HOOKS = {
    "ClipboardManager.getPrimaryClip",
    "ClipboardManager.setPrimaryClip",
    "Cipher.doFinal([B)",
    "DexClassLoader.$init",
    "URL.openConnection",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--observations-dir", type=Path, required=True)
    args = parser.parse_args()

    artifact = ObservationArtifact.model_validate_json(args.artifact.read_text())
    apk_sha = digest(args.apk)
    if artifact.sha256 != apk_sha:
        raise SystemExit("fixture artifact SHA-256 does not match the APK")
    if not artifact.safe_for_ingestion:
        raise SystemExit("fixture failed containment/snapshot acceptance")
    hooks = {event.source_hook for event in artifact.observations}
    missing = sorted(EXPECTED_HOOKS - hooks)
    if missing:
        raise SystemExit("fixture is missing expected observations: " + ", ".join(missing))
    args.observations_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = args.observations_dir / f"{apk_sha}.json"
    shutil.copyfile(args.artifact, destination)
    destination.chmod(0o600)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
