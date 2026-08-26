#!/usr/bin/env python3
"""Fail-closed containment verification entry point for the sealed GCE VM."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from drishti.m3_dynamic.admission import (
    DEFAULT_MANIFEST,
    DEFAULT_PRIVATE_KEY,
    DEFAULT_PUBLIC_KEY,
    checks_from_report,
    manifest_summary,
    require_sealed_runtime,
    sign_manifest,
    write_manifest,
)
from drishti.m3_dynamic.containment import require_containment


def _iptables_default_drop() -> bool:
    return all(
        subprocess.run(
            ["iptables", "-C", chain, "-j", "DROP"],
            capture_output=True,
            check=False,
        ).returncode
        == 0
        for chain in ("OUTPUT", "FORWARD")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--instance-id", default=os.environ.get("DRISHTI_INSTANCE_ID"))
    parser.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--public-key-out", type=Path, default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--manifest-out", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--ttl-minutes", type=int, default=10)
    args = parser.parse_args()
    if not args.instance_id:
        raise SystemExit("DRISHTI_INSTANCE_ID or --instance-id is required")

    runtime_image = require_sealed_runtime()
    report = require_containment(args.serial)
    checks = checks_from_report(
        report,
        kvm_ok=os.access("/dev/kvm", os.R_OK | os.W_OK),
        firewall_default_drop=_iptables_default_drop(),
    )
    manifest = sign_manifest(
        instance_id=args.instance_id,
        runtime_image=runtime_image,
        checks=checks,
        private_key_hex=args.private_key.read_text(encoding="utf-8"),
        ttl_minutes=args.ttl_minutes,
    )
    digest = write_manifest(
        manifest, manifest_path=args.manifest_out, public_key_path=args.public_key_out
    )
    print(manifest_summary(manifest, digest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
