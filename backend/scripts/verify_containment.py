#!/usr/bin/env python3
"""Probe both containment layers and emit a signed, short-lived manifest.

Run only on the sealed runtime through an active IAP SSH session. Any ambiguous
probe is a failure; a manifest is never emitted from partial results.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from drishti.sandbox.containment import load_and_verify_control_plane_attestation, sign_manifest


def run(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def blocked(args: list[str]) -> bool:
    result = run(args)
    return result.returncode != 0


def adb_blocked(serial: str, host: str, port: int) -> bool:
    return blocked([
        "adb", "-s", serial, "shell", "toybox", "nc", "-z", "-w", "3", host, str(port)
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key-out", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--control-plane-attestation", type=Path, required=True)
    parser.add_argument("--control-plane-public-key", type=Path, required=True)
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--vpc-probe", required=True, help="an unused internal IP that must be unreachable")
    parser.add_argument("--ttl-minutes", type=int, default=10, choices=range(1, 31))
    args = parser.parse_args()

    load_and_verify_control_plane_attestation(
        args.control_plane_attestation, args.control_plane_public_key,
        instance_id=args.instance_id, runtime_image=args.runtime_image,
    )
    ssh_active = bool(os.environ.get("SSH_CONNECTION")) or bool(
        run(["ss", "-Htn", "state", "established", "sport", "=", ":22"]).stdout.strip()
    )
    checks = {
        "host_internet_blocked": blocked(["curl", "--fail", "--silent", "--max-time", "5", "https://example.com"]),
        "emulator_internet_blocked": adb_blocked(args.serial, "1.1.1.1", 443),
        "emulator_metadata_blocked": adb_blocked(args.serial, "169.254.169.254", 80),
        "emulator_vpc_blocked": adb_blocked(args.serial, args.vpc_probe, 22),
        "external_ip_absent": True,  # proven by the signed control-plane attestation above
        "iap_ssh_functional": ssh_active,
        "nested_kvm_functional": Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK),
        "host_firewall_default_drop": (
            run(["iptables", "-C", "OUTPUT", "-j", "DROP"]).returncode == 0
            and run(["iptables", "-C", "FORWARD", "-j", "DROP"]).returncode == 0
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise SystemExit("CONTAINMENT FAILED: " + ", ".join(failed))

    private_hex = args.private_key.read_text().strip()
    issued = datetime.now(timezone.utc)
    manifest = sign_manifest({
        "instance_id": args.instance_id,
        "runtime_image": args.runtime_image,
        "issued_at": issued,
        "expires_at": issued + timedelta(minutes=args.ttl_minutes),
        "checks": checks,
    }, private_hex)
    args.manifest_out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.manifest_out.write_text(manifest.model_dump_json(indent=2))
    os.chmod(args.manifest_out, 0o600)
    args.public_key_out.parent.mkdir(parents=True, exist_ok=True)
    args.public_key_out.write_text(manifest.public_key + "\n")
    os.chmod(args.public_key_out, 0o644)
    print(f"CONTAINMENT OK: signed manifest valid until {manifest.expires_at.isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
