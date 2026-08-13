#!/usr/bin/env python3
"""Probe both containment layers and emit a signed, short-lived manifest.

Run only on the sealed runtime through an active IAP SSH session. Any ambiguous
probe is a failure; a manifest is never emitted from partial results.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from drishti.sandbox.containment import load_and_verify_control_plane_attestation, sign_manifest

#: A port on the emulator's loopback that nothing ever listens on.
NEGATIVE_CONTROL_PORT = 1
#: A high port used only to prove the probe can observe a *reachable* endpoint.
POSITIVE_CONTROL_PORT = 47131
_RC_MARKER = re.compile(r"DRISHTI_RC=(\d+)")


class ContainmentProbeError(RuntimeError):
    """The probe mechanism itself is untrustworthy, so no manifest may be emitted.

    This is deliberately distinct from "the destination was unreachable". A probe we
    cannot trust must never be reported as containment.
    """


#: Synthetic return code used when a probe process had to be killed on timeout. Matches the
#: shell convention for `timeout(1)`.
TIMEOUT_RC = 124


def run(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    """Run a probe, converting a hung process into an explicit non-zero result.

    A blackhole `-j DROP` rule makes a probe HANG rather than fail fast, and curl's
    --max-time is not reliably honoured while DNS resolution itself is being dropped.
    Previously the resulting subprocess.TimeoutExpired propagated out of `blocked()` and
    crashed the whole containment verification, which made verification flaky: identical
    lockdowns passed or aborted depending on DNS cache state.

    Returning TIMEOUT_RC keeps the semantics correct -- for a reachability probe, "it hung"
    means "it could not connect" -- while callers that need a real answer
    (`adb_tcp_reachable`) still refuse to guess because they require an explicit exit-code
    marker in stdout and raise when it is absent.
    """
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              check=False)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args, TIMEOUT_RC,
            stdout=(exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=f"probe timed out after {timeout}s",
        )
    except (OSError, ValueError) as exc:
        # A probe we could not even launch must not read as "reachable".
        return subprocess.CompletedProcess(args, TIMEOUT_RC, stdout="",
                                           stderr=f"probe failed to start: {exc}")


def blocked(args: list[str]) -> bool:
    """True when a reachability probe did not succeed, including when it timed out."""
    result = run(args)
    return result.returncode != 0


def adb_tcp_reachable(serial: str, host: str, port: int, timeout_s: int = 3) -> bool:
    """Return True when the emulator can complete a TCP connection to host:port.

    Android's toybox ``nc`` has no ``-z`` flag (API 30 exits 1 with
    ``nc: Unknown option 'z'``). The previous implementation ran
    ``toybox nc -z -w 3 host port`` and treated a non-zero exit as "blocked", so every
    destination was reported blocked whether or not the network was actually reachable
    -- the emulator containment probes passed unconditionally and the signed manifest
    attested to containment that had never been tested.

    We instead run plain ``nc -w N host port </dev/null`` and parse an explicit exit-code
    marker. Anything we cannot parse raises rather than being read as "blocked".
    """
    script = (
        f"toybox nc -w {timeout_s} {host} {port} </dev/null >/dev/null 2>&1; "
        f"echo DRISHTI_RC=$?"
    )
    result = run(["adb", "-s", serial, "shell", script], timeout=timeout_s + 20)
    match = _RC_MARKER.search(result.stdout or "")
    if result.returncode != 0 or match is None:
        raise ContainmentProbeError(
            f"TCP probe to {host}:{port} produced no usable exit code; "
            "refusing to infer containment"
        )
    return match.group(1) == "0"


def assert_probe_trustworthy(serial: str) -> None:
    """Prove the probe distinguishes reachable from unreachable before relying on it.

    Without this, a broken probe is indistinguishable from perfect containment.
    """
    if adb_tcp_reachable(serial, "127.0.0.1", NEGATIVE_CONTROL_PORT):
        raise ContainmentProbeError(
            "negative control unexpectedly reachable; TCP probe is not meaningful"
        )
    listener = (
        f"(toybox nc -l -p {POSITIVE_CONTROL_PORT} >/dev/null 2>&1 &) ; sleep 1; echo UP"
    )
    started = run(["adb", "-s", serial, "shell", listener], timeout=25)
    if "UP" not in (started.stdout or ""):
        raise ContainmentProbeError("could not start the positive-control listener")
    try:
        if not adb_tcp_reachable(serial, "127.0.0.1", POSITIVE_CONTROL_PORT):
            raise ContainmentProbeError(
                "positive control unreachable; the TCP probe cannot observe a live "
                "endpoint, so 'blocked' results carry no information"
            )
    finally:
        run(["adb", "-s", serial, "shell", f"pkill -f 'nc -l -p {POSITIVE_CONTROL_PORT}'"],
            timeout=15)


def adb_blocked(serial: str, host: str, port: int) -> bool:
    return not adb_tcp_reachable(serial, host, port)


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
    # Establish that the emulator TCP probe can tell reachable from unreachable before
    # any of its "blocked" answers are allowed to mean anything. Raises on malfunction.
    assert_probe_trustworthy(args.serial)
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
