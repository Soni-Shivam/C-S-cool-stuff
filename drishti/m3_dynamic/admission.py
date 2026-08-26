"""Runtime admission and signed containment manifests for live detonation."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drishti.contracts.containment import ContainmentChecks, ContainmentManifest
from drishti.m3_dynamic.containment import ContainmentReport

DEFAULT_RUNTIME_MARKER = Path("/opt/drishti/RUNTIME_IMAGE")
DEFAULT_PRIVATE_KEY = Path("/etc/drishti/containment-signing.key")
DEFAULT_PUBLIC_KEY = Path("/etc/drishti/containment-signing.pub")
DEFAULT_MANIFEST = Path("/var/lib/drishti/containment-manifest.json")


class RuntimeAdmissionError(RuntimeError):
    """The current machine is not the sealed GCE detonator."""


def require_sealed_runtime(
    *,
    marker: Path = DEFAULT_RUNTIME_MARKER,
    kvm: Path = Path("/dev/kvm"),
    environment: dict[str, str] | None = None,
) -> str:
    """Return the image id only when immutable runtime markers are all present."""
    env = environment if environment is not None else os.environ
    if env.get("DRISHTI_SEALED_RUNTIME") != "1":
        raise RuntimeAdmissionError("DRISHTI_SEALED_RUNTIME=1 is not set")
    if not marker.is_file():
        raise RuntimeAdmissionError(f"immutable runtime marker is missing: {marker}")
    if not kvm.exists():
        raise RuntimeAdmissionError("/dev/kvm is unavailable; refusing local execution")
    image = marker.read_text(encoding="utf-8").strip()
    if not image:
        raise RuntimeAdmissionError("runtime image marker is empty")
    return image


def checks_from_report(
    report: ContainmentReport, *, kvm_ok: bool, firewall_default_drop: bool
) -> ContainmentChecks:
    """Convert verified probes into the strict all-true signed contract."""
    if not report.verified or not report.probe_trustworthy:
        raise RuntimeAdmissionError("containment report is not verified and trustworthy")
    reachability = {(result.host, result.port): result.reachable for result in report.results}

    # Each field is `Literal[True]` on the contract, so a false check cannot be signed.
    # They are evaluated and named HERE rather than passed straight in, so a failure
    # says which containment property failed instead of surfacing a pydantic type
    # error about a literal — the difference between an operator diagnosing a firewall
    # rule in a minute and reading a stack trace.
    #
    # `.get(..., True)` defaults to REACHABLE for a destination the probe never tested:
    # an untested destination must count as not-blocked, never as safe.
    checks: dict[str, bool] = {
        "emulator_internet_blocked": not any(
            reachability.get(destination, True)
            for destination in (("8.8.8.8", 53), ("1.1.1.1", 443))
        ),
        "emulator_metadata_blocked": not reachability.get(("169.254.169.254", 80), True),
        "emulator_vpc_blocked": not reachability.get(("10.0.0.1", 22), True),
        "nested_kvm_functional": kvm_ok,
        "host_firewall_default_drop": firewall_default_drop,
    }
    failed = sorted(name for name, ok in checks.items() if not ok)
    if failed:
        raise RuntimeAdmissionError(f"containment checks failed: {', '.join(failed)}")

    return ContainmentChecks(
        probe_trustworthy=True,
        emulator_internet_blocked=True,
        emulator_metadata_blocked=True,
        emulator_vpc_blocked=True,
        nested_kvm_functional=True,
        host_firewall_default_drop=True,
    )


def sign_manifest(
    *,
    instance_id: str,
    runtime_image: str,
    checks: ContainmentChecks,
    private_key_hex: str,
    ttl_minutes: int = 10,
    issued_at: datetime | None = None,
) -> ContainmentManifest:
    """Sign a short-lived manifest with the image-local Ed25519 key."""
    if not 1 <= ttl_minutes <= 30:
        raise ValueError("containment manifest TTL must be between 1 and 30 minutes")
    issued = issued_at or datetime.now(UTC)
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex.strip()))
    public = private.public_key().public_bytes_raw().hex()
    candidate = {
        "instance_id": instance_id,
        "runtime_image": runtime_image,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=ttl_minutes)).isoformat(),
        "checks": checks,
        "public_key": public,
        "signature": "0" * 128,
    }
    unsigned = ContainmentManifest.model_validate(candidate)
    return ContainmentManifest.model_validate(
        {**candidate, "signature": private.sign(unsigned.canonical_payload()).hex()}
    )


def write_manifest(
    manifest: ContainmentManifest,
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    public_key_path: Path = DEFAULT_PUBLIC_KEY,
) -> str:
    """Atomically write the manifest and return the exact file SHA-256."""
    payload = manifest.model_dump_json(indent=2).encode()
    manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    temporary.write_bytes(payload)
    os.chmod(temporary, 0o600)
    temporary.replace(manifest_path)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_text(manifest.public_key + "\n", encoding="utf-8")
    os.chmod(public_key_path, 0o644)
    return hashlib.sha256(payload).hexdigest()


def load_verified_manifest(
    manifest_path: Path = DEFAULT_MANIFEST,
    public_key_path: Path = DEFAULT_PUBLIC_KEY,
    *,
    now: datetime | None = None,
) -> tuple[ContainmentManifest, str]:
    """Load, verify, and return a manifest plus its exact file digest."""
    if not manifest_path.is_file() or not public_key_path.is_file():
        raise RuntimeAdmissionError("signed containment admission is missing")
    payload = manifest_path.read_bytes()
    manifest = ContainmentManifest.model_validate_json(payload)
    manifest.verify(public_key_path.read_text(encoding="utf-8"), now=now)
    return manifest, hashlib.sha256(payload).hexdigest()


def manifest_summary(manifest: ContainmentManifest, digest: str) -> str:
    """Produce stable machine-readable output for the lab command."""
    return json.dumps(
        {
            "containment": "verified",
            "instance_id": manifest.instance_id,
            "runtime_image": manifest.runtime_image,
            "expires_at": manifest.expires_at,
            "manifest_sha256": digest,
        },
        sort_keys=True,
    )
