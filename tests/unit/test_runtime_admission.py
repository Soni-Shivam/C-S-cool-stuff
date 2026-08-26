from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drishti.contracts.containment import ContainmentChecks, ContainmentManifest
from drishti.m3_dynamic.admission import (
    RuntimeAdmissionError,
    load_verified_manifest,
    require_sealed_runtime,
    sign_manifest,
    write_manifest,
)


def _checks() -> ContainmentChecks:
    return ContainmentChecks(
        probe_trustworthy=True,
        emulator_internet_blocked=True,
        emulator_metadata_blocked=True,
        emulator_vpc_blocked=True,
        nested_kvm_functional=True,
        host_firewall_default_drop=True,
    )


def test_runtime_gate_refuses_a_developer_machine(tmp_path: Path) -> None:
    marker = tmp_path / "RUNTIME_IMAGE"
    marker.write_text("drishti-emulator-v3")
    kvm = tmp_path / "kvm"
    kvm.touch()
    with pytest.raises(RuntimeAdmissionError, match="SEALED_RUNTIME"):
        require_sealed_runtime(marker=marker, kvm=kvm, environment={})


def test_runtime_gate_requires_all_three_independent_markers(tmp_path: Path) -> None:
    marker = tmp_path / "RUNTIME_IMAGE"
    marker.write_text("drishti-emulator-v3")
    kvm = tmp_path / "kvm"
    kvm.touch()
    assert (
        require_sealed_runtime(marker=marker, kvm=kvm, environment={"DRISHTI_SEALED_RUNTIME": "1"})
        == "drishti-emulator-v3"
    )


def test_manifest_signature_and_exact_file_digest_are_verified(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    issued = datetime.now(UTC)
    manifest = sign_manifest(
        instance_id="instance-123",
        runtime_image="drishti-emulator-v3",
        checks=_checks(),
        private_key_hex=private,
        issued_at=issued,
    )
    manifest_path = tmp_path / "manifest.json"
    public_path = tmp_path / "manifest.pub"
    digest = write_manifest(manifest, manifest_path=manifest_path, public_key_path=public_path)
    revived, revived_digest = load_verified_manifest(
        manifest_path, public_path, now=issued + timedelta(minutes=1)
    )
    assert revived.instance_id == "instance-123"
    assert revived_digest == digest


def test_tampered_or_expired_manifest_is_rejected(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    issued = datetime.now(UTC)
    manifest = sign_manifest(
        instance_id="instance-123",
        runtime_image="drishti-emulator-v3",
        checks=_checks(),
        private_key_hex=private,
        issued_at=issued,
        ttl_minutes=1,
    )
    with pytest.raises(ValueError, match="validity window"):
        manifest.verify(manifest.public_key, now=issued + timedelta(minutes=2))

    tampered = ContainmentManifest.model_validate(
        {**manifest.model_dump(), "runtime_image": "untrusted-image"}
    )
    with pytest.raises(InvalidSignature):
        tampered.verify(manifest.public_key, now=issued)
