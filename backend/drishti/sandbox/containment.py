"""Signed, short-lived containment manifests for M3 runtime admission."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ConfigDict, BaseModel, StringConstraints, model_validator


class ContainmentChecks(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host_internet_blocked: Literal[True]
    emulator_internet_blocked: Literal[True]
    emulator_metadata_blocked: Literal[True]
    emulator_vpc_blocked: Literal[True]
    external_ip_absent: Literal[True]
    iap_ssh_functional: Literal[True]
    nested_kvm_functional: Literal[True]
    host_firewall_default_drop: Literal[True]


class ControlPlaneChecks(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    external_ip_absent: Literal[True]
    cloud_nat_absent: Literal[True]
    service_account_absent: Literal[True]
    machine_type_n2_standard_4: Literal[True]
    nested_virtualization_enabled: Literal[True]
    detonator_tag_present: Literal[True]
    disposable_disk: Literal[True]


class ControlPlaneAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.0"] = "1.0"
    instance_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    runtime_image: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    issued_at: datetime
    expires_at: datetime
    checks: ControlPlaneChecks
    public_key: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]

    def canonical_payload(self) -> bytes:
        return json.dumps(self.model_dump(mode="json", exclude={"signature"}), sort_keys=True, separators=(",", ":")).encode()

    def verify(self, trusted_public_key: str, now: datetime | None = None) -> None:
        if self.public_key != trusted_public_key.lower():
            raise ValueError("control-plane attestation signer is not trusted")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key)).verify(bytes.fromhex(self.signature), self.canonical_payload())
        current = now or datetime.now(timezone.utc)
        if current < self.issued_at.astimezone(timezone.utc) or current >= self.expires_at.astimezone(timezone.utc):
            raise ValueError("control-plane attestation is stale")


class ContainmentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.0"] = "1.0"
    instance_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    runtime_image: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    issued_at: datetime
    expires_at: datetime
    checks: ContainmentChecks
    public_key: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def valid_window(self) -> "ContainmentManifest":
        if self.expires_at <= self.issued_at:
            raise ValueError("containment manifest expiry must follow issue time")
        return self

    def canonical_payload(self) -> bytes:
        body = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()

    def verify(self, *, trusted_public_key: str, now: datetime | None = None) -> None:
        if self.public_key != trusted_public_key.lower():
            raise ValueError("containment manifest signer is not trusted")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key)).verify(
            bytes.fromhex(self.signature), self.canonical_payload()
        )
        current = now or datetime.now(timezone.utc)
        issued = self.issued_at.astimezone(timezone.utc)
        expires = self.expires_at.astimezone(timezone.utc)
        if current < issued or current >= expires:
            raise ValueError("containment manifest is missing a current validity window")


def load_and_verify_manifest(
    manifest_path: str | Path,
    trusted_public_key_path: str | Path,
    *,
    now: datetime | None = None,
) -> ContainmentManifest:
    path = Path(manifest_path)
    key_path = Path(trusted_public_key_path)
    if not path.is_file():
        raise ValueError("containment manifest is missing")
    if not key_path.is_file():
        raise ValueError("trusted containment public key is missing")
    manifest = ContainmentManifest.model_validate_json(path.read_text())
    manifest.verify(trusted_public_key=key_path.read_text().strip(), now=now)
    return manifest


def sign_manifest(unsigned: dict, private_key_hex: str) -> ContainmentManifest:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    public = private.public_key().public_bytes_raw().hex()
    candidate = {**unsigned, "public_key": public, "signature": "0" * 128}
    manifest = ContainmentManifest.model_validate(candidate)
    signature = private.sign(manifest.canonical_payload()).hex()
    return ContainmentManifest.model_validate({**candidate, "signature": signature})


def sign_control_plane_attestation(unsigned: dict, private_key_hex: str) -> ControlPlaneAttestation:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    public = private.public_key().public_bytes_raw().hex()
    candidate = {**unsigned, "public_key": public, "signature": "0" * 128}
    attestation = ControlPlaneAttestation.model_validate(candidate)
    signature = private.sign(attestation.canonical_payload()).hex()
    return ControlPlaneAttestation.model_validate({**candidate, "signature": signature})


def load_and_verify_control_plane_attestation(
    path: str | Path, trusted_public_key_path: str | Path, *,
    instance_id: str, runtime_image: str, now: datetime | None = None,
) -> ControlPlaneAttestation:
    artifact = Path(path)
    key = Path(trusted_public_key_path)
    if not artifact.is_file() or not key.is_file():
        raise ValueError("signed control-plane attestation is missing")
    attestation = ControlPlaneAttestation.model_validate_json(artifact.read_text())
    attestation.verify(key.read_text().strip(), now=now)
    if attestation.instance_id != instance_id or attestation.runtime_image != runtime_image:
        raise ValueError("control-plane attestation targets a different runtime")
    return attestation
