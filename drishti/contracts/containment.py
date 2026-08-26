"""Signed containment admission contract for the sealed detonator."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ConfigDict, StringConstraints, model_validator

from drishti.contracts.base import DrishtiModel


class ContainmentChecks(DrishtiModel):
    """Assertions that must all be true before a manifest is signable."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    probe_trustworthy: Literal[True]
    emulator_internet_blocked: Literal[True]
    emulator_metadata_blocked: Literal[True]
    emulator_vpc_blocked: Literal[True]
    nested_kvm_functional: Literal[True]
    host_firewall_default_drop: Literal[True]


class ContainmentManifest(DrishtiModel):
    """Short-lived signed proof required by the detonation harness."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    instance_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    runtime_image: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    issued_at: Annotated[str, StringConstraints(min_length=20, max_length=40)]
    expires_at: Annotated[str, StringConstraints(min_length=20, max_length=40)]
    checks: ContainmentChecks
    public_key: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def valid_window(self) -> ContainmentManifest:
        if self._parse_time(self.expires_at) <= self._parse_time(self.issued_at):
            raise ValueError("containment manifest expiry must follow issue time")
        return self

    @staticmethod
    def _parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)

    def canonical_payload(self) -> bytes:
        """Return deterministic bytes covered by the signature."""
        body = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def verify(self, trusted_public_key: str, now: datetime | None = None) -> None:
        """Verify signer and current validity window, raising on any mismatch."""
        if self.public_key != trusted_public_key.strip().lower():
            raise ValueError("containment manifest signer is not trusted")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key)).verify(
            bytes.fromhex(self.signature), self.canonical_payload()
        )
        current = now or datetime.now(UTC)
        if current < self._parse_time(self.issued_at) or current >= self._parse_time(
            self.expires_at
        ):
            raise ValueError("containment manifest is outside its validity window")
