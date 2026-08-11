"""Strict wire contract for the only artifact allowed off the detonator."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from drishti.sandbox.redaction import contains_sensitive_text


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ObservationEvent(StrictModel):
    type: Literal["observation"] = "observation"
    technique: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    mitre: Annotated[str, StringConstraints(pattern=r"^T\d{4}(?:\.\d{3})?$")]
    detail: Annotated[str, StringConstraints(max_length=512)] = ""
    source_hook: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    redacted: Literal[True] = True
    occurred_at: datetime

    @model_validator(mode="after")
    def reject_raw_secrets(self) -> "ObservationEvent":
        if contains_sensitive_text(self.detail):
            raise ValueError("observation detail contains unredacted sensitive text")
        return self


class FailureRecord(StrictModel):
    code: Literal[
        "containment_failed", "snapshot_restore_failed", "install_failed",
        "frida_failed", "hook_error", "sample_crashed", "timeout",
        "cleanup_failed", "emulator_unhealthy", "internal_error",
    ]
    stage: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    message: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    occurred_at: datetime


class SnapshotLifecycle(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    before_restore: Literal["passed", "failed", "not_run"]
    after_restore: Literal["passed", "failed", "not_run"]
    package_absent_after: bool = False


class HarnessMetadata(StrictModel):
    harness_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    hook_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    emulator_image: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    emulator_serial: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    avd_name: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    sample_kind: Literal["inert_fixture", "benign", "vetted_malware"] = "inert_fixture"
    containment_manifest_sha256: Sha256 | None = None
    containment_verified: bool
    containment_verified_at: datetime | None = None


class ObservationArtifact(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    sha256: Sha256
    package: Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")] | None
    simulated: Literal[False] = False
    outcome: Literal["completed", "inconclusive", "failed", "timeout", "crashed"]
    started_at: datetime
    finished_at: datetime
    duration_s: Annotated[float, Field(ge=0, le=3600)]
    metadata: HarnessMetadata
    snapshot: SnapshotLifecycle
    observations: list[ObservationEvent] = Field(default_factory=list, max_length=10000)
    failures: list[FailureRecord] = Field(default_factory=list, max_length=1000)
    diagnostics: list[Annotated[str, StringConstraints(max_length=512)]] = Field(default_factory=list, max_length=500)
    mitre_observed: list[Annotated[str, StringConstraints(pattern=r"^T\d{4}(?:\.\d{3})?$")]] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_outcome(self) -> "ObservationArtifact":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        if self.outcome == "completed" and not self.observations:
            raise ValueError("empty completed output must be marked inconclusive")
        if self.outcome == "inconclusive" and self.observations:
            raise ValueError("an artifact with observations is not inconclusive")
        if self.outcome in {"failed", "timeout", "crashed"} and not self.failures:
            raise ValueError("failure outcome requires an explicit failure record")
        observed = sorted({event.mitre for event in self.observations})
        if sorted(set(self.mitre_observed)) != observed:
            raise ValueError("mitre_observed must exactly match observation events")
        exported_text = self.diagnostics + [failure.message for failure in self.failures]
        if any(contains_sensitive_text(value) for value in exported_text):
            raise ValueError("artifact diagnostics contain unredacted sensitive text")
        return self

    @property
    def safe_for_ingestion(self) -> bool:
        return (
            self.outcome in {"completed", "inconclusive"}
            and self.package is not None
            and self.metadata.containment_verified
            and self.metadata.containment_manifest_sha256 is not None
            and self.snapshot.before_restore == "passed"
            and self.snapshot.after_restore == "passed"
            and self.snapshot.package_absent_after
        )
