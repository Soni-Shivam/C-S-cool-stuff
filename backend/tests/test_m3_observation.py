import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from drishti.sandbox.containment import load_and_verify_manifest, sign_manifest
from drishti.sandbox.observation import ObservationArtifact
from drishti.sandbox.real import result_from_payload
from drishti.sandbox.redaction import redact_text


def artifact_payload(sha="a" * 64):
    return {
        "schema_version": "1.0", "sha256": sha, "package": "in.drishti.fixture.m3",
        "simulated": False, "outcome": "completed",
        "started_at": "2026-08-11T00:00:00Z", "finished_at": "2026-08-11T00:00:10Z", "duration_s": 10.0,
        "metadata": {"harness_version": "m3-test", "hook_version": "hooks-test", "emulator_image": "image-test",
                     "emulator_serial": "emulator-5554", "avd_name": "drishti", "containment_manifest_sha256": "b" * 64,
                     "containment_verified": True, "containment_verified_at": "2026-08-11T00:00:00Z"},
        "snapshot": {"name": "clean", "before_restore": "passed", "after_restore": "passed", "package_absent_after": True},
        "observations": [{"type": "observation", "technique": "Clipboard read", "mitre": "T1414",
                          "detail": "[REDACTED:CLIPBOARD]", "source_hook": "ClipboardManager.getPrimaryClip",
                          "redacted": True, "occurred_at": "2026-08-11T00:00:05Z"}],
        "failures": [], "diagnostics": [], "mitre_observed": ["T1414"],
    }


def test_strict_artifact_requires_sha_metadata_and_rejects_extra_fields():
    payload = artifact_payload()
    assert ObservationArtifact.model_validate_json(json.dumps(payload)).safe_for_ingestion
    with pytest.raises(ValidationError):
        ObservationArtifact.model_validate_json(json.dumps({**payload, "unexpected": True}))
    with pytest.raises(ValidationError):
        ObservationArtifact.model_validate_json(json.dumps({**payload, "sha256": "bad"}))


def test_sha_mismatch_and_failed_snapshot_are_rejected_for_ingestion():
    with pytest.raises(ValueError, match="SHA-256"):
        result_from_payload(artifact_payload(), expected_sha256="c" * 64)
    payload = artifact_payload()
    payload["snapshot"] = {**payload["snapshot"], "after_restore": "failed", "package_absent_after": False}
    with pytest.raises(ValueError, match="acceptance gates"):
        result_from_payload(payload, expected_sha256="a" * 64)


def test_empty_success_must_be_explicitly_inconclusive():
    payload = artifact_payload()
    payload.update(observations=[], mitre_observed=[])
    with pytest.raises(ValidationError, match="inconclusive"):
        ObservationArtifact.model_validate_json(json.dumps(payload))
    payload["outcome"] = "inconclusive"
    assert ObservationArtifact.model_validate_json(json.dumps(payload)).outcome == "inconclusive"


def test_redaction_removes_otp_credentials_and_tokens():
    value = redact_text("OTP 123456 password=hunter2 bearer abcdefghijklmnop")
    assert "123456" not in value and "hunter2" not in value and "abcdefghijklmnop" not in value
    assert "[REDACTED:OTP]" in value and "[REDACTED:CREDENTIAL]" in value and "[REDACTED:TOKEN]" in value


def test_signed_containment_manifest_rejects_stale_and_wrong_signer(tmp_path):
    now = datetime.now(timezone.utc)
    private = Ed25519PrivateKey.generate()
    private_hex = private.private_bytes_raw().hex()
    unsigned = {
        "instance_id": "runtime-1", "runtime_image": "drishti-image-1",
        "issued_at": now - timedelta(minutes=1), "expires_at": now + timedelta(minutes=1),
        "checks": {name: True for name in (
            "host_internet_blocked", "emulator_internet_blocked", "emulator_metadata_blocked",
            "emulator_vpc_blocked", "external_ip_absent", "iap_ssh_functional",
            "nested_kvm_functional", "host_firewall_default_drop")},
    }
    manifest = sign_manifest(unsigned, private_hex)
    path = tmp_path / "manifest.json"
    key = tmp_path / "trusted.pub"
    path.write_text(manifest.model_dump_json())
    key.write_text(manifest.public_key)
    assert load_and_verify_manifest(path, key, now=now).instance_id == "runtime-1"
    with pytest.raises(ValueError, match="validity"):
        load_and_verify_manifest(path, key, now=now + timedelta(minutes=2))
    key.write_text(Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
    with pytest.raises(ValueError, match="not trusted"):
        load_and_verify_manifest(path, key, now=now)
