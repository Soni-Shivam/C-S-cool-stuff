from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drishti.contracts.containment import ContainmentChecks
from drishti.m3_dynamic.admission import RuntimeAdmissionError, sign_manifest, write_manifest
from drishti.m3_dynamic.harness import DynamicHarness, HarnessConfig


def _admission_files(tmp_path: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    checks = ContainmentChecks(
        probe_trustworthy=True,
        emulator_internet_blocked=True,
        emulator_metadata_blocked=True,
        emulator_vpc_blocked=True,
        nested_kvm_functional=True,
        host_firewall_default_drop=True,
    )
    manifest = sign_manifest(
        instance_id="instance-123",
        runtime_image="drishti-emulator-v3",
        checks=checks,
        private_key_hex=private,
        issued_at=datetime.now(UTC),
    )
    manifest_path = tmp_path / "manifest.json"
    public_path = tmp_path / "manifest.pub"
    write_manifest(manifest, manifest_path=manifest_path, public_key_path=public_path)
    return manifest_path, public_path


def test_admission_failure_reaches_no_command_surface(tmp_path: Path) -> None:
    apk = tmp_path / "canary.apk"
    apk.write_bytes(b"inert-canary")
    calls: list[list[str]] = []

    def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    harness = DynamicHarness(
        HarnessConfig(apk=apk, output=tmp_path / "out.json"),
        command=command,
        admission=lambda: (_ for _ in ()).throw(RuntimeAdmissionError("not sealed")),
    )
    with pytest.raises(RuntimeAdmissionError, match="not sealed"):
        harness.run()
    assert calls == []


def test_snapshot_precedes_install_and_cleanup_restores_again(tmp_path: Path) -> None:
    apk = tmp_path / "canary.apk"
    apk.write_bytes(b"inert-canary")
    manifest, public = _admission_files(tmp_path)
    calls: list[list[str]] = []

    def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        joined = " ".join(args)
        if joined.startswith("aapt dump badging"):
            return subprocess.CompletedProcess(args, 0, "package: name='in.drishti.canary'", "")
        if " install " in f" {joined} ":
            return subprocess.CompletedProcess(args, 0, "Success\n", "")
        if " shell pm path " in f" {joined} ":
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "OK\n", "")

    artifact = DynamicHarness(
        HarnessConfig(
            apk=apk,
            output=tmp_path / "out.json",
            manifest=manifest,
            public_key=public,
        ),
        command=command,
        admission=lambda: "drishti-emulator-v3",
        collector=lambda *_args: (
            [
                {
                    "type": "observation",
                    "technique": "Software discovery",
                    "mitre": "T1418",
                    "detail": "queried package=<redacted>",
                    "source_hook": "PackageManager.getPackageInfo",
                    "redacted": True,
                    "occurred_at": "2026-08-25T00:00:00Z",
                }
            ],
            [],
        ),
    ).run()

    operations = [" ".join(call) for call in calls]
    restores = [index for index, value in enumerate(operations) if "snapshot load clean" in value]
    install = next(index for index, value in enumerate(operations) if " install " in f" {value} ")
    assert len(restores) == 2
    assert restores[0] < install < restores[1]
    assert artifact.safe_for_ingestion is True
