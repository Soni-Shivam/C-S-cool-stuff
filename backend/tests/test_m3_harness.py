import subprocess
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drishti.sandbox.containment import sign_manifest
from scripts import dynamic_analyze


class FakeProcess:
    def __init__(self, *_args, **_kwargs): self.returncode = None
    def poll(self): return self.returncode
    def terminate(self): self.returncode = -15
    def kill(self): self.returncode = -9
    def wait(self, timeout=None): self.returncode = self.returncode or 0; return self.returncode


def containment_files(tmp_path):
    now = datetime.now(timezone.utc)
    private = Ed25519PrivateKey.generate()
    manifest = sign_manifest({
        "instance_id": "runtime-test", "runtime_image": "image-test",
        "issued_at": now - timedelta(minutes=1), "expires_at": now + timedelta(minutes=5),
        "checks": {name: True for name in (
            "host_internet_blocked", "emulator_internet_blocked", "emulator_metadata_blocked",
            "emulator_vpc_blocked", "external_ip_absent", "iap_ssh_functional",
            "nested_kvm_functional", "host_firewall_default_drop")},
    }, private.private_bytes_raw().hex())
    path, key = tmp_path / "manifest.json", tmp_path / "trusted.pub"
    path.write_text(manifest.model_dump_json())
    key.write_text(manifest.public_key)
    return path, key


def make_harness(tmp_path, monkeypatch, collector, failed_snapshot_number=None):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"fixture")
    manifest, key = containment_files(tmp_path)
    calls = []
    snapshot_calls = 0

    def command(args, timeout=120):
        nonlocal snapshot_calls
        calls.append(args)
        if args[:3] == ["aapt", "dump", "badging"]:
            return subprocess.CompletedProcess(args, 0, "package: name='in.drishti.fixture.m3'", "")
        if "snapshot" in args:
            snapshot_calls += 1
            if snapshot_calls == failed_snapshot_number:
                return subprocess.CompletedProcess(args, 1, "KO", "snapshot failed")
        if "sys.boot_completed" in args:
            return subprocess.CompletedProcess(args, 0, "1\n", "")
        if "init.svc.bootanim" in args:
            return subprocess.CompletedProcess(args, 0, "stopped\n", "")
        if "install" in args:
            return subprocess.CompletedProcess(args, 0, "Success\n", "")
        if "pm" in args and "path" in args:
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(dynamic_analyze.subprocess, "Popen", FakeProcess)
    config = dynamic_analyze.HarnessConfig(
        apk=apk, output=tmp_path / "artifact.json", duration_s=1, snapshot="clean",
        avd_name="drishti", emulator_serial="emulator-5554", emulator_image="image-test",
        manifest=manifest, trusted_public_key=key,
    )
    return dynamic_analyze.DynamicHarness(config, command=command, sleep=lambda _: None, collector=collector), calls


def test_crash_is_explicit_and_cleanup_and_after_restore_still_run(tmp_path, monkeypatch):
    def crash(*_):
        raise dynamic_analyze.HarnessFailure("sample_crashed", "detonation", "SIGSEGV tombstone")
    harness, calls = make_harness(tmp_path, monkeypatch, crash)
    artifact, code = harness.run()
    assert code == 2 and artifact.outcome == "crashed"
    assert any(f.code == "sample_crashed" for f in artifact.failures)
    assert artifact.snapshot.before_restore == "passed" and artifact.snapshot.after_restore == "passed"
    assert any("uninstall" in call for call in calls)


def test_timeout_is_explicit_and_not_empty_success(tmp_path, monkeypatch):
    def timeout(*_): raise subprocess.TimeoutExpired("frida", 1)
    harness, _ = make_harness(tmp_path, monkeypatch, timeout)
    artifact, code = harness.run()
    assert code == 2 and artifact.outcome == "timeout"
    assert [failure.code for failure in artifact.failures] == ["timeout"]


@pytest.mark.parametrize("failed_number", [1, 2])
def test_failed_snapshot_recovery_aborts_acceptance(tmp_path, monkeypatch, failed_number):
    harness, calls = make_harness(tmp_path, monkeypatch, lambda *_: ([], []), failed_snapshot_number=failed_number)
    artifact, code = harness.run()
    assert code == 2 and artifact.outcome == "failed"
    assert any(f.code == "snapshot_restore_failed" for f in artifact.failures)
    assert sum("snapshot" in call for call in calls) == 2


def test_missing_containment_manifest_fails_before_install(tmp_path, monkeypatch):
    harness, calls = make_harness(tmp_path, monkeypatch, lambda *_: ([], []))
    harness.config.manifest = tmp_path / "missing.json"
    artifact, code = harness.run()
    assert code == 2 and not artifact.metadata.containment_verified
    assert not any("install" in call for call in calls)


def test_vetted_malware_requires_exact_fresh_pilot_authorization(tmp_path):
    now = datetime.now(timezone.utc)
    path = tmp_path / "pilot.json"
    payload = {
        "approval_id": "review-1", "sha256": "a" * 64, "reviewed_by": "security-reviewer",
        "runtime_image": "image-immutable-1", "approved_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(), "max_duration_s": 120,
    }
    path.write_text(json.dumps(payload))
    approved = dynamic_analyze.require_pilot_authorization(
        path, apk_sha256="a" * 64, runtime_image="image-immutable-1", duration_s=120, now=now)
    assert approved.approval_id == "review-1"
    with pytest.raises(ValueError, match="SHA-256"):
        dynamic_analyze.require_pilot_authorization(
            path, apk_sha256="b" * 64, runtime_image="image-immutable-1", duration_s=120, now=now)
    with pytest.raises(ValueError, match="duration"):
        dynamic_analyze.require_pilot_authorization(
            path, apk_sha256="a" * 64, runtime_image="image-immutable-1", duration_s=121, now=now)
