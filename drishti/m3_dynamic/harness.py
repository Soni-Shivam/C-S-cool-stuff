"""Spawn-gated Frida harness that runs only on the sealed GCE detonator."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from drishti.contracts.dynamic_trace import (
    FailureRecord,
    HarnessMetadata,
    ObservationArtifact,
    ObservationEvent,
    SnapshotLifecycle,
)
from drishti.m3_dynamic.admission import (
    DEFAULT_MANIFEST,
    DEFAULT_PUBLIC_KEY,
    load_verified_manifest,
    require_sealed_runtime,
)
from drishti.m3_dynamic.redaction import redact_text

HARNESS_VERSION = "m3-harness-2.0.0"
HOOK_VERSION = "m3-hooks-2.0.0"
DEFAULT_HOOKS = Path("/opt/drishti/harness/frida_hooks.js")
Command = Callable[..., subprocess.CompletedProcess[str]]
Collector = Callable[[str, int, Path, str], tuple[list[dict[str, Any]], list[str]]]


def utcnow() -> str:
    """Return a UTC ISO timestamp for the VM wire artifact."""
    return datetime.now(UTC).isoformat()


def sha256_file(path: Path) -> str:
    """Hash an APK without executing or extracting it."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_command(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run one bounded harness command."""
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


class HarnessError(RuntimeError):
    """A classified failure suitable for the strict wire artifact."""

    def __init__(self, code: str, stage: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage


@dataclass(frozen=True)
class HarnessConfig:
    """One bounded detonation request."""

    apk: Path
    output: Path
    duration_s: int = 120
    snapshot: str = "clean"
    avd_name: str = "drishti"
    serial: str = "emulator-5554"
    hooks: Path = DEFAULT_HOOKS
    manifest: Path = DEFAULT_MANIFEST
    public_key: Path = DEFAULT_PUBLIC_KEY
    sample_kind: Literal["inert_fixture", "benign", "vetted_malware"] = "inert_fixture"


class DynamicHarness:
    """Detonate one admitted APK and always restore the immutable snapshot."""

    _UNSUPPORTED = (
        "INSTALL_FAILED_NO_MATCHING_ABIS",
        "INSTALL_FAILED_OLDER_SDK",
        "INSTALL_FAILED_DEPRECATED_SDK_VERSION",
        "INSTALL_PARSE_FAILED_NO_CERTIFICATES",
        "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED",
    )

    def __init__(
        self,
        config: HarnessConfig,
        *,
        command: Command = run_command,
        collector: Collector | None = None,
        admission: Callable[[], str] = require_sealed_runtime,
    ) -> None:
        self.config = config
        self.command = command
        self.collector = collector or collect_frida
        self.admission = admission

    def adb(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return self.command(["adb", "-s", self.config.serial, *args], timeout=timeout)

    def restore_snapshot(self) -> None:
        result = self.adb("emu", "avd", "snapshot", "load", self.config.snapshot, timeout=180)
        output = f"{result.stdout}\n{result.stderr}"
        if result.returncode or re.search(r"\bKO\b", output):
            raise HarnessError(
                "snapshot_restore_failed", "snapshot", redact_text(output or "restore failed")
            )
        ready = self.adb("wait-for-device", timeout=180)
        if ready.returncode:
            raise HarnessError("emulator_unhealthy", "snapshot", "adb did not recover")

    def package_name(self) -> str:
        result = self.command(["aapt", "dump", "badging", str(self.config.apk)], timeout=120)
        match = re.search(r"package: name='([^']+)'", result.stdout or "")
        if result.returncode or not match:
            raise HarnessError("internal_error", "identify", "aapt could not identify package")
        return match.group(1)

    def install(self) -> None:
        result = self.adb("install", "-r", "-g", str(self.config.apk), timeout=300)
        output = f"{result.stdout}\n{result.stderr}"[:400]
        if result.returncode == 0 and "Success" in (result.stdout or ""):
            return
        code = (
            "install_unsupported"
            if any(item in output for item in self._UNSUPPORTED)
            else "install_failed"
        )
        raise HarnessError(code, "install", redact_text(output or "APK installation failed"))

    def package_absent(self, package: str) -> bool:
        result = self.adb("shell", "pm", "path", package, timeout=30)
        return result.returncode != 0 or not result.stdout.strip()

    def run(self) -> ObservationArtifact:
        """Execute with admission, provenance, and cleanup enforced in code order."""
        started = utcnow()
        image = self.admission()
        manifest, manifest_sha = load_verified_manifest(
            self.config.manifest, self.config.public_key
        )
        if manifest.runtime_image != image:
            raise HarnessError("containment_failed", "admission", "manifest targets another image")

        package: str | None = None
        observations: list[ObservationEvent] = []
        failures: list[FailureRecord] = []
        before: Literal["passed", "failed", "not_run"] = "not_run"
        after: Literal["passed", "failed", "not_run"] = "not_run"
        absent = False
        outcome: Literal["completed", "inconclusive", "failed", "timeout", "crashed"] = "failed"
        try:
            self.restore_snapshot()
            before = "passed"
            package = self.package_name()
            self.install()
            raw, hook_errors = self.collector(
                package, self.config.duration_s, self.config.hooks, self.config.serial
            )
            observations = [ObservationEvent.model_validate(event) for event in raw]
            failures.extend(
                FailureRecord(
                    code="hook_error",
                    stage="instrumentation",
                    message=redact_text(error),
                    occurred_at=utcnow(),
                )
                for error in hook_errors
            )
            outcome = "completed" if observations else "inconclusive"
        except subprocess.TimeoutExpired as exc:
            outcome = "timeout"
            failures.append(
                FailureRecord(
                    code="timeout",
                    stage="subprocess",
                    message=redact_text(exc),
                    occurred_at=utcnow(),
                )
            )
        except HarnessError as exc:
            failures.append(
                FailureRecord(
                    code=exc.code, stage=exc.stage, message=redact_text(exc), occurred_at=utcnow()
                )
            )
        except Exception as exc:  # hostile inputs and external tools degrade into evidence
            failures.append(
                FailureRecord(
                    code="internal_error",
                    stage="harness",
                    message=redact_text(f"{type(exc).__name__}: {exc}"),
                    occurred_at=utcnow(),
                )
            )
        finally:
            if package:
                self.adb("uninstall", package, timeout=120)
            try:
                self.restore_snapshot()
                after = "passed"
                absent = bool(package) and self.package_absent(package)
            except Exception as exc:
                after = "failed"
                outcome = "failed"
                failures.append(
                    FailureRecord(
                        code="snapshot_restore_failed",
                        stage="snapshot_after",
                        message=redact_text(exc),
                        occurred_at=utcnow(),
                    )
                )

        artifact = ObservationArtifact(
            sha256=sha256_file(self.config.apk),
            package=package,
            outcome=outcome,
            observations=tuple(observations),
            failures=tuple(failures),
            snapshot=SnapshotLifecycle(
                name=self.config.snapshot,
                before_restore=before,
                after_restore=after,
                package_absent_after=absent,
            ),
            metadata=HarnessMetadata(
                harness_version=HARNESS_VERSION,
                hook_version=HOOK_VERSION,
                emulator_image=image,
                emulator_serial=self.config.serial,
                avd_name=self.config.avd_name,
                sample_kind=self.config.sample_kind,
                containment_manifest_sha256=manifest_sha,
                containment_verified=True,
                containment_verified_at=manifest.issued_at,
            ),
            started_at=started,
            finished_at=utcnow(),
            diagnostics=(f"containment:{manifest.instance_id}",),
            mitre_observed=tuple(sorted({event.mitre for event in observations})),
        )
        self.config.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.config.output.with_suffix(self.config.output.suffix + ".tmp")
        temporary.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.config.output)
        return artifact


def collect_frida(
    package: str, duration_s: int, hooks: Path, serial: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Spawn the app under Frida so startup behaviour cannot precede instrumentation."""
    import frida

    events: list[dict[str, Any]] = []
    errors: list[str] = []
    device = frida.get_usb_device(timeout=30)
    pid = device.spawn([package])
    session = device.attach(pid)
    script = session.create_script(hooks.read_text(encoding="utf-8"))

    def on_message(message: dict[str, Any], _data: bytes | None) -> None:
        payload = message.get("payload", {}) if message.get("type") == "send" else {}
        if payload.get("type") == "observation":
            payload["detail"] = redact_text(payload.get("detail", ""))
            payload["redacted"] = True
            payload.setdefault("occurred_at", utcnow())
            events.append(payload)
        elif payload.get("type") == "hook_error" or message.get("type") == "error":
            errors.append(redact_text(payload.get("error") or message.get("description")))

    script.on("message", on_message)
    script.load()
    device.resume(pid)
    monkey = subprocess.Popen(
        [
            "adb",
            "-s",
            serial,
            "shell",
            "monkey",
            "-p",
            package,
            "--throttle",
            "300",
            "-v",
            str(max(1, duration_s * 3)),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(duration_s)
    finally:
        monkey.terminate()
        script.unload()
        session.detach()
        device.kill(pid)
    return events, errors
