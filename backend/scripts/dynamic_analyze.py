#!/usr/bin/env python3
"""M3 sealed-runtime harness. This file must never be invoked by the API.

The harness fails closed on containment or snapshot errors, bounds every child
process, and writes a strict SHA-bound artifact for success *or* failure.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from drishti.sandbox.containment import load_and_verify_manifest
from drishti.sandbox.observation import (
    FailureRecord,
    HarnessMetadata,
    ObservationArtifact,
    ObservationEvent,
    SnapshotLifecycle,
)
from drishti.sandbox.redaction import redact_text

HARNESS_VERSION = "m3-harness-1.0.0"
HOOK_VERSION = "m3-hooks-1.0.0"
HOOKS = Path(__file__).with_name("frida_hooks.js")
DEFAULT_MANIFEST = Path("/var/lib/drishti/containment-manifest.json")
DEFAULT_PUBLIC_KEY = Path("/etc/drishti/containment-signing.pub")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class HarnessFailure(RuntimeError):
    def __init__(self, code: str, stage: str, message: str):
        super().__init__(message)
        self.code = code
        self.stage = stage


def run_command(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def _stop_process(process: subprocess.Popen | None, *, timeout: int = 5) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


@dataclass
class HarnessConfig:
    apk: Path
    output: Path
    duration_s: int
    snapshot: str
    avd_name: str
    emulator_serial: str
    emulator_image: str
    manifest: Path
    trusted_public_key: Path
    hooks: Path = HOOKS
    sample_kind: Literal["inert_fixture", "benign", "vetted_malware"] = "inert_fixture"


class PilotAuthorization(BaseModel):
    """Human review record required before the single real-sample pilot."""
    model_config = ConfigDict(extra="forbid", strict=True)
    approval_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    reviewed_by: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    runtime_image: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    approved_at: datetime
    expires_at: datetime
    max_duration_s: Annotated[int, Field(ge=1, le=1800)]


def require_pilot_authorization(
    path: Path, *, apk_sha256: str, runtime_image: str, duration_s: int,
    now: datetime | None = None,
) -> PilotAuthorization:
    if not path.is_file():
        raise ValueError("vetted-malware pilot authorization is missing")
    authorization = PilotAuthorization.model_validate_json(path.read_text())
    current = now or utcnow()
    if authorization.sha256 != apk_sha256:
        raise ValueError("pilot authorization SHA-256 does not match the APK")
    if authorization.runtime_image != runtime_image:
        raise ValueError("pilot authorization targets a different runtime image")
    if current < authorization.approved_at or current >= authorization.expires_at:
        raise ValueError("pilot authorization is stale or not yet valid")
    if duration_s > authorization.max_duration_s:
        raise ValueError("requested duration exceeds pilot authorization")
    return authorization


class DynamicHarness:
    def __init__(
        self,
        config: HarnessConfig,
        *,
        command: Callable[..., subprocess.CompletedProcess[str]] = run_command,
        sleep: Callable[[float], None] = time.sleep,
        collector: Callable[[str, int, Path], tuple[list[dict], list[str]]] | None = None,
    ) -> None:
        self.config = config
        self.command = command
        self.sleep = sleep
        self.collector = collector or (
            lambda package, duration, hooks: collect_frida(
                package, duration, hooks, self.config.emulator_serial
            )
        )
        self.frida_process: subprocess.Popen | None = None

    def adb(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return self.command(["adb", "-s", self.config.emulator_serial, *args], timeout=timeout)

    def wait_for_device(self, timeout: int = 300) -> None:
        result = self.adb("wait-for-device", timeout=timeout)
        if result.returncode != 0:
            raise HarnessFailure("emulator_unhealthy", "boot", "adb wait-for-device failed")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            completed = self.adb("shell", "getprop", "sys.boot_completed", timeout=15)
            if completed.returncode == 0 and completed.stdout.strip() == "1":
                health = self.adb("shell", "getprop", "init.svc.bootanim", timeout=15)
                if health.stdout.strip() == "stopped":
                    return
            self.sleep(2)
        raise HarnessFailure("emulator_unhealthy", "boot", "emulator boot health timed out")

    def restore_snapshot(self, stage: str) -> None:
        result = self.adb("emu", "avd", "snapshot", "load", self.config.snapshot, timeout=180)
        output = f"{result.stdout}\n{result.stderr}"
        if result.returncode != 0 or re.search(r"\bKO\b", output):
            raise HarnessFailure(
                "snapshot_restore_failed", stage,
                redact_text(output.strip() or f"snapshot {self.config.snapshot} unavailable"),
            )
        self.wait_for_device(timeout=180)

    def package_name(self) -> str:
        result = self.command(["aapt", "dump", "badging", str(self.config.apk)], timeout=120)
        match = re.search(r"package: name='([^']+)'", result.stdout or "")
        if not match:
            raise HarnessFailure("internal_error", "identify", "aapt could not determine package name")
        return match.group(1)

    def start_frida(self) -> None:
        result = self.adb("root", timeout=90)
        if result.returncode != 0:
            raise HarnessFailure("frida_failed", "frida_start", "failed to restart adbd as root")
        self.wait_for_device(timeout=90)
        for args in (("push", "/opt/drishti/tools/frida-server", "/data/local/tmp/frida-server"),
                     ("shell", "chmod", "755", "/data/local/tmp/frida-server")):
            result = self.adb(*args, timeout=90)
            if result.returncode != 0:
                raise HarnessFailure("frida_failed", "frida_start", "failed to prepare Frida server")
        self.frida_process = subprocess.Popen(
            ["adb", "-s", self.config.emulator_serial, "shell", "/data/local/tmp/frida-server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.sleep(2)
        if self.frida_process.poll() is not None:
            raise HarnessFailure("frida_failed", "frida_start", "Frida server exited during startup")

    def stop_frida(self) -> None:
        _stop_process(self.frida_process)
        self.adb("shell", "pkill", "-f", "frida-server", timeout=15)

    def install(self) -> None:
        result = self.adb("install", "-r", "-g", str(self.config.apk), timeout=300)
        if result.returncode != 0 or "Success" not in (result.stdout or ""):
            raise HarnessFailure("install_failed", "install", "APK installation failed")

    def package_absent(self, package: str) -> bool:
        result = self.adb("shell", "pm", "path", package, timeout=30)
        return result.returncode != 0 or not result.stdout.strip()

    def run(self) -> tuple[ObservationArtifact, int]:
        started = utcnow()
        apk_sha = sha256_file(self.config.apk)
        package: str | None = None
        observations: list[ObservationEvent] = []
        failures: list[FailureRecord] = []
        diagnostics: list[str] = []
        before = "not_run"
        after = "not_run"
        absent_after = False
        containment_hash: str | None = None
        containment_verified_at: datetime | None = None
        outcome = "failed"

        try:
            try:
                manifest = load_and_verify_manifest(self.config.manifest, self.config.trusted_public_key)
            except Exception as exc:  # signature, freshness, and probe state all fail closed
                raise HarnessFailure("containment_failed", "admission", redact_text(exc)) from exc
            containment_hash = hashlib.sha256(self.config.manifest.read_bytes()).hexdigest()
            containment_verified_at = utcnow()
            package = self.package_name()
            self.wait_for_device()
            try:
                self.restore_snapshot("snapshot_before")
                before = "passed"
            except Exception:
                before = "failed"
                raise
            self.start_frida()
            self.install()
            self.adb("logcat", "-c", timeout=30)
            raw_events, hook_errors = self.collector(package, self.config.duration_s, self.config.hooks)
            for event in raw_events:
                observations.append(ObservationEvent.model_validate_json(json.dumps(event)))
            for error in hook_errors:
                failures.append(FailureRecord(
                    code="hook_error", stage="instrumentation",
                    message=redact_text(error), occurred_at=utcnow(),
                ))
            outcome = "completed" if observations else "inconclusive"
            diagnostics.append(redact_text(f"containment:{manifest.instance_id}; hooks completed"))
        except subprocess.TimeoutExpired as exc:
            outcome = "timeout"
            failures.append(FailureRecord(code="timeout", stage="subprocess", message=redact_text(exc), occurred_at=utcnow()))
        except HarnessFailure as exc:
            outcome = "crashed" if exc.code == "sample_crashed" else "failed"
            failures.append(FailureRecord(code=exc.code, stage=exc.stage, message=redact_text(exc), occurred_at=utcnow()))
        except Exception as exc:  # noqa: BLE001 - converted to a redacted explicit state
            outcome = "failed"
            failures.append(FailureRecord(
                code="internal_error", stage="harness", message=redact_text(f"{type(exc).__name__}: {exc}"),
                occurred_at=utcnow(),
            ))
        finally:
            try:
                self.stop_frida()
            except Exception as exc:  # noqa: BLE001
                failures.append(FailureRecord(code="cleanup_failed", stage="frida_cleanup", message=redact_text(exc), occurred_at=utcnow()))
                outcome = "failed"
            if package:
                self.adb("uninstall", package, timeout=120)
            try:
                self.restore_snapshot("snapshot_after")
                after = "passed"
                absent_after = bool(package) and self.package_absent(package)
                if package and not absent_after:
                    raise HarnessFailure("cleanup_failed", "snapshot_after", "package remains after snapshot restore")
            except Exception as exc:  # noqa: BLE001
                after = "failed"
                outcome = "failed"
                code = exc.code if isinstance(exc, HarnessFailure) else "snapshot_restore_failed"
                failures.append(FailureRecord(code=code, stage="snapshot_after", message=redact_text(exc), occurred_at=utcnow()))

        finished = utcnow()
        artifact = ObservationArtifact(
            sha256=apk_sha,
            package=package,
            outcome=outcome,
            started_at=started,
            finished_at=finished,
            duration_s=min(3600.0, max(0.0, (finished - started).total_seconds())),
            metadata=HarnessMetadata(
                harness_version=HARNESS_VERSION,
                hook_version=HOOK_VERSION,
                emulator_image=self.config.emulator_image,
                emulator_serial=self.config.emulator_serial,
                avd_name=self.config.avd_name,
                sample_kind=self.config.sample_kind,
                containment_manifest_sha256=containment_hash,
                containment_verified=containment_verified_at is not None,
                containment_verified_at=containment_verified_at,
            ),
            snapshot=SnapshotLifecycle(
                name=self.config.snapshot,
                before_restore=before,
                after_restore=after,
                package_absent_after=absent_after,
            ),
            observations=observations,
            failures=failures,
            diagnostics=diagnostics,
            mitre_observed=sorted({event.mitre for event in observations}),
        )
        self._write_artifact(artifact)
        return artifact, 0 if artifact.safe_for_ingestion else 2

    def _write_artifact(self, artifact: ObservationArtifact) -> None:
        self.config.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.config.output.with_suffix(self.config.output.suffix + ".tmp")
        temporary.write_text(artifact.model_dump_json(indent=2))
        os.chmod(temporary, 0o600)
        temporary.replace(self.config.output)


def collect_frida(package: str, duration: int, hooks: Path, serial: str = "emulator-5554") -> tuple[list[dict], list[str]]:
    """Collect events while guaranteeing Frida, sample, and Monkey cleanup."""
    import frida

    events: list[dict] = []
    errors: list[str] = []
    device = None
    pid = None
    session = None
    script = None
    monkey: subprocess.Popen | None = None

    def on_message(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "sensitive_observation":
                raw = str(payload.pop("sensitive_detail", ""))
                payload["type"] = "observation"
                payload["detail"] = (
                    f"[REDACTED:DECRYPTED_PAYLOAD] length={len(raw)} "
                    f"sha256={hashlib.sha256(raw.encode()).hexdigest()}"
                )
                payload["redacted"] = True
                payload.setdefault("occurred_at", utcnow().isoformat())
                events.append(payload)
            elif payload.get("type") == "observation":
                payload["detail"] = redact_text(payload.get("detail", ""))
                payload["redacted"] = True
                payload.setdefault("occurred_at", utcnow().isoformat())
                events.append(payload)
            elif payload.get("type") == "hook_error":
                errors.append(f"{payload.get('hook', 'unknown')}: {redact_text(payload.get('error', 'unknown'))}")
        elif message.get("type") == "error":
            errors.append(redact_text(message.get("description", "Frida script error")))

    try:
        device = frida.get_usb_device(timeout=30)
        pid = device.spawn([package])
        session = device.attach(pid)
        script = session.create_script(hooks.read_text())
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        event_count = max(1, min(1000, duration * 3))
        monkey = subprocess.Popen(
            ["adb", "-s", serial, "shell", "monkey", "-p", package, "--throttle", "300",
             "--ignore-crashes", "--ignore-timeouts", "-v", str(event_count)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            time.sleep(min(0.25, max(0.01, deadline - time.monotonic())))
    finally:
        _stop_process(monkey)
        if script is not None:
            try:
                script.unload()
            except Exception:  # noqa: BLE001
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:  # noqa: BLE001
                pass
        if device is not None and pid is not None:
            try:
                device.kill(pid)
            except Exception:  # noqa: BLE001
                pass
    return events, errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=120, choices=range(1, 1801), metavar="1..1800")
    parser.add_argument("--snapshot", default="clean")
    parser.add_argument("--avd", default="drishti")
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--emulator-image", required=True)
    parser.add_argument("--sample-kind", choices=("inert_fixture", "benign", "vetted_malware"), default="inert_fixture")
    parser.add_argument("--pilot-authorization", type=Path)
    parser.add_argument("--containment-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--containment-public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.apk.is_file():
        raise SystemExit("APK path is not a regular file")
    for executable in ("adb", "aapt"):
        if not shutil.which(executable):
            raise SystemExit(f"{executable} not found; run only on the prepared detonator")
    if not HOOKS.is_file():
        raise SystemExit(f"hook catalogue missing: {HOOKS}")
    if args.sample_kind == "vetted_malware":
        if args.pilot_authorization is None:
            raise SystemExit("--pilot-authorization is mandatory for vetted malware")
        try:
            require_pilot_authorization(
                args.pilot_authorization,
                apk_sha256=sha256_file(args.apk), runtime_image=args.emulator_image,
                duration_s=args.duration,
            )
        except ValueError as exc:
            raise SystemExit(f"pilot authorization rejected: {exc}") from exc
    lock_path = Path(os.environ.get("DRISHTI_ANALYSIS_LOCK", "/run/drishti-analysis.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit("another M3 analysis is already running") from exc
        artifact, exit_code = DynamicHarness(HarnessConfig(
            apk=args.apk,
            output=args.out,
            duration_s=args.duration,
            snapshot=args.snapshot,
            avd_name=args.avd,
            emulator_serial=args.serial,
            emulator_image=args.emulator_image,
            manifest=args.containment_manifest,
            trusted_public_key=args.containment_public_key,
            sample_kind=args.sample_kind,
        )).run()
    print(f"artifact={args.out} sha256={artifact.sha256} outcome={artifact.outcome} observations={len(artifact.observations)}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
