"""Fixed runtime implementations for the allowlisted M3 stimulus catalogue."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from drishti.sandbox.catalog import require_allowlisted


class StimulusRunner:
    """Execute reviewed argv lists only; no shell, LLM text, or free-form command input."""

    def __init__(
        self,
        *,
        serial: str = "emulator-5554",
        fixture_dir: str | Path = "/opt/drishti/inert-banking-fixtures",
        command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.serial = serial
        self.fixture_dir = Path(fixture_dir)
        self.command = command

    def _run(self, args: list[str], timeout: int = 30) -> None:
        result = self.command(args, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"allowlisted stimulus failed: {args[3] if len(args) > 3 else args[0]}")

    def apply(self, stimulus_ids: list[str]) -> list[str]:
        entries = require_allowlisted(stimulus_ids, "stimulus")
        applied: list[str] = []
        for entry in entries:
            getattr(self, "_" + entry.id.replace(".", "_"))()
            applied.append(entry.id)
        return applied

    def _adb(self, *args: str, timeout: int = 30) -> None:
        self._run(["adb", "-s", self.serial, *args], timeout=timeout)

    def _stimulus_ui_monkey(self) -> None:
        self._adb("shell", "monkey", "--throttle", "300", "--ignore-crashes", "-v", "100", timeout=60)

    def _stimulus_synthetic_sms(self) -> None:
        self._adb("emu", "sms", "send", "+15551230000", "DRISHTI synthetic verification code 000000")

    def _stimulus_synthetic_contacts(self) -> None:
        self._adb(
            "shell", "content", "insert", "--uri", "content://com.android.contacts/raw_contacts",
            "--bind", "account_name:s:DRISHTI_SYNTHETIC", "--bind", "account_type:s:fixture",
        )

    def _stimulus_locale_sim_time(self) -> None:
        self._adb("shell", "setprop", "persist.sys.locale", "en-IN")
        self._adb("shell", "setprop", "persist.sys.timezone", "Asia/Kolkata")
        self._adb("emu", "gsm", "voice", "home")
        self._adb("emu", "gsm", "data", "home")

    def _stimulus_inert_banking_apps(self) -> None:
        for filename in ("bank-one.apk", "bank-two.apk"):
            fixture = (self.fixture_dir / filename).resolve()
            if fixture.parent != self.fixture_dir.resolve() or not fixture.is_file():
                raise RuntimeError(f"approved inert banking fixture missing: {filename}")
            self._adb("install", "-r", str(fixture), timeout=120)

    def _stimulus_fake_c2_template(self) -> None:
        self._run(["curl", "--fail", "--silent", "--max-time", "3", "http://127.0.0.1:8080/fixture"])
