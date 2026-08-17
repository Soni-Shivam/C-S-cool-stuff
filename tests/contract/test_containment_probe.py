"""The containment probe must be trustworthy before any verdict it produces is believed.

CLAUDE.md "Containment verification is a test, not a claim". CI gate.

v1 shipped a probe using `nc -z`, which toybox does not support. It exited 1 with
`Unknown option 'z'`, so every containment check passed regardless of the real network
state and a signed manifest attested containment that had never been tested. These tests
exist so that cannot happen twice.
"""

from __future__ import annotations

import pytest

from drishti.m3_dynamic.containment import (
    NEGATIVE_CONTROL,
    TIMEOUT_RC,
    ContainmentError,
    assert_probe_trustworthy,
    parse_rc,
    probe_command,
    require_containment,
    verify,
)


def test_the_probe_command_does_not_use_the_z_flag() -> None:
    """toybox nc has no -z. Using it made every check pass unconditionally."""
    command = probe_command("10.0.0.1", 22)
    assert " -z" not in command
    assert "DRISHTI_RC=$?" in command, "the exit code must be echoed explicitly"


def test_an_explicit_exit_code_is_parsed() -> None:
    assert parse_rc("DRISHTI_RC=0") == 0
    assert parse_rc("noise\nDRISHTI_RC=1\n") == 1


def test_a_missing_marker_reads_as_unreachable_not_as_success() -> None:
    """Absent output must never be read as a clean pass."""
    assert parse_rc("") == TIMEOUT_RC
    assert parse_rc("Unknown option 'z'") == TIMEOUT_RC


def _runner(mapping: dict[tuple[str, int], int], default: int = 1):
    def run(_serial: str, command: str) -> str:
        for (host, port), rc in mapping.items():
            if f" {host} {port} " in command:
                return f"DRISHTI_RC={rc}"
        if "nc -l -p" in command:
            return "DRISHTI_RC=0"
        return f"DRISHTI_RC={default}"

    return run


def test_a_probe_that_always_says_blocked_is_rejected() -> None:
    """The exact v1 bug: a probe that cannot see an open port proves nothing."""
    always_blocked = _runner({}, default=1)
    trustworthy, reason = assert_probe_trustworthy("emulator-5554", runner=always_blocked)
    assert trustworthy is False
    assert "positive control" in reason


def test_a_probe_that_always_says_reachable_is_rejected() -> None:
    always_open = _runner({}, default=0)
    trustworthy, reason = assert_probe_trustworthy("emulator-5554", runner=always_open)
    assert trustworthy is False
    assert "negative control" in reason


def test_a_discriminating_probe_is_accepted() -> None:
    good = _runner({NEGATIVE_CONTROL: 1, ("127.0.0.1", 45999): 0}, default=1)
    trustworthy, _ = assert_probe_trustworthy("emulator-5554", runner=good)
    assert trustworthy is True


def test_containment_passes_only_when_everything_is_blocked() -> None:
    good = _runner({NEGATIVE_CONTROL: 1, ("127.0.0.1", 45999): 0}, default=1)
    report = verify("emulator-5554", runner=good)
    assert report.verified is True
    assert report.summary == "CONTAINED"


def test_a_reachable_metadata_server_fails_containment() -> None:
    """169.254.169.254 is the crown jewels. Reaching it is catastrophic."""
    leaky = _runner(
        {NEGATIVE_CONTROL: 1, ("127.0.0.1", 45999): 0, ("169.254.169.254", 80): 0}, default=1
    )
    report = verify("emulator-5554", runner=leaky)
    assert report.verified is False
    assert any("169.254.169.254" in f for f in report.failures)


def test_an_untrustworthy_probe_never_claims_containment() -> None:
    """No verdict at all is the correct output when the instrument is broken."""
    report = verify("emulator-5554", runner=_runner({}, default=0))
    assert report.verified is False
    assert report.probe_trustworthy is False
    assert "UNTRUSTWORTHY" in report.summary


def test_failure_aborts_rather_than_warns() -> None:
    """CLAUDE.md: a containment failure aborts the batch, never downgrades."""
    leaky = _runner({NEGATIVE_CONTROL: 1, ("127.0.0.1", 45999): 0, ("8.8.8.8", 53): 0}, default=1)
    with pytest.raises(ContainmentError):
        require_containment("emulator-5554", runner=leaky)


def test_a_timeout_is_read_as_blocked() -> None:
    """A blackhole DROP makes the probe hang; hanging is blocked, not unknown."""
    assert parse_rc(f"DRISHTI_RC={TIMEOUT_RC}") == TIMEOUT_RC
