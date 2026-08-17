"""Containment verification. Fail closed, and prove the probe works before trusting it.

docs/PHASE_4_DYNAMIC_SANDBOX.md, CLAUDE.md "Containment verification is a test, not a
claim". LIFTed from v1's `verify_containment.py`, whose two hard-won corrections are the
entire reason this file is worth having.

**1. Android's toybox `nc` has no `-z` flag.** v1 originally ran `nc -z -w 3 host port`
and read a non-zero exit as "blocked". toybox exits 1 with `Unknown option 'z'`, so
`blocked()` returned True unconditionally: **every containment check passed regardless of
the real network state, and the signed manifest attested containment that had never been
tested.** The fix is a plain `nc -w N host port </dev/null` followed by an explicit
`echo DRISHTI_RC=$?` that is parsed out of the output.

**2. A timeout means blocked, not "unknown".** A blackhole `-j DROP` rule makes the probe
hang past its deadline. An unhandled `TimeoutExpired` propagating out of `blocked()`
previously turned verification into a coin flip on DNS cache state. Timeout maps to rc
124 and reads as blocked.

And the rule those two produce: `assert_probe_trustworthy()` runs a **negative control**
(a port that must be unreachable) and a **positive control** (a listener we started, which
must be reachable) before any verdict is believed. A probe that cannot tell the two apart
is not evidence of anything.

A containment failure aborts the batch. It never downgrades to a warning.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from drishti.logging import get_logger

log = get_logger(__name__)

#: A probe runner: (serial, command) -> raw stdout. Injectable so the trustworthiness
#: checks can be tested without an emulator — the v1 bug was in the probe itself.
ProbeRunner = Callable[[str, str], str]

#: The marker the in-guest command echoes so the real exit code survives the shell.
RC_MARKER = re.compile(r"DRISHTI_RC=(\d+)")

#: `subprocess.TimeoutExpired` is mapped to this and read as blocked. A probe that hangs
#: is a probe that did not get through.
TIMEOUT_RC = 124

#: Negative control: nothing listens here, so a trustworthy probe must call it blocked.
NEGATIVE_CONTROL = ("127.0.0.1", 1)

#: Destinations that must be unreachable from inside the guest.
FORBIDDEN = (
    ("169.254.169.254", 80),  # GCE metadata server — the crown jewels
    ("8.8.8.8", 53),  # the open internet
    ("1.1.1.1", 443),
    ("10.0.0.1", 22),  # RFC1918: the VPC the host sits on
)


class ContainmentError(RuntimeError):
    """Containment could not be verified. Never downgraded to a warning."""


@dataclass
class ProbeResult:
    host: str
    port: int
    reachable: bool
    rc: int


@dataclass
class ContainmentReport:
    """What the attestation manifest signs."""

    verified: bool
    probe_trustworthy: bool
    results: tuple[ProbeResult, ...] = ()
    failures: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""

    @property
    def summary(self) -> str:
        if not self.probe_trustworthy:
            return "UNTRUSTWORTHY PROBE — no containment claim may be made"
        return "CONTAINED" if self.verified else "NOT CONTAINED"


def parse_rc(output: str) -> int:
    """Read the explicit exit code out of probe output.

    Absent marker means the command did not complete as expected, which is treated as
    unreachable rather than assumed fine — the failure mode this whole module exists to
    prevent is a check that passes because it never really ran.
    """
    match = RC_MARKER.search(output)
    return int(match.group(1)) if match else TIMEOUT_RC


def probe_command(host: str, port: int, timeout_s: int = 3) -> str:
    """The in-guest shell command. No `-z`: toybox does not have it."""
    return f"toybox nc -w {timeout_s} {host} {port} </dev/null >/dev/null 2>&1; echo DRISHTI_RC=$?"


def run_adb(serial: str, command: str, timeout: int = 15) -> str:
    """Run a shell command in the guest, mapping a timeout to rc 124."""
    try:
        completed = subprocess.run(
            ["adb", "-s", serial, "shell", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.stdout
    except subprocess.TimeoutExpired:
        # A blackhole DROP makes this hang. Hanging is blocked, not unknown.
        return f"DRISHTI_RC={TIMEOUT_RC}"


def is_reachable(serial: str, host: str, port: int, runner: ProbeRunner = run_adb) -> ProbeResult:
    """True only when the probe explicitly reported success (rc 0)."""
    rc = parse_rc(runner(serial, probe_command(host, port)))
    return ProbeResult(host=host, port=port, reachable=rc == 0, rc=rc)


def assert_probe_trustworthy(serial: str, runner: ProbeRunner = run_adb) -> tuple[bool, str]:
    """Prove the probe can distinguish reachable from unreachable, before believing it.

    Without this, a probe that always says "blocked" produces a perfect containment
    report from a completely open network — which is exactly what v1 shipped.
    """
    negative = is_reachable(serial, *NEGATIVE_CONTROL, runner=runner)
    if negative.reachable:
        return False, (
            f"negative control {NEGATIVE_CONTROL[0]}:{NEGATIVE_CONTROL[1]} reported "
            "REACHABLE; the probe cannot detect a closed port"
        )

    # Positive control: start a listener in the guest and require the probe to find it.
    runner(serial, "(toybox nc -l -p 45999 >/dev/null 2>&1 &) ; sleep 1; echo DRISHTI_RC=0")
    positive = is_reachable(serial, "127.0.0.1", 45999, runner=runner)
    if not positive.reachable:
        return False, (
            "positive control 127.0.0.1:45999 reported UNREACHABLE while a listener was "
            "running; the probe cannot detect an open port either"
        )
    return True, "probe distinguishes open from closed"


def verify(serial: str, runner: ProbeRunner = run_adb) -> ContainmentReport:
    """Full containment check. Returns a report; the caller aborts on failure."""
    trustworthy, reason = assert_probe_trustworthy(serial, runner=runner)
    if not trustworthy:
        log.error("containment_probe_untrustworthy", reason=reason)
        return ContainmentReport(verified=False, probe_trustworthy=False, reason=reason)

    results = tuple(is_reachable(serial, host, port, runner=runner) for host, port in FORBIDDEN)
    failures = tuple(
        f"{r.host}:{r.port} is REACHABLE from inside the sandbox" for r in results if r.reachable
    )
    verified = not failures
    if not verified:
        log.error("containment_failed", failures=list(failures))
    return ContainmentReport(
        verified=verified,
        probe_trustworthy=True,
        results=results,
        failures=failures,
        reason=reason if verified else "; ".join(failures),
    )


def require_containment(serial: str, runner: ProbeRunner = run_adb) -> ContainmentReport:
    """Verify, or raise. A containment failure aborts a batch — it never warns."""
    report = verify(serial, runner=runner)
    if not report.verified:
        raise ContainmentError(f"{report.summary}: {report.reason}")
    return report
