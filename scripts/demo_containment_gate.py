#!/usr/bin/env python3
"""Show the containment gate accepting a trustworthy probe and rejecting an untrustworthy
one — the credibility moment, runnable without the lab.

This drives the REAL `drishti.m3_dynamic.containment.verify()` — the same function the
detonator runs before every sample. It does not reimplement the logic; it injects
controlled probe responses so the three cases can be shown side by side on a laptop, in
seconds, with no VM and no sample. The point being demonstrated is a property of the code
under `drishti/`, and this script is only a lens on it.

The three cases:

  1. SEALED + TRUSTWORTHY PROBE   negative control blocked, positive control reachable,
                                  every forbidden destination blocked            -> CONTAINED
  2. OPEN NETWORK + TRUSTWORTHY   the probe works, but the metadata server and the open
                                  internet answer                            -> NOT CONTAINED
  3. THE v1 BUG (`nc -z`)         a probe that reports "blocked" for everything, including
                                  a port it should reach                 -> UNTRUSTWORTHY PROBE

Case 3 is the one that matters. v1 shipped exactly this probe: toybox `nc` has no `-z`
flag, so `nc -z host port` exited non-zero for every host and every containment check
"passed" over a completely open network. The signed manifest attested a containment that
had never been tested. `assert_probe_trustworthy()`'s positive control is what turns that
silent false-pass into a loud rejection, and this case proves it does.

Run:  python scripts/demo_containment_gate.py     (or: make demo-containment)
"""

from __future__ import annotations

from drishti.m3_dynamic.containment import (
    FORBIDDEN,
    NEGATIVE_CONTROL,
    ContainmentReport,
    verify,
)

SERIAL = "emulator-5554"
POSITIVE_PORT = 45999  # the port assert_probe_trustworthy's listener uses


def _target(command: str) -> tuple[str, int] | None:
    """Pull the (host, port) a probe command is aimed at, from its text."""
    for host, port in (*FORBIDDEN, NEGATIVE_CONTROL, ("127.0.0.1", POSITIVE_PORT)):
        if f" {host} {port} " in command:
            return host, port
    return None


def sealed_trustworthy(_serial: str, command: str) -> str:
    """A working probe on a sealed network: only the positive-control listener answers."""
    if "nc -l -p" in command:  # starting the positive-control listener
        return "DRISHTI_RC=0"
    target = _target(command)
    if target == ("127.0.0.1", POSITIVE_PORT):
        return "DRISHTI_RC=0"  # our own listener is reachable — the probe can see 'open'
    return "DRISHTI_RC=1"  # everything else, including the forbidden set, is blocked


def open_network_trustworthy(_serial: str, command: str) -> str:
    """A working probe, but containment is not actually in place."""
    if "nc -l -p" in command:
        return "DRISHTI_RC=0"
    target = _target(command)
    if target == NEGATIVE_CONTROL:
        return "DRISHTI_RC=1"  # 127.0.0.1:1 still blocked — the probe is honest
    if target == ("127.0.0.1", POSITIVE_PORT):
        return "DRISHTI_RC=0"
    # The metadata server and the open internet answer — the network is not sealed.
    return "DRISHTI_RC=0"


def v1_broken_nc_z(_serial: str, command: str) -> str:
    """The v1 probe: `nc -z` toybox does not support, so every call fails the same way.

    Crucially it fails EVEN for the positive-control listener — a port that is genuinely
    open — because the flag error happens before any connection is attempted. That is what
    the trustworthiness gate catches.
    """
    if "nc -l -p" in command:
        return "DRISHTI_RC=0"  # the listener still starts fine
    # Every probe returns the toybox flag error, which parse_rc reads as unreachable.
    return "Unknown option 'z'"


def show(title: str, note: str, report: ContainmentReport) -> None:
    print(f"\n=== {title} ===")
    print(f"  {note}")
    print(f"  probe_trustworthy = {report.probe_trustworthy}")
    print(f"  verified          = {report.verified}")
    print(f"  VERDICT           = {report.summary}")
    if report.results:
        for r in report.results:
            state = "REACHABLE" if r.reachable else "blocked"
            print(f"    {r.host}:{r.port:<3} -> {state} (rc={r.rc})")
    if report.reason and not report.verified:
        print(f"  reason            = {report.reason}")


def main() -> int:
    print("DRISHTI containment gate — the same verify() the detonator runs per sample.")
    print("No VM, no sample: controlled probe responses, real gate logic.")

    r1 = verify(SERIAL, runner=sealed_trustworthy)
    show(
        "1. SEALED NETWORK, TRUSTWORTHY PROBE",
        "negative control blocked, positive control open, forbidden set blocked",
        r1,
    )

    r2 = verify(SERIAL, runner=open_network_trustworthy)
    show(
        "2. OPEN NETWORK, TRUSTWORTHY PROBE",
        "the probe works — and it can see the metadata server and the internet",
        r2,
    )

    r3 = verify(SERIAL, runner=v1_broken_nc_z)
    show(
        "3. THE v1 BUG: `nc -z`, WHICH TOYBOX DOES NOT SUPPORT",
        "every probe returns the flag error; even the open positive control reads blocked",
        r3,
    )

    # The demo asserts its own outcome, so a regression in the gate breaks the demo too.
    ok = (
        r1.verified
        and r1.probe_trustworthy
        and (not r2.verified)
        and r2.probe_trustworthy
        and (not r3.verified)
        and (not r3.probe_trustworthy)
    )
    print("\n" + ("PASS — the gate accepts only case 1, as it must." if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
