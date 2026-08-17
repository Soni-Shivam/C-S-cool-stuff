"""Detect that a sample checked its environment and then declined to act.

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.5, docs/00_GUIDING_MAP.md §2 beat 4.

This is the module the whole frontier narrative depends on. A sample that queries
`PackageManager` for a banking app, does not find it, and quietly stops looks — to any
system that only counts observations — *exactly* like a clean app. Both produce nothing.

The distinction is that a clean app never asks. So evasion is inferred from the shape of
what happened: **a probe, followed by silence**. Each pattern below names what the sample
looked for, which is what the frontier then synthesises.

`00_GUIDING_MAP.md` §2 makes the demo consequence explicit — the first detonation shows
the sample doing nothing, and saying so out loud is the point. `CLAUDE.md` makes the
scoring consequence explicit too: **a sample that produced no observations is
`inconclusive`, never benign.**
"""

from __future__ import annotations

from dataclasses import dataclass

from drishti.logging import get_logger
from drishti.m3_dynamic.normaliser import NormalisedTrace, ObservationGroup

log = get_logger(__name__)

#: A run quieter than this, with probes present, reads as stalling rather than as an app
#: that genuinely had nothing to do.
QUIET_EVENT_THRESHOLD = 12

#: Techniques that are environment *questions* rather than actions. A sample doing only
#: these has inspected its surroundings and committed to nothing.
PROBE_TECHNIQUES: frozenset[str] = frozenset(
    {
        "T1418",  # software discovery — is the target bank installed?
        "T1426",  # system information — SIM, build, emulator tells
        "T1430",  # location — geo-gating
    }
)

#: Hook name fragments that indicate a specific kind of probe, and what a morph should
#: answer with. The morph key is what `MorphPlan` consumes in P5.
_PROBE_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("getPackageInfo", "install_packages", "queried whether a specific package is installed"),
    ("getInstalledPackages", "install_packages", "enumerated installed packages"),
    ("resolveActivity", "install_packages", "asked which app handles an intent"),
    ("getSimOperator", "sim_locale", "read the SIM operator"),
    ("getSimCountryIso", "sim_locale", "read the SIM country"),
    ("getSubscriberId", "sim_locale", "read the subscriber id"),
    ("getDeviceId", "device_identity", "read a hardware identifier"),
    ("getLine1Number", "device_identity", "read the phone number"),
    ("Build", "device_identity", "inspected build properties"),
    ("getLastKnownLocation", "geo", "read device location"),
    ("SmsInbox", "sms_history", "counted or read SMS history"),
    ("query", "sms_history", "queried a content provider"),
)


@dataclass(frozen=True)
class EvasionObservation:
    """One environment check the sample made, and what would answer it."""

    probe: str
    morph: str
    detail: str
    occurrences: int


@dataclass(frozen=True)
class EvasionVerdict:
    """Whether this run looks like stalling, and what to synthesise if so."""

    stalled: bool
    reason: str
    observations: tuple[EvasionObservation, ...] = ()

    @property
    def morphs(self) -> tuple[str, ...]:
        """Distinct morph kinds, in the order first observed."""
        seen: list[str] = []
        for item in self.observations:
            if item.morph not in seen:
                seen.append(item.morph)
        return tuple(seen)


def _classify(group: ObservationGroup) -> EvasionObservation | None:
    haystack = f"{group.hook} {group.technique} {group.first_detail}"
    for fragment, morph, description in _PROBE_SIGNATURES:
        if fragment.lower() in haystack.lower():
            return EvasionObservation(
                probe=group.hook,
                morph=morph,
                detail=description,
                occurrences=group.occurrences,
            )
    if group.mitre in PROBE_TECHNIQUES:
        return EvasionObservation(
            probe=group.hook,
            morph="install_packages",
            detail=f"environment probe ({group.mitre})",
            occurrences=group.occurrences,
        )
    return None


def detect(trace: NormalisedTrace, *, installed_and_ran: bool = True) -> EvasionVerdict:
    """Decide whether a run stalled, and name what the sample was looking for.

    Deliberately conservative in one direction and not the other. A run with real
    actions is not called stalling merely because it also probed — plenty of legitimate
    apps ask what is installed. But a run with probes and nothing else is called
    stalling, because that shape is the whole reason the frontier exists.
    """
    if not installed_and_ran:
        return EvasionVerdict(
            stalled=False,
            reason="the sample never ran; this is a harness failure, not evasion",
        )

    if not trace.groups:
        # Nothing at all. Not evidence of innocence — an app that refuses to start on an
        # emulator produces exactly this, and so does one that genuinely does nothing.
        return EvasionVerdict(
            stalled=True,
            reason=(
                "no observations at all: the sample either detected the environment "
                "before any hook fired, or did nothing. Inconclusive, never benign."
            ),
        )

    probes = [obs for obs in (_classify(g) for g in trace.groups) if obs is not None]
    actioned = [g for g in trace.groups if _classify(g) is None]

    if probes and not actioned:
        log.info("evasion_detected", probes=len(probes), morphs=len({p.morph for p in probes}))
        return EvasionVerdict(
            stalled=True,
            reason=(
                f"{len(probes)} environment probe(s) and no other behaviour: the sample "
                "inspected its surroundings and committed to nothing"
            ),
            observations=tuple(probes),
        )

    if probes and trace.total_events < QUIET_EVENT_THRESHOLD:
        return EvasionVerdict(
            stalled=True,
            reason=(
                f"only {trace.total_events} events with {len(probes)} probe(s) present: "
                "too quiet for an app that found what it wanted"
            ),
            observations=tuple(probes),
        )

    return EvasionVerdict(
        stalled=False,
        reason=f"{len(actioned)} non-probe behaviour group(s) observed",
        observations=tuple(probes),
    )
