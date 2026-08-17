"""Trace aggregation and evasion detection.

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.5, T4.6, CLAUDE.md rule 11.

The load-bearing property is that aggregation does not change `b_dynamic`. If it did,
grouping would be a scoring decision disguised as a formatting one — and the whole
reason to group is that one real sample fired `Cipher.doFinal` 1,925 times in 103
seconds.
"""

from __future__ import annotations

from drishti.contracts.static_report import Severity
from drishti.m3_dynamic.evasion import detect
from drishti.m3_dynamic.normaliser import (
    MAX_OBSERVATION_GROUPS,
    aggregate,
)


def _event(technique: str, mitre: str, hook: str, detail: str = "") -> dict:
    return {"technique": technique, "mitre": mitre, "source_hook": hook, "detail": detail}


# ── aggregation ──────────────────────────────────────────────────────────────
def test_the_1925_event_case_collapses_to_one_group() -> None:
    """The measured v1 case: 1,925 Cipher.doFinal calls in 103 seconds."""
    events = [_event("Cipher.doFinal", "T1521", "cipher_hook") for _ in range(1925)]
    trace = aggregate(events)
    assert len(trace.groups) == 1
    assert trace.groups[0].occurrences == 1925
    assert trace.total_events == 1925


def test_aggregation_does_not_change_the_behavioural_signal() -> None:
    """Rule 11's actual requirement, and the reason grouping is safe at all.

    One encryption and 1,925 encryptions are the same behaviour. If the count moved the
    signal, aggregation would be a scoring change wearing a formatting disguise.
    """
    once = aggregate([_event("Cipher.doFinal", "T1521", "cipher_hook")])
    many = aggregate([_event("Cipher.doFinal", "T1521", "cipher_hook") for _ in range(1925)])
    assert once.b_dynamic == many.b_dynamic


def test_distinct_techniques_do_raise_the_signal() -> None:
    """It must key on WHAT was observed, even though it ignores how often."""
    one = aggregate([_event("a", "T1521", "h1")])
    two = aggregate([_event("a", "T1521", "h1"), _event("b", "T1407", "h2")])
    assert two.b_dynamic > one.b_dynamic


def test_the_group_cap_is_enforced_and_disclosed() -> None:
    events = [_event(f"t{i}", "T1426", f"hook{i}") for i in range(MAX_OBSERVATION_GROUPS + 25)]
    trace = aggregate(events)
    assert len(trace.groups) == MAX_OBSERVATION_GROUPS
    assert trace.dropped_groups == 25
    assert trace.errors, "dropping observations must be disclosed, not silent"


def test_the_cap_drops_the_least_severe_first() -> None:
    """If something must be lost it must not be the critical finding."""
    events = [_event(f"low{i}", "T1418", f"h{i}") for i in range(MAX_OBSERVATION_GROUPS + 5)]
    events.append(_event("dex_load", "T1407", "dex_hook"))
    trace = aggregate(events)
    assert any(g.mitre == "T1407" for g in trace.groups), "critical technique was dropped"


def test_signal_is_bounded_and_empty_means_zero() -> None:
    assert aggregate([]).b_dynamic == 0.0
    everything = [_event(f"t{i}", m, f"h{i}") for i, m in enumerate(("T1407", "T1417", "T1582"))]
    assert 0.0 <= aggregate(everything).b_dynamic <= 1.0


def test_severity_is_derived_from_the_technique() -> None:
    trace = aggregate([_event("dex", "T1407", "h")])
    assert trace.groups[0].severity is Severity.CRITICAL


def test_signal_is_deterministic() -> None:
    events = [_event("a", "T1521", "h1"), _event("b", "T1407", "h2")]
    assert aggregate(events).b_dynamic == aggregate(events).b_dynamic


# ── evasion ──────────────────────────────────────────────────────────────────
def test_probes_with_no_action_read_as_stalling() -> None:
    """The shape the entire frontier narrative depends on."""
    trace = aggregate([_event("PackageManager.getPackageInfo", "T1418", "pkg_hook")])
    verdict = detect(trace)
    assert verdict.stalled is True
    assert "install_packages" in verdict.morphs


def test_silence_is_inconclusive_never_benign() -> None:
    """CLAUDE.md: a sample that produced no observations is inconclusive."""
    verdict = detect(aggregate([]))
    assert verdict.stalled is True
    assert "never benign" in verdict.reason


def test_real_behaviour_is_not_called_evasion() -> None:
    """Legitimate apps probe too; probing alongside real action is not stalling."""
    events = [_event("PackageManager.getPackageInfo", "T1418", "pkg_hook")]
    events += [_event("SmsManager.sendTextMessage", "T1582", "sms_hook") for _ in range(30)]
    assert detect(aggregate(events)).stalled is False


def test_a_harness_failure_is_not_reported_as_evasion() -> None:
    """ "It never ran" and "it ran and hid" are different findings."""
    verdict = detect(aggregate([]), installed_and_ran=False)
    assert verdict.stalled is False
    assert "harness failure" in verdict.reason


def test_the_morph_plan_names_what_the_sample_looked_for() -> None:
    """The frontier synthesises answers, so the probe must name the question."""
    trace = aggregate(
        [
            _event("PackageManager.getPackageInfo", "T1418", "pkg_hook"),
            _event("TelephonyManager.getSimCountryIso", "T1426", "sim_hook"),
        ]
    )
    verdict = detect(trace)
    assert verdict.stalled is True
    assert set(verdict.morphs) == {"install_packages", "sim_locale"}
