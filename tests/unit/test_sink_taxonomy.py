"""The sink taxonomy and combo rules, held to PHASE_1's Definition of Done.

docs/PHASE_1_STATIC_ENGINE.md — "≥14 permission-combo rules; ≥18 sinks in the taxonomy".

These counts are asserted rather than remembered. A DoD number that lives only in a
markdown file drifts the moment someone refactors, and the failure is silent: fewer
sinks simply means samples score lower, which looks like a quiet model rather than a
regression.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from drishti.contracts.static_report import Severity
from drishti.m2_static.sinks import SINK_BY_ID, SINK_SIGNATURES, SINKS, severity_of

RULES = Path(__file__).resolve().parents[2] / "drishti/m2_static/rules/permission_combos.yaml"

MIN_SINKS = 18
MIN_COMBO_RULES = 14


def _rules() -> list[dict]:
    return yaml.safe_load(RULES.read_text())


def test_sink_taxonomy_meets_the_definition_of_done() -> None:
    assert len(SINKS) >= MIN_SINKS, f"PHASE_1 DoD requires >= {MIN_SINKS} sinks, found {len(SINKS)}"


def test_combo_rules_meet_the_definition_of_done() -> None:
    rules = _rules()
    assert len(rules) >= MIN_COMBO_RULES, (
        f"PHASE_1 DoD requires >= {MIN_COMBO_RULES} combo rules, found {len(rules)}"
    )


def test_sink_ids_are_unique() -> None:
    ids = [sink.sink_id for sink in SINKS]
    assert len(ids) == len(set(ids)), "duplicate sink id would silently drop a marker"
    assert len(SINK_SIGNATURES) == len(SINKS)
    assert len(SINK_BY_ID) == len(SINKS)


def test_combo_rule_ids_are_unique() -> None:
    ids = [rule["id"] for rule in _rules()]
    assert len(ids) == len(set(ids))


def test_every_sink_carries_mitre_and_severity() -> None:
    """Both flow downstream: MITRE into the technique mapper and STIX, severity into G."""
    for sink in SINKS:
        assert sink.mitre.startswith("T"), f"{sink.sink_id} has no MITRE technique"
        assert isinstance(sink.severity, Severity)
        assert sink.description.strip(), f"{sink.sink_id} has no description"
        assert sink.marker.strip(), f"{sink.sink_id} has no marker"


def test_every_combo_rule_carries_mitre_and_severity() -> None:
    for rule in _rules():
        assert str(rule.get("mitre", "")).startswith("T"), f"{rule['id']} has no MITRE technique"
        assert rule.get("severity") in {"low", "medium", "high", "critical"}
        assert str(rule.get("description", "")).strip(), f"{rule['id']} has no description"


def test_unknown_sink_defaults_to_low_severity() -> None:
    """An unrecognised sink must never inflate a score by accident."""
    assert severity_of("no_such_sink_exists") is Severity.LOW


def test_the_frontier_probe_sink_exists() -> None:
    """`pkg_query` is the thread the whole frontier demo hangs on.

    The canary probes PackageManager, the probe misses, the morph plan installs the
    package, and re-detonation turns the miss into a hit. Losing this sink would break
    that beat without breaking any other test.
    """
    assert "pkg_query" in SINK_BY_ID
    assert "PackageManager" in SINK_BY_ID["pkg_query"].marker


def test_high_value_sinks_are_not_understated() -> None:
    """Overlay, accessibility, SMS-send and DEX-load are the capabilities that matter."""
    for sink_id in ("overlay", "accessibility", "sms_send", "dex_load"):
        assert SINK_BY_ID[sink_id].severity is Severity.CRITICAL, (
            f"{sink_id} is a critical capability and must be scored as one"
        )
