"""Tests for the deterministic core of the static-analysis engine."""

from __future__ import annotations

from pathlib import Path

import networkx as nx

from drishti.contracts.static_report import Component, ComponentKind, HypothesisKind
from drishti.ledger.store import LedgerStore
from drishti.m2_static.callgraph import backward_paths
from drishti.m2_static.engine import analyse
from drishti.m2_static.hypotheses import derive_hypotheses
from drishti.m2_static.rules import effective_exported, evaluate_permission_combos


def test_effective_exported_obeys_explicit_and_legacy_rules() -> None:
    """An explicit manifest value wins; legacy intent filters imply export."""
    assert effective_exported(explicit=False, has_intent_filter=True, target_sdk=30) is False
    assert effective_exported(explicit=None, has_intent_filter=True, target_sdk=30) is True
    assert effective_exported(explicit=None, has_intent_filter=False, target_sdk=35) is False


def test_permission_combos_require_the_full_surface() -> None:
    """Combination matches preserve their exact declared-permission evidence."""
    combos = evaluate_permission_combos(
        permissions={"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"},
        components=(),
    )
    assert [combo.rule_id for combo in combos] == ["OTP_THEFT_SURFACE"]
    assert combos[0].permissions == (
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
    )


def test_backward_paths_returns_the_shortest_entrypoint_attributed_path() -> None:
    """Backward traversal must not prefer a longer explanation over a short one."""
    graph = nx.DiGraph()
    graph.add_edges_from(
        [
            ("receiver.onReceive", "parse"),
            ("parse", "sink.sms"),
            ("other", "middle"),
            ("middle", "parse"),
        ]
    )
    paths = backward_paths(
        graph,
        sink="sink.sms",
        entrypoints={"receiver.onReceive": "broadcast_receiver"},
        max_depth=6,
        max_paths=5,
    )
    assert len(paths) == 1
    assert paths[0].path == ("receiver.onReceive", "parse", "sink.sms")
    assert paths[0].entrypoint_kind == "broadcast_receiver"


def test_target_app_probe_hypothesis_carries_candidates() -> None:
    """A package-manager sink plus target package strings drives the frontier loop."""
    hypotheses = derive_hypotheses(
        sink_hits={"pkg_query"},
        permission_combos=(),
        package_strings=("com.sbi.yono", "com.example.library"),
        urls=(),
        dcl_indicators=(),
        evidence_refs=("ev_sink",),
    )
    probe = next(item for item in hypotheses if item.kind is HypothesisKind.TARGET_APP_PROBE)
    assert probe.suggested_probe == {
        "morph": "install_packages",
        "candidates": ["com.sbi.yono"],
    }


def test_overlay_combo_requires_a_service() -> None:
    """Overlay permission alone is not enough to assert the service-backed pattern."""
    permissions = {"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"}
    assert not evaluate_permission_combos(permissions=permissions, components=())
    service = Component(name=".Overlay", kind=ComponentKind.SERVICE, exported=False)
    assert [
        combo.rule_id
        for combo in evaluate_permission_combos(permissions=permissions, components=(service,))
    ] == ["OVERLAY_CREDENTIAL_THEFT"]


def test_canary_static_parse_is_data_only_and_produces_a_chained_report(tmp_path: Path) -> None:
    """The authored inert canary exercises M2 parsing, never Android execution."""
    repo_root = Path(__file__).resolve().parents[2]
    with LedgerStore(tmp_path / "ledger.db", tmp_path / "ledger.key") as ledger:
        ledger.open("job_canary_static")
        report = analyse(repo_root / "canary/dist/canary.apk", ledger)
        assert report.package == "in.drishti.canary"
        assert not report.partial, report.errors
        assert "android.permission.INTERNET" in report.permissions
        assert ledger.verify_chain().ok
