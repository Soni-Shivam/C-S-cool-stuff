"""One analysis must stay inside the ledger node sanity band.

docs/00_GUIDING_MAP.md §12 sets 50-400 nodes per APK. A real 50 MB sample produced
**516**, of which 505 were `manifest_entry` — one per component. A ledger that grows
linearly with an app's component count is a ledger nobody can read, and it inflates
every prompt built from it.

This is the same explosion CLAUDE.md rule 11 already forbids for dynamic events (one
sample emitted 1,925 `Cipher.doFinal` calls), applied where it happens statically.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.contracts.static_report import Component, ComponentKind
from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import MAX_INDIVIDUAL_COMPONENTS, _write_manifest_evidence

LEDGER_NODE_CEILING = 400


def _component(index: int, *, exported: bool, permission: str | None) -> Component:
    return Component(
        name=f"com.example.C{index}",
        kind=ComponentKind.ACTIVITY,
        exported=exported,
        permission=permission,
        intent_filters=(),
    )


@pytest.fixture
def store(tmp_path: Path):
    ledger = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    ledger.open("job_budget")
    yield ledger
    ledger.close()


def test_a_component_heavy_app_stays_inside_the_budget(store) -> None:
    """453 components is a real number, measured on a real sample."""
    components = tuple(_component(i, exported=False, permission=None) for i in range(453))
    _write_manifest_evidence(
        store, permissions=tuple(f"perm.P{i}" for i in range(52)), components=components
    )
    count = store.count("job_budget")
    assert count <= LEDGER_NODE_CEILING, (
        f"{count} nodes for one app exceeds the {LEDGER_NODE_CEILING}-node sanity band"
    )


def test_exported_unprotected_components_keep_their_own_nodes(store) -> None:
    """The attack surface stays individually addressable; ordinary UI does not."""
    components = (
        *(_component(i, exported=True, permission=None) for i in range(5)),
        *(_component(100 + i, exported=False, permission=None) for i in range(200)),
    )
    _write_manifest_evidence(store, permissions=(), components=components)
    nodes = store.query(job_id="job_budget")
    individual = [n for n in nodes if n.content.get("kind") == "activity"]
    summary = [n for n in nodes if n.content.get("kind") == "component_summary"]
    assert len(individual) == 5, "each exported-unprotected component keeps a node"
    assert len(summary) == 1, "everything else is summarised into one node"
    assert summary[0].content["total"] == 200


def test_nothing_is_lost_only_the_node_count(store) -> None:
    """Aggregation must preserve the counts a report would quote."""
    components = tuple(_component(i, exported=False, permission=None) for i in range(60))
    _write_manifest_evidence(store, permissions=(), components=components)
    summary = next(
        n for n in store.query(job_id="job_budget") if n.content.get("kind") == "component_summary"
    )
    assert summary.content["counts"]["activity"] == 60


def test_permissions_keep_individual_nodes(store) -> None:
    """Combo rules cite permissions as parents, so they must stay addressable."""
    refs = _write_manifest_evidence(store, permissions=("a.B", "a.C"), components=())
    assert set(refs) == {"a.B", "a.C"}
    assert all(refs.values())


def test_the_cap_is_enforced(store) -> None:
    exported = tuple(
        _component(i, exported=True, permission=None) for i in range(MAX_INDIVIDUAL_COMPONENTS + 30)
    )
    _write_manifest_evidence(store, permissions=(), components=exported)
    nodes = store.query(job_id="job_budget")
    individual = [n for n in nodes if n.content.get("kind") == "activity"]
    assert len(individual) == MAX_INDIVIDUAL_COMPONENTS
