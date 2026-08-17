"""Technique Mapper and Code Interpreter.

docs/PHASE_3_GENAI_CORE.md T3.4, T3.7.

The mapper's defining property is that it CANNOT invent a technique id. A language
model asked for MITRE ids will happily produce plausible-looking ones, and a technique
id is exactly the sort of authoritative token a reader does not think to check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from drishti.config import Settings
from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse
from drishti.m2_static.sinks import SINKS
from drishti.m4_genai.agents.code_interpreter import explain_paths
from drishti.m4_genai.agents.technique_mapper import load_kb, map_techniques
from drishti.m4_genai.client import LLMClient

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "canary" / "dist" / "canary.apk"
KB = REPO / "data" / "kb" / "mitre_mobile.json"
RULES = REPO / "drishti" / "m2_static" / "rules" / "permission_combos.yaml"


@pytest.fixture
def ledger(tmp_path: Path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_agents")
    yield store, analyse(CANARY, store)
    store.close()


# ── knowledge base ───────────────────────────────────────────────────────────
def test_the_kb_covers_every_technique_the_detections_reference() -> None:
    """A detection citing a technique the KB cannot name would produce a blank mapping."""
    kb = json.loads(KB.read_text())["techniques"]
    referenced = {s.mitre for s in SINKS} | {r["mitre"] for r in yaml.safe_load(RULES.read_text())}
    assert referenced - set(kb) == set(), "detections reference techniques absent from the KB"


def test_the_kb_carries_no_unreferenced_techniques() -> None:
    """A technique with no evidence path is one we could never ground a claim on."""
    kb = json.loads(KB.read_text())["techniques"]
    referenced = {s.mitre for s in SINKS} | {r["mitre"] for r in yaml.safe_load(RULES.read_text())}
    assert set(kb) - referenced == set()


def test_every_kb_entry_is_complete() -> None:
    for technique, entry in json.loads(KB.read_text())["techniques"].items():
        assert technique.startswith("T")
        for field in ("name", "tactic", "description"):
            assert entry.get(field), f"{technique} is missing {field}"


# ── technique mapper ─────────────────────────────────────────────────────────
def test_mapped_techniques_all_exist_in_the_kb(ledger) -> None:
    """The property that makes hallucination structurally impossible."""
    store, report = ledger
    kb = load_kb()
    for mapping in map_techniques(report, store, "job_agents"):
        assert mapping.technique_id in kb
        assert mapping.name == kb[mapping.technique_id]["name"]


def test_mappings_cite_evidence(ledger) -> None:
    store, report = ledger
    mappings = map_techniques(report, store, "job_agents")
    assert mappings, "the canary reaches sinks, so techniques must be derived"
    grounded = [m for m in mappings if m.evidence_refs]
    assert grounded, "at least one technique must cite a real ledger node"
    for mapping in grounded:
        for ref in mapping.evidence_refs:
            assert store.get(ref) is not None, "a mapping cited a node that does not exist"


def test_static_analysis_never_claims_a_dynamic_layer(ledger) -> None:
    """Conflating "could do this" with "we watched it" would overstate every finding."""
    store, report = ledger
    assert all(m.layer == "static" for m in map_techniques(report, store, "job_agents"))


def test_a_missing_kb_yields_no_techniques(ledger, tmp_path: Path) -> None:
    """Better to assert nothing than to assert a technique we cannot describe."""
    store, report = ledger
    load_kb.cache_clear()
    try:
        assert (
            map_techniques(report, store, "job_agents", kb_path=str(tmp_path / "gone.json")) == ()
        )
    finally:
        load_kb.cache_clear()


# ── code interpreter ─────────────────────────────────────────────────────────
def test_no_call_paths_means_no_explanations(ledger, tmp_path: Path) -> None:
    """It must not invent narrative for code it was never shown."""
    store, report = ledger
    settings = Settings(llm_provider="mock", llm_cache_dir=tmp_path / "c")
    empty = report.model_copy(update={"call_paths": ()})
    assert explain_paths(empty, store, "job_agents", LLMClient(settings, use_cache=False)) == ()


def test_explanations_cite_the_path_they_describe(ledger, tmp_path: Path) -> None:
    store, report = ledger
    settings = Settings(llm_provider="mock", llm_cache_dir=tmp_path / "c")
    for claim in explain_paths(report, store, "job_agents", LLMClient(settings, use_cache=False)):
        assert claim.agent == "code_interpreter"
        for ref in claim.evidence_refs:
            assert store.get(ref) is not None
