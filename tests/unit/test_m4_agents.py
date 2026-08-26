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
from drishti.m4_genai.agents.code_interpreter import (
    InterpretationOut,
    InterpretationSet,
    explain_paths,
    interpret_methods,
    normalise_signature,
    resolve_signature,
)
from drishti.m4_genai.agents.technique_mapper import load_kb, map_techniques
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.retrieval import select

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
    settings = Settings(groq_api_key="gsk-test", llm_cache_dir=tmp_path / "c")
    empty = report.model_copy(update={"call_paths": ()})
    assert explain_paths(empty, store, "job_agents", LLMClient(settings, use_cache=False)) == ()


def test_explanations_cite_the_path_they_describe(ledger, tmp_path: Path) -> None:
    store, report = ledger
    settings = Settings(groq_api_key="gsk-test", llm_cache_dir=tmp_path / "c")
    for claim in explain_paths(report, store, "job_agents", LLMClient(settings, use_cache=False)):
        assert claim.agent == "code_interpreter"
        for ref in claim.evidence_refs:
            assert store.get(ref) is not None


# ── code interpreter: signature identity ─────────────────────────────────────
# Our canonical form is `Lpkg/Cls;->method` with NO parameter descriptor. Handed the
# source, the model writes the parameters back, or writes the class in Java spelling.
# Measured over five live calls on the canary, ZERO of five matched by string equality
# and all five interpretations were dropped — the Reverse Engineering view showed code
# with no reading beside it, and the run blamed a provider that had answered correctly.
@pytest.mark.parametrize(
    "returned",
    [
        "Lin/drishti/canary/MainActivity;->onCreate",
        "Lin/drishti/canary/MainActivity;->onCreate(Landroid/os/Bundle;)V",
        "in.drishti.canary.MainActivity;->onCreate(android.os.Bundle)",
        "in.drishti.canary.MainActivity;->onCreate",
        "in.drishti.canary.MainActivity.onCreate",
        "  Lin/drishti/canary/MainActivity;->onCreate(Landroid/os/Bundle;)V  ",
    ],
)
def test_every_spelling_of_a_signature_resolves_to_the_one_we_recovered(returned: str) -> None:
    """Identity is the class and method, not the transcription the model chose."""
    canonical = "Lin/drishti/canary/MainActivity;->onCreate"
    assert resolve_signature(returned, [canonical]) == canonical


def test_a_method_we_did_not_recover_still_resolves_to_nothing() -> None:
    """The grounding rule is unchanged: only the spelling is forgiven, never the method."""
    canonical = "Lin/drishti/canary/MainActivity;->onCreate"
    for absent in (
        "Lin/drishti/canary/MainActivity;->onResume",
        "Lcom/evil/Payload;->onCreate",
        "",
        "not a signature at all",
    ):
        assert resolve_signature(absent, [canonical]) is None


def test_an_ambiguous_signature_is_dropped_rather_than_guessed() -> None:
    """Two candidates normalising alike means we cannot say which was read. Refuse."""
    candidates = ["La/b/C;->run", "La.b.C;->run"]
    assert resolve_signature("a.b.C.run", candidates) is None


def test_an_exact_match_wins_before_any_normalisation() -> None:
    """Normalisation is a fallback, never a rewrite of a signature that already matched."""
    exact = "La/b/C;->run(I)V"
    assert resolve_signature(exact, [exact, "La/b/C;->run"]) == exact


def test_normalisation_keeps_a_class_whose_name_begins_with_l() -> None:
    """`Llama` is a class, `L` is a descriptor prefix — only strip when one follows."""
    assert normalise_signature("Lcom/x/Llama;->go") == "com.x.Llama.go"
    assert normalise_signature("Llama;->go") == "Llama.go"


def test_a_kept_interpretation_is_stored_under_the_canonical_signature(
    ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The UI joins interpretation to source on this exact string, so it must be ours.

    Storing the model's spelling would leave the reading orphaned beside the code even
    when it was kept — the same blank panel, one layer further along.
    """
    store, report = ledger
    settings = Settings(groq_api_key="gsk-test", llm_cache_dir=tmp_path / "c")
    client = LLMClient(settings, use_cache=False)
    pack = select(report)
    canonical = pack.chains[0].methods[0].signature

    def reply(**_: object) -> InterpretationSet:
        return InterpretationSet(
            interpretations=[
                InterpretationOut(
                    # Java spelling with a descriptor: what the live model returned on
                    # four of five measured runs.
                    method_signature=canonical.lstrip("L").replace("/", ".")
                    + "(android.os.Bundle)",
                    summary="probes the package manager and counts SMS",
                    confidence="high",
                )
            ]
        )

    monkeypatch.setattr(client, "complete_with_tools_as", reply)
    kept, _, _ = interpret_methods(report, store, "job_agents", client, pack=pack)
    assert [k.method_signature for k in kept] == [canonical]


def test_an_empty_pass_names_the_cause_it_observed(
    ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three failures, three different sentences. None of them may blame the provider.

    "provider unavailable or response invalid after retry" was printed for all of them,
    including the case where the provider answered correctly and we discarded the
    answer. A banner naming the wrong subsystem is a false claim on the dashboard.
    """
    store, report = ledger
    settings = Settings(groq_api_key="gsk-test", llm_cache_dir=tmp_path / "c")
    pack = select(report)

    def run(reply, failure=None) -> list[str]:
        client = LLMClient(settings, use_cache=False)
        client.last_failure = failure
        monkeypatch.setattr(client, "complete_with_tools_as", lambda **_: reply)
        notes: list[str] = []
        got, _, _ = interpret_methods(
            report, store, "job_agents", client, pack=pack, diagnostics=notes
        )
        assert got == ()
        assert len(notes) == 1
        return notes

    # 1. The request never produced a usable reply: the client's own words, verbatim.
    transport = run(None, failure="the request to the model failed: connect timeout")
    assert "connect timeout" in transport[0]

    # 2. The model answered, and named a method outside this analysis.
    dropped = run(
        InterpretationSet(
            interpretations=[InterpretationOut(method_signature="Lcom/evil/Never;->seen")]
        )
    )
    assert "did not recover" in dropped[0]
    assert "Lcom/evil/Never;->seen" in dropped[0]
    assert "provider" not in dropped[0]

    # 3. The model answered with an empty list. Also not a provider problem.
    empty = run(InterpretationSet(interpretations=[]))
    assert "no interpretations" in empty[0]
    assert "unavailable" not in empty[0]
