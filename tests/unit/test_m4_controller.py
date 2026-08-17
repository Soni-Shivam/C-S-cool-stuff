"""M4 controller: prompt assembly, grounding, and degradation.

docs/PHASE_3_GENAI_CORE.md T3.3, T3.6.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.config import Settings
from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse as static_analyse
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.controller import analyse, build_system_prompt, build_user_turn

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        llm_provider="mock",
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )


@pytest.fixture
def static_report(settings: Settings):
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    store.open("job_ctrl")
    try:
        yield static_analyse(CANARY, store), store
    finally:
        store.close()


def test_the_system_prompt_carries_no_sample_text() -> None:
    """System prompt must be static. Sample text belongs in the user turn only."""
    system = build_system_prompt()
    assert "untrusted_artifact" in system  # it explains the convention
    assert "<untrusted_artifact " not in system  # but contains no actual block


def test_the_system_prompt_lists_every_behaviour(static_report) -> None:
    from drishti.m4_genai.safety import BEHAVIOUR_WEIGHTS

    system = build_system_prompt()
    for name in BEHAVIOUR_WEIGHTS:
        assert name in system, f"{name} is weighted but never asked about"


def test_sample_derived_text_is_wrapped(static_report) -> None:
    report, _ = static_report
    user = build_user_turn(report)
    if report.urls or report.crypto_constants or report.call_paths:
        assert "<untrusted_artifact" in user


def test_the_user_turn_stays_within_budget(static_report, settings: Settings) -> None:
    report, _ = static_report
    combined = build_system_prompt() + build_user_turn(report)
    assert len(combined) // 4 < settings.llm_max_prompt_tokens


def test_b_is_computed_locally_not_read_from_the_model(static_report, settings) -> None:
    """The verdict's B must equal the weight table's answer for those booleans."""
    from drishti.m4_genai.safety import behavioural_risk

    report, store = static_report
    verdict = analyse(report, store, settings)
    expected, _ = behavioural_risk(verdict.behaviours)
    assert verdict.behavioural_risk_B == expected


def test_a_provider_outage_degrades_rather_than_losing_the_report(
    static_report, settings: Settings
) -> None:
    """Losing M2's work to an LLM timeout would be absurd."""
    report, store = static_report
    broken = settings.model_copy(update={"llm_provider": "gemini"})
    verdict = analyse(report, store, broken, client=LLMClient(broken, use_cache=False))
    assert verdict.partial is True
    assert verdict.errors
    assert verdict.behavioural_risk_B == 0.0


def test_claims_cite_the_static_nodes_they_rest_on(static_report, settings: Settings) -> None:
    """ledger.append() rejects an ungrounded AI_CLAIM — that rejection is the product."""
    report, store = static_report
    verdict = analyse(report, store, settings)
    if not verdict.partial:
        assert verdict.ledger_refs
        assert set(report.ledger_refs).issubset(set(verdict.ledger_refs))
