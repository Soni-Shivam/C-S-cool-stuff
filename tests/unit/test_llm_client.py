"""LLM client: budgets, caching, and output that is never structurally trusted.

docs/PHASE_3_GENAI_CORE.md T3.1, docs/00_GUIDING_MAP.md §9.4 and §12.

No test here calls a real provider. The live check lives in
`tests/lab/test_openrouter_live.py`, marked so CI never runs it — CI must not depend on
a third party being up, and it must not spend anyone's quota.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel

from drishti.config import Settings
from drishti.m4_genai.client import (
    BudgetExceededError,
    LLMClient,
    parse_and_validate,
    strip_fences,
)


class Verdict(BaseModel):
    summary: str
    behaviours: dict[str, bool] = {}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        llm_provider="mock",
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )


# ── output is never structurally trusted ─────────────────────────────────────
def test_code_fences_are_stripped() -> None:
    assert strip_fences('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert strip_fences('```\n{"a": 1}\n```') == '{"a": 1}'
    assert strip_fences('{"a": 1}') == '{"a": 1}'


def test_prose_around_json_is_not_regex_scraped() -> None:
    """§9.4: never regex-scrape a value out of prose. Unparseable means None."""
    assert parse_and_validate("Sure! Here is the verdict: score is 90.", Verdict) is None


def test_a_json_array_is_rejected() -> None:
    """A top-level array is not the contract, and must not be coerced into one."""
    assert parse_and_validate('[{"summary": "x"}]', Verdict) is None


def test_valid_json_validates_into_the_contract() -> None:
    parsed = parse_and_validate('{"summary": "ok", "behaviours": {"a": true}}', Verdict)
    assert parsed is not None
    assert parsed.summary == "ok"


def test_schema_violations_are_rejected() -> None:
    assert parse_and_validate('{"behaviours": {"a": true}}', Verdict) is None  # no summary
    assert parse_and_validate('{"summary": "x", "behaviours": {"a": "yes"}}', Verdict) is None


# ── budgets are asserts, not hopes ───────────────────────────────────────────
def test_call_budget_raises_rather_than_logging(settings: Settings) -> None:
    """A runaway agent loop is a bill and a hung demo. It must stop hard."""
    client = LLMClient(settings, use_cache=False)
    for _ in range(settings.llm_max_calls_per_job):
        client.complete(system="s", user="u")
    with pytest.raises(BudgetExceededError, match="call budget"):
        client.complete(system="s", user="u")


def test_oversized_prompt_is_refused_before_it_is_sent(settings: Settings) -> None:
    client = LLMClient(settings, use_cache=False)
    huge = "x" * (settings.llm_max_prompt_tokens * 4 + 100)
    with pytest.raises(BudgetExceededError, match="tokens"):
        client.complete(system="s", user=huge)
    assert client.calls_made == 0, "the budget must be checked BEFORE the call is made"


def test_budget_errors_are_not_swallowed_as_degradation(settings: Settings) -> None:
    """Provider failures degrade to None; a blown budget is a caller bug and propagates."""
    client = LLMClient(settings, use_cache=False)
    client.calls_made = settings.llm_max_calls_per_job
    with pytest.raises(BudgetExceededError):
        client.complete(system="s", user="u")


# ── caching ──────────────────────────────────────────────────────────────────
def test_identical_prompts_hit_the_cache(settings: Settings) -> None:
    client = LLMClient(settings, use_cache=True)
    first = client.complete(system="s", user="u")
    calls_after_first = client.calls_made
    second = client.complete(system="s", user="u")
    assert first == second
    assert client.calls_made == calls_after_first, "a cache hit must not spend budget"


def test_a_different_prompt_misses_the_cache(settings: Settings) -> None:
    client = LLMClient(settings, use_cache=True)
    client.complete(system="s", user="u")
    before = client.calls_made
    client.complete(system="s", user="different")
    assert client.calls_made == before + 1


def test_no_cache_flag_disables_reuse(settings: Settings) -> None:
    """`--no-cache` exists for honesty if a judge asks whether the demo is canned."""
    client = LLMClient(settings, use_cache=False)
    client.complete(system="s", user="u")
    before = client.calls_made
    client.complete(system="s", user="u")
    assert client.calls_made == before + 1


# ── degradation ──────────────────────────────────────────────────────────────
def test_provider_failure_returns_none_rather_than_raising(settings: Settings) -> None:
    """A failed LLM call must never lose the static report (§9.2)."""
    broken = settings.model_copy(update={"llm_provider": "gemini"})
    client = LLMClient(broken, use_cache=False)
    assert client.complete(system="s", user="u") is None


def test_the_mock_provider_is_deterministic(settings: Settings) -> None:
    """Offline demos and tests need a stand-in that does not pretend to be a model."""
    a = LLMClient(settings, use_cache=False).complete(system="s", user="u")
    b = LLMClient(settings, use_cache=False).complete(system="s", user="u")
    assert a == b and a is not None


def test_complete_as_validates_into_the_contract(settings: Settings) -> None:
    client = LLMClient(settings, use_cache=False)

    class MockShape(BaseModel):
        summary: str
        behaviours: dict[str, bool]

    result = client.complete_as(system="s", user="u", schema=MockShape)
    assert result is not None
    assert isinstance(result.behaviours, dict)
