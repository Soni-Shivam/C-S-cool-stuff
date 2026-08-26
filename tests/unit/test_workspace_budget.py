"""The RE workspace must size itself to the provider, not to a Groq-era constant.

`DEFAULT_TOKEN_BUDGET` was cut from 5,000 to 1,800 to make the tool loop fit Groq's
8,000-token-per-minute ceiling, where a single request carrying prompt + reserved output
could not exceed it. That was the right call for Groq and it is now the thing starving
the flagship layer: on Gemini the ceiling is 1,048,576, and the workspace was still 1,800.

The visible symptom, on a real job: 12 sink-reachable methods recovered, 2 interpreted,
and the Reverse Engineering tab telling the reader ten times over that "no validated model
interpretation was produced for this method". The model was not declining to read them —
it was never shown them.

The budget therefore derives from `llm_max_request_tokens`, bounded by our own
`llm_max_prompt_tokens` assert (CLAUDE.md rule 10 — prompts stay under 12k regardless of
what a provider would tolerate), minus room for the system prompt, the tool declarations,
the tool results that come back in round 1, and the answer itself.
"""

from __future__ import annotations

from drishti.config import Settings
from drishti.m4_genai.retrieval import workspace_budget


def _settings(**kw: object) -> Settings:
    base: dict[str, object] = {
        "llm_provider": "groq",
        "llm_model": "qwen/qwen3.8-27b",
        "groq_api_key": "gsk-test",
    }
    base.update(kw)
    return Settings(**base)  # type: ignore[arg-type]


def test_a_small_provider_ceiling_produces_a_small_workspace() -> None:
    """Groq's 8k has to hold prompt AND reserved output, so the workspace stays modest."""
    budget = workspace_budget(_settings(llm_max_request_tokens=8_000))
    assert 1_000 <= budget <= 3_000, budget


def test_a_large_provider_ceiling_is_bounded_by_our_own_prompt_budget() -> None:
    """CLAUDE.md rule 10 caps prompts at 12k whatever the provider would accept."""
    budget = workspace_budget(
        _settings(llm_max_request_tokens=1_048_576, llm_max_prompt_tokens=12_000)
    )
    assert budget < 12_000, "our own budget assert must still bind"
    assert budget > 5_000, f"a 1M-token provider should get a real workspace, got {budget}"


def test_gemini_gets_far_more_room_than_groq() -> None:
    """The regression this file exists for: the same constant for both providers."""
    groq = workspace_budget(_settings(llm_max_request_tokens=8_000))
    gemini = workspace_budget(_settings(llm_max_request_tokens=1_048_576))
    assert gemini > groq * 2, f"gemini {gemini} vs groq {groq}"


def test_the_budget_is_never_negative_or_absurdly_small() -> None:
    """A pathological ceiling must still leave something to read, or degrade honestly."""
    assert workspace_budget(_settings(llm_max_request_tokens=1_000)) >= 500


def test_it_is_deterministic() -> None:
    settings = _settings(llm_max_request_tokens=8_000)
    assert workspace_budget(settings) == workspace_budget(settings)
