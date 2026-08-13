"""Config is read in one place, and a missing key fails at startup not mid-analysis."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from drishti.config import Settings


def test_defaults_are_offline_safe() -> None:
    """A fresh checkout must be runnable with no keys at all.

    `mock` as the default provider is what makes `make test` work on a machine that
    has never seen a credential.
    """
    settings = Settings(_env_file=None)
    assert settings.llm_provider == "mock"
    assert settings.resolved_llm_model == "mock"
    assert settings.sandbox_mode == "auto"


def test_gemini_without_a_key_fails_at_construction() -> None:
    """Discovering a missing key at GENAI_STATIC means the run is already half-spent.

    Worse, the failure looks like a model problem rather than a config one.
    """
    with pytest.raises(ValidationError, match="GEMINI_API_KEY"):
        Settings(_env_file=None, llm_provider="gemini", gemini_api_key=None)


def test_anthropic_without_a_key_fails_at_construction() -> None:
    with pytest.raises(ValidationError, match="ANTHROPIC_API_KEY"):
        Settings(_env_file=None, llm_provider="anthropic", anthropic_api_key=None)


def test_provider_with_a_key_is_accepted() -> None:
    settings = Settings(_env_file=None, llm_provider="gemini", gemini_api_key="k")
    assert settings.llm_provider == "gemini"
    assert settings.resolved_llm_model == "gemini-3.1-pro-preview"


def test_explicit_model_overrides_the_provider_default() -> None:
    settings = Settings(
        _env_file=None, llm_provider="gemini", gemini_api_key="k", llm_model="gemini-flash"
    )
    assert settings.resolved_llm_model == "gemini-flash"


def test_api_keys_are_secrets_and_do_not_leak_in_repr() -> None:
    """A settings object ends up in logs and tracebacks. Keys must not."""
    settings = Settings(_env_file=None, llm_provider="gemini", gemini_api_key="super-secret")
    assert "super-secret" not in repr(settings)
    assert "super-secret" not in str(settings)
    assert settings.gemini_api_key is not None
    assert settings.gemini_api_key.get_secret_value() == "super-secret"


def test_env_prefix_is_honoured(monkeypatch) -> None:
    monkeypatch.setenv("DRISHTI_SANDBOX_MODE", "replay")
    monkeypatch.setenv("DRISHTI_LLM_MAX_CALLS_PER_JOB", "7")
    settings = Settings(_env_file=None)
    assert settings.sandbox_mode == "replay"
    assert settings.llm_max_calls_per_job == 7


def test_unprefixed_env_is_ignored(monkeypatch) -> None:
    """Guards against picking up an unrelated variable from the host environment."""
    monkeypatch.setenv("SANDBOX_MODE", "live")
    assert Settings(_env_file=None).sandbox_mode == "auto"


def test_budgets_have_the_documented_defaults() -> None:
    """00_GUIDING_MAP.md §12. These are asserts, not aspirations."""
    settings = Settings(_env_file=None)
    assert settings.llm_max_calls_per_job == 25
    assert settings.llm_max_prompt_tokens == 12_000
    assert settings.static_timeout_s == 90
