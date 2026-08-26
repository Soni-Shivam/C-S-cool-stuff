"""Config is read in one place, and a missing key fails at startup not mid-analysis."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from drishti.config import Settings


def test_groq_is_the_only_runtime_provider_and_has_the_selected_default_model() -> None:
    """Every runtime LLM request must use Groq, never a synthetic fallback."""
    settings = Settings(_env_file=None, groq_api_key="gsk-test")
    assert settings.llm_provider == "groq"
    assert settings.resolved_llm_model == "qwen/qwen3.8-27b"
    assert settings.sandbox_mode == "auto"


def test_missing_groq_key_fails_at_construction() -> None:
    """A real analysis never falls back to a synthetic LLM completion."""
    with pytest.raises(ValidationError, match="GROQ_API_KEY"):
        Settings(_env_file=None, groq_api_key=None)


def test_explicit_model_overrides_the_provider_default() -> None:
    settings = Settings(_env_file=None, groq_api_key="gsk-test", llm_model="qwen/custom")
    assert settings.resolved_llm_model == "qwen/custom"


def test_api_keys_are_secrets_and_do_not_leak_in_repr() -> None:
    """A settings object ends up in logs and tracebacks. Keys must not."""
    settings = Settings(_env_file=None, groq_api_key="super-secret")
    assert "super-secret" not in repr(settings)
    assert "super-secret" not in str(settings)
    assert settings.groq_api_key is not None
    assert settings.groq_api_key.get_secret_value() == "super-secret"


def test_env_prefix_is_honoured(monkeypatch) -> None:
    monkeypatch.setenv("DRISHTI_SANDBOX_MODE", "replay")
    monkeypatch.setenv("DRISHTI_LLM_MAX_CALLS_PER_JOB", "7")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    settings = Settings(_env_file=None)
    assert settings.sandbox_mode == "replay"
    assert settings.llm_max_calls_per_job == 7


def test_unprefixed_env_is_ignored(monkeypatch) -> None:
    """Guards against picking up an unrelated variable from the host environment."""
    monkeypatch.setenv("SANDBOX_MODE", "live")
    assert Settings(_env_file=None, groq_api_key="gsk-test").sandbox_mode == "auto"


def test_budgets_have_the_documented_defaults() -> None:
    """00_GUIDING_MAP.md §12. These are asserts, not aspirations."""
    settings = Settings(_env_file=None, groq_api_key="gsk-test")
    assert settings.llm_max_calls_per_job == 25
    assert settings.llm_max_prompt_tokens == 12_000
    assert settings.static_timeout_s == 90


def test_the_api_key_is_not_printed_by_repr() -> None:
    """Keys have already been leaked once on this project (CARRIED_FINDINGS H8)."""
    settings = Settings(_env_file=None, groq_api_key="gsk-super-secret")
    assert "gsk-super-secret" not in repr(settings)
    assert settings.groq_api_key is not None
    assert settings.groq_api_key.get_secret_value() == "gsk-super-secret"
