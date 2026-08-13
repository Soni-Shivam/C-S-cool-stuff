"""One settings object. Nothing anywhere else reads `os.environ`.

docs/PHASE_0_FOUNDATIONS.md T0.2.

That rule is not tidiness. Config read at the point of use is config nobody can
audit: you cannot answer "was the sandbox live for this run?" by reading one place,
and the honesty requirements in CLAUDE.md depend on being able to.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LLMProvider = Literal["gemini", "anthropic", "mock"]
SandboxMode = Literal["live", "replay", "auto"]


class Settings(BaseSettings):
    """Read from `.env` with a `DRISHTI_` prefix. See `.env.example`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="DRISHTI_",
        extra="ignore",
    )

    # ── LLM ──────────────────────────────────────────────────────────────────
    # `mock` is deterministic and needs no key, so tests and offline demos never
    # depend on a provider being reachable.
    llm_provider: LLMProvider = "mock"
    gemini_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    llm_model: str | None = None

    # Budgets are asserts, not hopes (00_GUIDING_MAP.md §12).
    llm_max_calls_per_job: int = 25
    llm_max_prompt_tokens: int = 12_000
    llm_cache_enabled: bool = True
    llm_cache_dir: Path = Path(".cache/llm")

    # ── storage ──────────────────────────────────────────────────────────────
    db_path: Path = Path("data/drishti.db")
    ledger_key_path: Path = Path("data/ledger_ed25519.key")

    # ── static ───────────────────────────────────────────────────────────────
    static_timeout_s: int = 90
    mobsf_enabled: bool = False
    mobsf_url: str = "http://localhost:8000"

    # ── sandbox ──────────────────────────────────────────────────────────────
    # "auto" tries live and falls back to replay when LiveSandboxSource.available()
    # is False. This is the Replay-Mode parachute, wired in from hour one so the
    # PHASE_4 tripwire costs 20 minutes instead of 6 hours.
    sandbox_enabled: bool = True
    sandbox_mode: SandboxMode = "auto"
    sandbox_duration_s: int = 120

    # ── GCP lab ──────────────────────────────────────────────────────────────
    # The only place a real sample is ever executed. A laptop must never point these
    # at a reachable detonator and run a sample locally — see CLAUDE.md.
    gcp_project: str | None = None
    gcp_zone: str = "asia-south1-a"
    gcp_detonator_instance: str = "drishti-detonator"
    gcs_corpus_bucket: str | None = None
    gcs_artifacts_bucket: str | None = None
    gcs_models_bucket: str | None = None

    # ── corpus (training only, never at request time) ────────────────────────
    androzoo_api_key: SecretStr | None = None
    malwarebazaar_api_key: SecretStr | None = None

    # ── feature flags ────────────────────────────────────────────────────────
    vlm_enabled: bool = True
    rag_enabled: bool = False

    # ── limits ───────────────────────────────────────────────────────────────
    max_upload_bytes: int = 300 * 1024 * 1024
    job_workers: int = 2

    log_level: str = "INFO"
    log_path: Path = Field(default=Path("logs/drishti.jsonl"))

    @model_validator(mode="after")
    def _provider_has_a_key(self) -> Settings:
        """A non-mock provider without a key fails at startup, not mid-analysis.

        Discovering a missing key at stage GENAI_STATIC means the run is already
        half-spent, and the failure looks like a model problem rather than a config
        one.
        """
        required = {"gemini": self.gemini_api_key, "anthropic": self.anthropic_api_key}
        if self.llm_provider in required and required[self.llm_provider] is None:
            raise ValueError(
                f"llm_provider={self.llm_provider!r} requires "
                f"DRISHTI_{self.llm_provider.upper()}_API_KEY. "
                "Use DRISHTI_LLM_PROVIDER=mock for offline work."
            )
        return self

    @property
    def resolved_llm_model(self) -> str:
        """Explicit model, else the provider's default."""
        if self.llm_model:
            return self.llm_model
        return {
            "gemini": "gemini-3.1-pro-preview",
            "anthropic": "claude-sonnet-4-5",
            "mock": "mock",
        }[self.llm_provider]


@lru_cache
def get_settings() -> Settings:
    """Cached accessor. Call `get_settings.cache_clear()` in tests that override env."""
    return Settings()
