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

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LLMProvider = Literal["groq", "gemini"]
SandboxMode = Literal["live", "replay", "auto"]

#: The model used when `llm_model` is unset. One entry per provider, because a default
#: that is right for one provider is a 404 on the other.
DEFAULT_MODELS: dict[str, str] = {
    "groq": "qwen/qwen3.8-27b",
    # Deliberately the smallest Gemini model. Its 1,048,576-token input window is the
    # reason this provider exists: the shipped Groq tier caps a single request at 8,000
    # tokens, which the code interpreter's second round (prompt + tool results + reserved
    # output) cannot fit, so `interpretations` was 0 on every job.
    #
    # NOT `gemini-2.5-flash-lite`, even though ListModels still advertises it. MEASURED
    # 2026-08-26 against the project's own key: `generateContent` on any 2.5 model answers
    # 404 "This model models/gemini-2.5-flash-lite is no longer available to new users.
    # Please update your code to use models/gemini-3.5-flash-lite". ListModels is not
    # authoritative for what a key may actually call — probe the endpoint, not the list.
    "gemini": "gemini-3.5-flash-lite",
}

#: Which model names belong to which provider. Used only to refuse an obviously
#: cross-wired pair at startup — see `_model_matches_provider`.
_GEMINI_MODEL_PREFIX = "gemini"

#: Gemini's per-request input limit, read from ListModels' `inputTokenLimit` (identical on
#: every 2.5/3.x flash and pro model this key can see).
#: Two orders of magnitude above the Groq free tier's 8,000, which is the entire reason
#: this provider was added.
GEMINI_MAX_REQUEST_TOKENS = 1_048_576


class Settings(BaseSettings):
    """Read from `.env` with a `DRISHTI_` prefix. See `.env.example`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="DRISHTI_",
        extra="ignore",
    )

    # ── LLM ──────────────────────────────────────────────────────────────────
    # Two real providers, selected here and nowhere else. Tests intercept HTTP at their
    # boundary; production never fabricates an LLM completion when a key is unavailable.
    llm_provider: LLMProvider = "groq"
    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GROQ_API_KEY", "DRISHTI_GROQ_API_KEY"),
    )
    gemini_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GEMINI_API_KEY", "DRISHTI_GEMINI_API_KEY"),
    )
    llm_model: str | None = None

    # Budgets are asserts, not hopes (00_GUIDING_MAP.md §12).
    llm_max_calls_per_job: int = 25
    llm_max_prompt_tokens: int = 12_000
    #: Hard ceiling ONE request may occupy at the provider, prompt + reserved output.
    #: Distinct from `llm_max_prompt_tokens`, which is our own budget assert: this one is
    #: the provider's, and exceeding it is refused rather than billed.
    #:
    #: MEASURED 2026-08-26 on the shipped Groq free tier: "Limit 8000, Requested 8528,
    #: please reduce your message size". The reserved `max_tokens` counts toward it, so a
    #: 5,300-token prompt asking for 3,000 output is an 8,300-token request and is
    #: rejected outright — which is why the code interpreter's second round, the one
    #: carrying the tool results back, never completed. Raise this after a tier upgrade.
    #:
    #: The default is the Groq one. When `llm_provider='gemini'` and this was left alone,
    #: `_gemini_lifts_the_request_ceiling` replaces it with Gemini's own input limit —
    #: leaving 8,000 there would keep sizing the interpreter's answer for a ceiling that
    #: no longer exists.
    llm_max_request_tokens: int = 8_000
    llm_cache_enabled: bool = True
    llm_cache_dir: Path = Path(".cache/llm")

    # ── storage ──────────────────────────────────────────────────────────────
    models_dir: Path = Path("models")
    db_path: Path = Path("data/drishti.db")
    ledger_key_path: Path = Path("data/ledger_ed25519.key")

    #: Directory of staged samples with known ground truth, holding the APKs and a
    #: `manifest.json` describing them (contract A21).
    #:
    #: **Unset by default, and that is the safe default.** The samples are real
    #: malware, so they live on the analysis VM and are never committed, never copied
    #: to a laptop, and never served over the API — the catalogue routes offer
    #: metadata and an id to analyse, never the bytes. A checkout with this unset
    #: reports an empty catalogue and the dashboard hides the picker, which is the
    #: correct behaviour on a machine that has no samples rather than an error.
    samples_dir: Path | None = None

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
    #: Icon impersonation (T3.9). DEFAULT OFF: the Groq account exposes 14 models and
    #: NONE of them accept image input, so there is no vision provider to call. The
    #: deterministic perceptual-hash layer still runs and needs no model — but it also
    #: needs reference brand icons, and `data/kb/brand_icons/` ships empty on purpose
    #: (an unverified reference would silently exempt whatever it matched).
    #: So impersonation detection is currently INERT, and says so rather than
    #: returning a confident "no match". Set both when a vision endpoint exists.
    vlm_enabled: bool = False
    #: OpenAI-compatible chat-completions endpoint accepting image_url content parts.
    vlm_base_url: str | None = None
    vlm_api_key: SecretStr | None = None
    vlm_model: str | None = None
    rag_enabled: bool = False

    # ── limits ───────────────────────────────────────────────────────────────
    max_upload_bytes: int = 300 * 1024 * 1024
    job_workers: int = 2

    log_level: str = "INFO"
    log_path: Path = Field(default=Path("logs/drishti.jsonl"))

    @model_validator(mode="after")
    def _provider_has_a_key(self) -> Settings:
        """The selected provider without its key fails at startup, not mid-analysis.

        Discovering a missing key at stage GENAI_STATIC means the run is already
        half-spent, and the failure looks like a model problem rather than a config
        one. Only the *selected* provider is required to have a key: keeping a stale
        Groq key in `.env` must not block a Gemini run, and vice versa.
        """
        if self.llm_provider == "groq" and self.groq_api_key is None:
            raise ValueError("llm_provider='groq' requires GROQ_API_KEY (or DRISHTI_GROQ_API_KEY).")
        if self.llm_provider == "gemini" and self.gemini_api_key is None:
            raise ValueError(
                "llm_provider='gemini' requires GEMINI_API_KEY (or DRISHTI_GEMINI_API_KEY)."
            )
        return self

    @model_validator(mode="after")
    def _model_matches_provider(self) -> Settings:
        """An explicit model from the other provider is a config error, not a 404.

        `.env` pins both `DRISHTI_LLM_PROVIDER` and `DRISHTI_LLM_MODEL`. Flipping only the
        first sends `qwen/qwen3.8-27b` to Gemini, which answers 404 on every call — and
        because every LLM call degrades gracefully (CLAUDE.md rule 2) that reads on screen
        as a model that declined to answer rather than as a typo. Same startup-not-
        mid-analysis argument as the key check above.
        """
        if not self.llm_model:
            return self
        looks_gemini = self.llm_model.removeprefix("models/").startswith(_GEMINI_MODEL_PREFIX)
        if self.llm_provider == "gemini" and not looks_gemini:
            raise ValueError(
                f"llm_provider='gemini' but llm_model={self.llm_model!r} is not a Gemini "
                f"model. Unset DRISHTI_LLM_MODEL to use {DEFAULT_MODELS['gemini']}."
            )
        if self.llm_provider == "groq" and looks_gemini:
            raise ValueError(
                f"llm_provider='groq' but llm_model={self.llm_model!r} is a Gemini model. "
                f"Unset DRISHTI_LLM_MODEL to use {DEFAULT_MODELS['groq']}."
            )
        return self

    @model_validator(mode="after")
    def _gemini_lifts_the_request_ceiling(self) -> Settings:
        """Gemini's per-request input limit is 1,048,576 tokens, not Groq's 8,000.

        Only applied when the field was not set explicitly, so an operator can still pin
        a smaller ceiling. Our own `llm_max_prompt_tokens` budget assert is untouched:
        this is the provider's limit, not permission to send more.
        """
        if self.llm_provider == "gemini" and "llm_max_request_tokens" not in self.model_fields_set:
            self.llm_max_request_tokens = GEMINI_MAX_REQUEST_TOKENS
        return self

    @property
    def resolved_llm_model(self) -> str:
        """Explicit model, else the selected provider's default."""
        if self.llm_model:
            return self.llm_model
        return DEFAULT_MODELS.get(self.llm_provider, DEFAULT_MODELS["groq"])


@lru_cache
def get_settings() -> Settings:
    """Cached accessor. Call `get_settings.cache_clear()` in tests that override env."""
    return Settings()
