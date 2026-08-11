from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gemini_api_key: str | None = None
    gemini_model: str | None = None
    androzoo_api_key: str | None = None
    ledger_signing_key: str | None = None
    embeddings_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    demo_api_token: str = "change-this-demo-token"
    max_upload_bytes: int = 100 * 1024 * 1024
    quarantine_dir: Path = Path("/tmp/drishti-quarantine")
    observations_dir: Path = Path("/tmp/drishti-observations")
    trained_model_path: Path | None = None
    ml_model_version: str = "baseline-synthetic-v1"
    analysis_workers: int = 1

    @field_validator("trained_model_path", mode="before")
    @classmethod
    def empty_model_path_is_none(cls, value):
        return None if value in (None, "") else value


@lru_cache
def get_settings() -> Settings:
    return Settings()
