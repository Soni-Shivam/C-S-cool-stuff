from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gemini_api_key: str | None = None
    gemini_model: str | None = None
    androzoo_api_key: str | None = None
    ledger_signing_key: str | None = None
    embeddings_model: str = "sentence-transformers/all-MiniLM-L6-v2"


@lru_cache
def get_settings() -> Settings:
    return Settings()
