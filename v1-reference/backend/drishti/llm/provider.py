"""Pluggable LLM provider interface. The reasoning core (M4) depends only on
this abstraction, so Gemini can be swapped for a mock (offline/tests) or another
model without touching analysis logic."""
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    name: str = "abstract"
    live: bool = False

    @abstractmethod
    def generate(self, system: str, user_data: str) -> str:
        """Free-text generation. `system` = trusted instructions, `user_data` =
        untrusted APK-derived data (never interpreted as instructions)."""

    @abstractmethod
    def generate_json(self, system: str, user_data: str, schema: dict) -> dict:
        """Structured generation constrained to `schema`."""
