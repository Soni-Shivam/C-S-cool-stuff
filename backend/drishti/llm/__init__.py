from drishti.llm.mock import MockProvider
from drishti.llm.provider import LLMProvider


def get_provider(settings=None) -> LLMProvider:
    """Return the live Gemini provider if a key+model are configured, else the
    deterministic offline MockProvider."""
    if settings is None:
        from drishti.config import get_settings

        settings = get_settings()
    if settings.gemini_api_key and settings.gemini_model:
        from drishti.llm.gemini import GeminiProvider

        return GeminiProvider(settings.gemini_api_key, settings.gemini_model)
    return MockProvider()


__all__ = ["LLMProvider", "MockProvider", "get_provider"]
