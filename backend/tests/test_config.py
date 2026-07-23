from drishti.config import get_settings


def test_settings_default_embeddings_model():
    s = get_settings()
    assert s.embeddings_model  # non-empty default
    assert s.gemini_api_key is None  # unset by default in test env


def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.1-pro-preview")
    get_settings.cache_clear()
    s = get_settings()
    assert s.gemini_api_key == "test-key"
    assert s.gemini_model == "gemini-3.1-pro-preview"
    get_settings.cache_clear()
