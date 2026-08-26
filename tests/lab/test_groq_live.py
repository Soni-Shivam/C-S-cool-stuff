"""Live Groq check. Excluded from CI by the `gcp` marker.

CI must not depend on a third party being reachable, and it must not spend anyone's
quota. Run deliberately:

    uv run pytest tests/lab/test_groq_live.py -m gcp
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from drishti.config import Settings
from drishti.m4_genai.client import LLMClient

pytestmark = pytest.mark.gcp


class Shape(BaseModel):
    verdict: str
    confident: bool


@pytest.fixture
def live_settings() -> Settings:
    settings = Settings()
    if settings.llm_provider != "groq" or settings.groq_api_key is None:
        pytest.skip("Groq is not configured")
    return settings


def test_a_real_completion_comes_back(live_settings: Settings) -> None:
    client = LLMClient(live_settings, use_cache=False)
    out = client.complete(system="Reply concisely.", user="Reply with exactly: LIVE_OK")
    assert out is not None and "LIVE_OK" in out


def test_the_model_can_produce_the_required_schema(live_settings: Settings) -> None:
    """Whether this model reliably emits strict JSON is a real risk for T3.3."""
    client = LLMClient(live_settings, use_cache=False)
    result = client.complete_as(
        system=(
            "You output ONLY valid JSON matching the schema. No prose, no code fences. "
            'Schema: {"verdict": string, "confident": boolean}'
        ),
        user='Return {"verdict": "benign", "confident": true}',
        schema=Shape,
    )
    assert result is not None, "model could not produce strict JSON even after repair"
    assert isinstance(result.confident, bool)
