"""Test-only HTTP boundary for Groq.

Production has no mock provider or synthetic LLM fallback. Unit and e2e tests avoid
network calls by intercepting the external HTTP request here; `@pytest.mark.gcp` tests
remain live checks and are intentionally not intercepted.
"""

from __future__ import annotations

import json

import httpx
import pytest


@pytest.fixture(autouse=True)
def intercept_groq_http(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep non-lab tests hermetic at the Groq HTTP boundary."""
    if request.node.get_closest_marker("gcp"):
        return

    def test_response(*_args: object, **_kwargs: object) -> httpx.Response:
        content = json.dumps(
            {
                "summary": "Test-only intercepted Groq response.",
                "behaviours": {},
                "claims": [],
            }
        )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": content}}]},
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", test_response)
