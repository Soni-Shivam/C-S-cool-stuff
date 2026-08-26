"""Test-only HTTP boundary for the LLM providers.

Production has no mock provider or synthetic LLM fallback. Unit and e2e tests avoid
network calls by intercepting the external HTTP request here; `@pytest.mark.gcp` tests
remain live checks and are intentionally not intercepted.

The single canned body carries BOTH provider envelopes — Groq's `choices` and Gemini's
`candidates` — because `.env` selects the provider and most tests build `Settings()` from
it. A body that only spoke one dialect would turn a provider flip in `.env` into a wall of
unrelated unit-test failures that say nothing about the code under test.
"""

from __future__ import annotations

import json

import httpx
import pytest


@pytest.fixture(autouse=True)
def intercept_groq_http(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep non-lab tests hermetic at the LLM HTTP boundary."""
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
            json={
                "choices": [{"message": {"content": content}}],
                "candidates": [
                    {"content": {"role": "model", "parts": [{"text": content}]}},
                ],
            },
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", test_response)
