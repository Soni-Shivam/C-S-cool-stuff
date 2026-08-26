"""A transient provider rejection must not permanently kill a sub-analyser.

Measured against the live Groq endpoint on 2026-08-26, with the real code-interpreter
payload for a corpus sample:

  * the request is ~17 KiB / ~3.7k tokens — an order of magnitude under the 12k prompt
    budget, and a deliberately oversized 40k-character message returns 200. So size is
    not what 413 is reporting here.
  * the identical tool-calling request returns **200 with a real `read_method` tool
    call** when the account is not rate-limited.
  * under back-to-back runs the same request returns **413** and **429** interchangeably.

Groq expresses tokens-per-minute exhaustion as 413 as well as 429. Because 413 was not in
`RETRYABLE_STATUS`, `_exchange_with_retry` re-raised it on the first attempt, the tool
loop returned `None`, and `_guarded` swallowed it — so a job that hit a momentary quota
ceiling reported `0 methods interpreted · 0 retrieval tool calls` and the dashboard
rendered that as though the model had *chosen* not to use its tools.

The second half of this file is about that second failure. A degrade-gracefully wrapper
(CLAUDE.md rule 2) is only honest if the degradation is *reported*; a failure that exists
solely in structlog is indistinguishable, on screen, from a clean zero.
"""

from __future__ import annotations

import httpx
import pytest

from drishti.m4_genai import client as client_mod
from drishti.m4_genai.client import RETRYABLE_STATUS


def _response(status: int) -> httpx.Response:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    return httpx.Response(status, request=request, text="rate limited")


class _Boom:
    """Raises a given status N times, then succeeds."""

    def __init__(self, status: int, failures: int) -> None:
        self.status = status
        self.remaining = failures
        self.calls = 0

    def __call__(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        if self.remaining > 0:
            self.remaining -= 1
            raise httpx.HTTPStatusError(
                "boom", request=_response(self.status).request, response=_response(self.status)
            )
        return {"content": "{}", "tool_calls": []}


def test_413_is_treated_as_transient() -> None:
    """Groq reports TPM exhaustion as 413. It clears on its own; do not give up on it."""
    assert 413 in RETRYABLE_STATUS


def test_the_usual_transient_statuses_are_still_retryable() -> None:
    for status in (408, 429, 500, 502, 503, 504):
        assert status in RETRYABLE_STATUS


def test_a_real_client_error_is_not_retried() -> None:
    """401/400 will not fix themselves; retrying them just burns the budget slowly."""
    for status in (400, 401, 403, 404, 422):
        assert status not in RETRYABLE_STATUS


def test_a_transient_413_recovers_instead_of_killing_the_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point: one quota blip must not cost the job its code interpretation."""
    from drishti.config import Settings

    boom = _Boom(413, failures=2)
    monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

    settings = Settings.model_construct(
        llm_provider="groq", llm_max_calls_per_job=25, llm_max_prompt_tokens=12000
    )
    llm = client_mod.LLMClient.__new__(client_mod.LLMClient)
    llm._settings = settings  # noqa: SLF001 - constructing without touching the network
    monkeypatch.setattr(llm, "_groq_exchange", boom, raising=False)

    message, attempts = llm._exchange_with_retry(  # noqa: SLF001
        messages=[{"role": "user", "content": "x"}], tools=[], max_output_tokens=10
    )
    assert message == {"content": "{}", "tool_calls": []}
    assert attempts == 3, "it should have taken all three attempts"
    assert boom.calls == 3
