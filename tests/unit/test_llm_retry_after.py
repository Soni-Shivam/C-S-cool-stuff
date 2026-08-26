"""When the provider says how long to wait, waiting less is the same as not retrying.

Measured against the live Groq endpoint on 2026-08-26, running the real pipeline over a
corpus sample. The provider's own words:

    Rate limit reached for model `qwen/qwen3.8-27b` ... service tier `on_demand`
    on tokens per minute (TPM): Limit 8000, Used 4932, Requested 5584.
    Please try again in 18.87s.

That is an account quota, not a defect: the behaviour checklist costs ~4,932 tokens and
the code interpreter's tool loop needs ~5,584, so **one job needs ~10.5k tokens against
an 8k-per-minute ceiling**. The two stages cannot both run inside the same minute.

`MAX_TRANSPORT_ATTEMPTS` is 3 with 1s and 2s backoff — about three seconds of waiting
against a stated 18.87s. Every attempt was therefore guaranteed to fail, the tool loop
returned None, and the dashboard reported "0 methods interpreted · 0 retrieval tool
calls" for the flagship reverse-engineering layer.

So the retry has to honour what the provider actually asked for. The cap exists because
an unbounded sleep read out of an error body is a hang: a pathological or hostile value
must not be able to stall a demo indefinitely.
"""

from __future__ import annotations

import httpx
import pytest

from drishti.m4_genai.client import MAX_RETRY_AFTER_S, retry_delay_from


def _response(status: int, *, body: str = "", headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    return httpx.Response(status, request=request, text=body, headers=headers or {})


def _error(status: int, *, body: str = "", headers: dict[str, str] | None = None) -> httpx.HTTPStatusError:
    response = _response(status, body=body, headers=headers)
    return httpx.HTTPStatusError("rate limited", request=response.request, response=response)


GROQ_BODY = (
    '{"error":{"message":"Rate limit reached for model `qwen/qwen3.8-27b` in organization '
    "`org_x` service tier `on_demand` on tokens per minute (TPM): Limit 8000, Used 4932, "
    'Requested 5584. Please try again in 18.87s. Need more tokens? Upgrade..."}}'
)


def test_the_groq_tpm_message_is_understood() -> None:
    """The exact body observed in production, parsed to the exact number it states."""
    assert retry_delay_from(_error(429, body=GROQ_BODY)) == pytest.approx(18.87, abs=0.01)


def test_it_is_read_from_a_413_too() -> None:
    """Groq reports TPM exhaustion as 413 as well as 429."""
    assert retry_delay_from(_error(413, body=GROQ_BODY)) == pytest.approx(18.87, abs=0.01)


def test_a_retry_after_header_wins_over_the_body() -> None:
    """A header is a contract; a message is prose. Prefer the contract."""
    delay = retry_delay_from(_error(429, body=GROQ_BODY, headers={"retry-after": "5"}))
    assert delay == pytest.approx(5.0)


def test_whole_second_phrasing_is_handled() -> None:
    assert retry_delay_from(_error(429, body="please try again in 7s")) == pytest.approx(7.0)


def test_an_unparseable_body_yields_no_opinion() -> None:
    """No stated delay means fall back to the caller's own backoff, not to zero."""
    assert retry_delay_from(_error(500, body="upstream exploded")) is None
    assert retry_delay_from(_error(429, body="")) is None


def test_a_non_http_error_yields_no_opinion() -> None:
    assert retry_delay_from(httpx.ConnectTimeout("timed out")) is None
    assert retry_delay_from(None) is None


def test_an_absurd_delay_is_capped_not_obeyed() -> None:
    """An unbounded sleep read out of an error body is a hang, not a retry."""
    delay = retry_delay_from(_error(429, body="please try again in 3600s"))
    assert delay == MAX_RETRY_AFTER_S


def test_a_negative_or_zero_delay_is_ignored() -> None:
    assert retry_delay_from(_error(429, body="please try again in 0s")) is None


def test_an_oversized_request_is_not_retried() -> None:
    """"Reduce your message size" cannot be waited out — one request exceeds the ceiling.

    Measured in round 1 of a real tool loop: Limit 8000, Requested 8528. Retrying that
    spent 38 seconds to reach the identical failure, and the model's completed tool calls
    were discarded with it.
    """
    from drishti.m4_genai.client import is_permanently_too_large

    oversized = _error(
        413,
        body='{"error":{"message":"Request too large for model `qwen/qwen3.8-27b` on tokens '
        'per minute (TPM): Limit 8000, Requested 8528, please reduce your message size."}}',
    )
    assert is_permanently_too_large(oversized) is True


def test_a_rolling_window_limit_is_still_retried() -> None:
    """The other 413. Same status, opposite handling — the wording is the only signal."""
    from drishti.m4_genai.client import is_permanently_too_large

    assert is_permanently_too_large(_error(429, body=GROQ_BODY)) is False
    assert retry_delay_from(_error(429, body=GROQ_BODY)) == pytest.approx(18.87, abs=0.01)
