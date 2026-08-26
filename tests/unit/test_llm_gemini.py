"""The Gemini transport: same call surface, a completely different wire shape.

docs/PHASE_3_GENAI_CORE.md T3.1. Gemini exists here for one measured reason: the shipped
Groq tier refuses a single request over 8,000 tokens ("Limit 8000, Requested 8528"), and
the code interpreter's second round — prompt + tool results + reserved output — does not
fit under that. `gemini-3.5-flash-lite` accepts 1,048,576 input tokens, so the round that
actually produces `interpretations` can run at all.

No test here makes a network call or needs a key. Every one of them asserts on the exact
JSON that would have gone over the wire, because the shape is where this integration can
be silently wrong: a body Groq accepts is a 400 at Gemini, and a 400 degrades to `None`
(CLAUDE.md rule 2) — which on screen is indistinguishable from a model that had nothing
to say.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, Field, ValidationError

from drishti.config import GEMINI_MAX_REQUEST_TOKENS, Settings
from drishti.m4_genai.client import (
    LLMClient,
    message_from_gemini,
    retry_delay_from,
    sanitise_tool_schema,
    to_gemini_contents,
    to_gemini_tools,
)


class Verdict(BaseModel):
    summary: str
    behaviours: dict[str, bool] = {}


@pytest.fixture
def gemini_settings(tmp_path: Path) -> Settings:
    """A Gemini-selected settings object with a fake key. Never reads `.env`."""
    return Settings(
        _env_file=None,
        llm_provider="gemini",
        gemini_api_key="test-key-not-real",
        llm_model=None,
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )


class _Recorder:
    """Stands in for `httpx.post`, replaying canned payloads and keeping the requests."""

    def __init__(self, *payloads: dict[str, Any]) -> None:
        self.payloads = list(payloads)
        self.urls: list[str] = []
        self.headers: list[dict[str, str]] = []
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, url: str, **kwargs: Any) -> httpx.Response:
        self.urls.append(url)
        self.headers.append(dict(kwargs.get("headers") or {}))
        self.bodies.append(dict(kwargs.get("json") or {}))
        payload = self.payloads.pop(0) if self.payloads else {}
        return httpx.Response(200, json=payload, request=httpx.Request("POST", url))


def _text_payload(text: str, **usage: int) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}]
    }
    if usage:
        payload["usageMetadata"] = usage
    return payload


# ── configuration ────────────────────────────────────────────────────────────
def test_gemini_is_selectable_and_defaults_to_the_smallest_model() -> None:
    settings = Settings(_env_file=None, llm_provider="gemini", gemini_api_key="k", llm_model=None)
    assert settings.resolved_llm_model == "gemini-3.5-flash-lite"


def test_missing_gemini_key_fails_at_construction() -> None:
    """Same rule as Groq: a missing key stops the demo at startup, not at GENAI_STATIC."""
    with pytest.raises(ValidationError, match="GEMINI_API_KEY"):
        Settings(_env_file=None, llm_provider="gemini", gemini_api_key=None, groq_api_key="gsk")


def test_only_the_selected_provider_needs_a_key() -> None:
    """A stale key for the other provider must not be required, or block startup."""
    gemini = Settings(_env_file=None, llm_provider="gemini", gemini_api_key="k", groq_api_key=None)
    assert gemini.groq_api_key is None
    groq = Settings(_env_file=None, llm_provider="groq", groq_api_key="gsk", gemini_api_key=None)
    assert groq.resolved_llm_model == "qwen/qwen3.8-27b"


def test_the_gemini_key_does_not_leak_in_repr() -> None:
    settings = Settings(_env_file=None, llm_provider="gemini", gemini_api_key="super-secret")
    assert "super-secret" not in repr(settings)
    assert "super-secret" not in str(settings)
    assert settings.gemini_api_key is not None


def test_a_model_from_the_other_provider_is_refused_at_startup() -> None:
    """`.env` pins provider AND model. Flipping one alone is a 404 on every call."""
    with pytest.raises(ValidationError, match="not a Gemini model"):
        Settings(
            _env_file=None,
            llm_provider="gemini",
            gemini_api_key="k",
            llm_model="qwen/qwen3.8-27b",
        )
    with pytest.raises(ValidationError, match="is a Gemini model"):
        Settings(
            _env_file=None,
            llm_provider="groq",
            groq_api_key="gsk",
            llm_model="gemini-3.5-flash-lite",
        )


def test_an_explicit_gemini_model_is_honoured() -> None:
    settings = Settings(
        _env_file=None, llm_provider="gemini", gemini_api_key="k", llm_model="gemini-2.5-pro"
    )
    assert settings.resolved_llm_model == "gemini-2.5-pro"


def test_gemini_lifts_the_request_ceiling_unless_it_was_set_explicitly() -> None:
    """The 8,000 ceiling is Groq's. Keeping it would size the answer for a limit that is
    two orders of magnitude away."""
    default = Settings(_env_file=None, llm_provider="gemini", gemini_api_key="k")
    assert default.llm_max_request_tokens == GEMINI_MAX_REQUEST_TOKENS
    pinned = Settings(
        _env_file=None, llm_provider="gemini", gemini_api_key="k", llm_max_request_tokens=20_000
    )
    assert pinned.llm_max_request_tokens == 20_000
    assert Settings(_env_file=None, groq_api_key="gsk").llm_max_request_tokens == 8_000


# ── plain completion ─────────────────────────────────────────────────────────
def test_completion_uses_the_gemini_endpoint_and_the_header_credential(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rule 12: the key is a header. `?key=` would work and would put it in every log."""
    recorder = _Recorder(_text_payload("LIVE_OK"))
    monkeypatch.setattr(httpx, "post", recorder)

    out = LLMClient(gemini_settings, use_cache=False).complete(system="sys", user="usr")

    assert out == "LIVE_OK"
    assert recorder.urls == [
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.5-flash-lite:generateContent"
    ]
    assert "key=" not in recorder.urls[0]
    assert recorder.headers[0]["x-goog-api-key"] == "test-key-not-real"
    assert "Authorization" not in recorder.headers[0]


def test_the_system_prompt_travels_in_system_instruction_not_as_a_message(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gemini has no `system` role, and rule 6 wants the split to be structural anyway."""
    recorder = _Recorder(_text_payload("ok"))
    monkeypatch.setattr(httpx, "post", recorder)

    LLMClient(gemini_settings, use_cache=False).complete(
        system="you are an analyst", user="<untrusted_artifact>x</untrusted_artifact>"
    )

    body = recorder.bodies[0]
    assert body["systemInstruction"] == {"parts": [{"text": "you are an analyst"}]}
    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "<untrusted_artifact>x</untrusted_artifact>"}]}
    ]
    assert body["generationConfig"]["maxOutputTokens"] == 2000
    assert all(m.get("role") != "system" for m in body["contents"])


def test_json_mode_asks_for_the_json_mime_type(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder(_text_payload('{"summary": "ok", "behaviours": {}}'))
    monkeypatch.setattr(httpx, "post", recorder)

    parsed = LLMClient(gemini_settings, use_cache=False).complete_as(
        system="s", user="u", schema=Verdict
    )

    assert parsed is not None and parsed.summary == "ok"
    assert recorder.bodies[0]["generationConfig"]["responseMimeType"] == "application/json"


def test_a_fenced_reply_still_validates(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(httpx, "post", _Recorder(_text_payload('```json\n{"summary": "x"}\n```')))
    assert (
        LLMClient(gemini_settings, use_cache=False).complete_as(
            system="s", user="u", schema=Verdict
        )
        is not None
    )


def test_provider_selection_routes_groq_to_groq(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the switch: adding Gemini must not divert the Groq path."""
    recorder = _Recorder({"choices": [{"message": {"content": "hi"}}]})
    monkeypatch.setattr(httpx, "post", recorder)
    settings = Settings(
        _env_file=None,
        llm_provider="groq",
        groq_api_key="gsk-test",
        llm_model=None,
        llm_cache_dir=tmp_path / "c",
    )

    assert LLMClient(settings, use_cache=False).complete(system="s", user="u") == "hi"
    assert recorder.urls == ["https://api.groq.com/openai/v1/chat/completions"]
    assert recorder.headers[0]["Authorization"] == "Bearer gsk-test"


# ── usage ────────────────────────────────────────────────────────────────────
def test_usage_metadata_is_read_as_a_measurement(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider counts, not chars/4 — the budget is an assert and must not assert on a
    guess. Thoughts are billed as output, so they count as completion tokens."""
    monkeypatch.setattr(
        httpx,
        "post",
        _Recorder(
            _text_payload(
                "ok",
                promptTokenCount=4931,
                candidatesTokenCount=120,
                thoughtsTokenCount=30,
                totalTokenCount=5081,
            )
        ),
    )
    client = LLMClient(gemini_settings, use_cache=False)
    client.complete(system="s", user="u", purpose="checklist")

    report = client.budget_report()
    assert report.measured_calls == 1
    assert report.total_prompt_tokens == 4931
    assert report.total_completion_tokens == 150
    assert report.max_prompt_tokens == 4931


def test_a_response_without_usage_falls_back_to_the_estimate(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(httpx, "post", _Recorder(_text_payload("ok")))
    client = LLMClient(gemini_settings, use_cache=False)
    client.complete(system="s", user="u")
    assert client.budget_report().measured_calls == 0


# ── degradation ──────────────────────────────────────────────────────────────
def test_a_blocked_prompt_degrades_to_none_rather_than_raising(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A safety block is a 200 with no candidates. Losing M2's work over it would be
    absurd (rule 2), but the reason must reach the log."""
    monkeypatch.setattr(httpx, "post", _Recorder({"promptFeedback": {"blockReason": "OTHER"}}))
    assert LLMClient(gemini_settings, use_cache=False).complete(system="s", user="u") is None


def test_a_depleted_account_fails_fast_instead_of_retrying(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MEASURED on the supplied key: `429 RESOURCE_EXHAUSTED — "Your prepayment credits
    are depleted"`, no `retryDelay`. Same status as a per-minute quota, opposite handling:
    no wait ever clears it, so retrying costs 5s a call, 25 calls a job, in front of an
    audience — to arrive at the identical failure."""
    posts = {"n": 0}

    def depleted(url: str, **_kwargs: Any) -> httpx.Response:
        posts["n"] += 1
        return httpx.Response(
            429,
            json={
                "error": {
                    "code": 429,
                    "message": "Your prepayment credits are depleted. Please go to AI "
                    "Studio at https://ai.studio/projects to manage your project and "
                    "billing.",
                    "status": "RESOURCE_EXHAUSTED",
                }
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", depleted)
    monkeypatch.setattr("drishti.m4_genai.client.time.sleep", lambda _s: None)
    client = LLMClient(gemini_settings, use_cache=False)

    assert client.complete(system="s", user="u") is None
    assert posts["n"] == 1, "a billing wall is not a rate limit; do not wait it out"


def test_an_ordinary_quota_message_is_still_retried(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The narrowness matters: a real per-minute limit clears on its own."""
    posts = {"n": 0}

    def throttled(url: str, **_kwargs: Any) -> httpx.Response:
        posts["n"] += 1
        return httpx.Response(
            429,
            json={"error": {"message": "You exceeded your current quota", "code": 429}},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", throttled)
    monkeypatch.setattr("drishti.m4_genai.client.time.sleep", lambda _s: None)

    assert LLMClient(gemini_settings, use_cache=False).complete(system="s", user="u") is None
    assert posts["n"] == 3


def test_a_non_retryable_failure_records_the_attempts_it_actually_made(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong model name is a 404, refused on the first attempt. The stat used to say
    three, which reads as a flaky network instead of a typo — measured, then fixed, while
    a deprecated `gemini-2.5-flash-lite` was 404ing on the live endpoint."""

    def not_found(url: str, **_kwargs: Any) -> httpx.Response:
        return httpx.Response(
            404,
            json={"error": {"code": 404, "message": "model not available"}},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", not_found)
    client = LLMClient(gemini_settings, use_cache=False)

    assert client.complete(system="s", user="u") is None
    assert client.stats[0].outcome == "failed"
    assert client.stats[0].attempts == 1


def test_a_missing_key_is_refused_by_the_transport_too() -> None:
    """Config refuses it at startup; the transport refuses it again rather than posting
    an unauthenticated request, for the paths that build Settings without validation."""
    settings = Settings.model_construct(
        llm_provider="gemini", gemini_api_key=None, llm_model="gemini-3.5-flash-lite"
    )
    client = LLMClient.__new__(LLMClient)
    client._settings = settings
    client._model = "gemini-3.5-flash-lite"
    with pytest.raises(Exception, match="GEMINI_API_KEY is unset"):
        client._gemini_post({})


def test_gemini_states_its_retry_delay_as_json_not_prose() -> None:
    """Groq says "try again in 18.87s"; Gemini sends a RetryInfo detail. Both must be
    honoured, or our 1s backoff guarantees the next attempt fails too."""
    body = json.dumps(
        {
            "error": {
                "code": 429,
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "17s"}
                ],
            }
        }
    )
    request = httpx.Request("POST", "https://generativelanguage.googleapis.com/")
    exc = httpx.HTTPStatusError(
        "429", request=request, response=httpx.Response(429, request=request, text=body)
    )
    assert retry_delay_from(exc) == 17.0


# ── tool calling ─────────────────────────────────────────────────────────────
class _Args(BaseModel):
    signature: str = Field(min_length=1, max_length=512)
    xor_key: int | None = Field(default=None, ge=0, le=255)


def test_the_tool_schema_is_reduced_to_what_gemini_accepts() -> None:
    """`title`, `$schema`, `additionalProperties` and `default` are 400s, not warnings,
    and `anyOf: [..., {type: null}]` is one too — NULL is not a Gemini type."""
    reduced = sanitise_tool_schema(_Args.model_json_schema())

    assert reduced["type"] == "OBJECT"
    assert "title" not in json.dumps(reduced)
    assert "additionalProperties" not in json.dumps(reduced)
    assert "default" not in json.dumps(reduced)
    assert reduced["required"] == ["signature"]
    assert reduced["properties"]["signature"]["type"] == "STRING"
    xor_key = reduced["properties"]["xor_key"]
    assert xor_key["type"] == "INTEGER"
    assert xor_key["nullable"] is True
    assert "anyOf" not in xor_key


def test_a_literal_becomes_an_enum_and_a_const_does_too() -> None:
    from typing import Literal

    class Direction(BaseModel):
        direction: Literal["callers", "callees"]
        fixed: Literal["only"]

    reduced = sanitise_tool_schema(Direction.model_json_schema())
    assert reduced["properties"]["direction"]["enum"] == ["callers", "callees"]
    assert reduced["properties"]["fixed"]["enum"] == ["only"]


def test_tools_become_one_function_declarations_block() -> None:
    tools = [
        {
            "type": "function",
            "function": {
                "name": "read_method",
                "description": "Read one method.",
                "parameters": _Args.model_json_schema(),
            },
        },
        {"type": "function", "function": {"name": "no_args", "parameters": {}}},
    ]
    converted = to_gemini_tools(tools)

    assert len(converted) == 1, "one entry holding every declaration"
    declarations = converted[0]["functionDeclarations"]
    assert [d["name"] for d in declarations] == ["read_method", "no_args"]
    assert declarations[0]["description"] == "Read one method."
    # An empty parameter object is rejected; omitting the field is how you say "none".
    assert "parameters" not in declarations[1]


def test_tool_results_go_back_as_function_responses_with_the_user_role() -> None:
    """Gemini has no `tool` role. Two results for one turn belong in ONE content."""
    system, contents = to_gemini_contents(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "c1", "function": {"name": "read_method", "arguments": '{"a": 1}'}},
                    {"id": "c2", "function": {"name": "lookup_mitre", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "name": "read_method", "content": '{"body": "return true;"}'},
            {"role": "tool", "name": "lookup_mitre", "content": '{"id": "T1521"}'},
        ]
    )

    assert system == {"parts": [{"text": "sys"}]}
    assert [c["role"] for c in contents] == ["user", "model", "user"]
    assert contents[1]["parts"][0]["functionCall"] == {"name": "read_method", "args": {"a": 1}}
    responses = contents[2]["parts"]
    assert len(responses) == 2, "both results belong to the one assistant turn"
    assert responses[0]["functionResponse"] == {
        "name": "read_method",
        "response": {"body": "return true;"},
    }


def test_a_non_object_tool_result_is_wrapped() -> None:
    """`functionResponse.response` must be an object; a bare string is a 400."""
    _, contents = to_gemini_contents([{"role": "tool", "name": "t", "content": "plain text"}])
    assert contents[0]["parts"][0]["functionResponse"]["response"] == {"result": "plain text"}


def test_a_function_call_part_becomes_an_openai_shaped_tool_call() -> None:
    message = message_from_gemini(
        {
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [
                            {"thought": True, "text": "thinking out loud"},
                            {"functionCall": {"name": "read_method", "args": {"signature": "Lx;"}}},
                        ],
                    }
                }
            ]
        }
    )
    assert message["content"] == "", "a thought summary is reasoning, not an answer"
    call = message["tool_calls"][0]
    assert call["function"]["name"] == "read_method"
    assert json.loads(call["function"]["arguments"]) == {"signature": "Lx;"}


def test_the_tool_loop_round_trips_and_validates_its_final_json(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of the provider change: the round that carries tool results back
    must complete. On Groq it was rejected outright at 8,528 tokens."""
    recorder = _Recorder(
        {
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "read_method",
                                    "args": {"signature": "Lx;->a"},
                                }
                            }
                        ],
                    }
                }
            ]
        },
        _text_payload('{"summary": "grounded", "behaviours": {}}'),
    )
    monkeypatch.setattr(httpx, "post", recorder)
    executed: list[tuple[str, Any]] = []
    client = LLMClient(gemini_settings, use_cache=False)

    result = client.complete_with_tools_as(
        system="system",
        user="user",
        tools=[
            {
                "type": "function",
                "function": {"name": "read_method", "parameters": _Args.model_json_schema()},
            }
        ],
        execute=lambda name, args: executed.append((name, args)) or {"body": "return true;"},
        schema=Verdict,
    )

    assert result is not None and result.summary == "grounded"
    assert executed == [("read_method", '{"signature": "Lx;->a"}')]
    assert client.calls_made == 2

    first, second = recorder.bodies
    assert "functionDeclarations" in first["tools"][0]
    assert first["toolConfig"] == {"functionCallingConfig": {"mode": "AUTO"}}
    # Gemini refuses tools + responseMimeType together. The schema is carried by the
    # prompt and enforced by `parse_and_validate`, exactly as on the Groq path.
    assert "responseMimeType" not in first["generationConfig"]
    assert [c["role"] for c in second["contents"]] == ["user", "model", "user"]
    assert second["contents"][2]["parts"][0]["functionResponse"]["response"] == {
        "body": "return true;"
    }


def test_the_tool_loop_stops_at_its_round_budget(
    gemini_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An agent loop is a bill and a hung demo. A model that keeps calling tools stops."""
    call_round = {
        "candidates": [
            {"content": {"role": "model", "parts": [{"functionCall": {"name": "t", "args": {}}}]}}
        ]
    }
    monkeypatch.setattr(httpx, "post", _Recorder(*[call_round] * 6))
    client = LLMClient(gemini_settings, use_cache=False)

    result = client.complete_with_tools_as(
        system="s",
        user="u",
        tools=[{"type": "function", "function": {"name": "t", "parameters": {}}}],
        execute=lambda name, args: {"ok": True},
        schema=Verdict,
        max_rounds=2,
    )
    assert result is None
    assert client.calls_made == 3, "rounds 0..max_rounds, then stop"
