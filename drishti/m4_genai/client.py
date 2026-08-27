"""The LLM client: one call surface, budgets as asserts, output never trusted.

docs/PHASE_3_GENAI_CORE.md T3.1, docs/00_GUIDING_MAP.md §9.4 and §12.

Four properties, each of which exists because its absence has a specific failure:

  * **Budgets are asserts, not hopes** (§12). ≤25 calls per job, ≤12k tokens in. A
    runaway agent loop is a bill and a hung demo, so the counter raises rather than logs.
  * **Structural output validation** (§9.4). Strip fences → `json.loads` → pydantic →
    on failure exactly one repair round-trip → on second failure return `None`. Never
    `eval`, never regex-scrape a number out of prose.
  * **Caching keyed by `sha256(model + prompt)`.** Rehearsal runs become fast, cheap and
    identical; `--no-cache` exists for honesty if a judge asks.
  * **Degradation, not exceptions.** A provider outage returns `None` and the pipeline
    continues with `partial=True`. A failed LLM call must never lose the static report.

The client has no opinion about scores. It moves validated JSON; `safety.behavioural_risk`
turns enumerated booleans into `B`.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from drishti.config import Settings
from drishti.logging import get_logger

log = get_logger(__name__)

ModelT = TypeVar("ModelT", bound=BaseModel)

GROQ_CHAT_COMPLETIONS_URL = "https://api.groq.com/openai/v1/chat/completions"

#: Gemini's REST base. The model name and the method are path segments, so the URL is
#: built per call. The key travels in the `x-goog-api-key` HEADER and never in the query
#: string: `?key=` is equally valid to Google and equally fatal to us, because a URL ends
#: up in proxy logs, exception text and `httpx` request reprs (CLAUDE.md rule 12).
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

#: Roughly 4 characters per token. Deliberately crude: the point is to refuse an
#: obviously oversized prompt before paying for it, not to bill anyone accurately.
#: When the provider reports real usage we record that instead — see `CallStat`.
CHARS_PER_TOKEN = 4

#: The `:free` OpenRouter endpoint returns `502 Upstream error from Nvidia: Service
#: temporarily overloaded` on roughly 2 calls in 5 (measured, STATUS.md). Without a
#: retry every second agent silently degrades to `partial` and the run looks like a
#: model failure rather than a flaky upstream. Three attempts with jittered backoff
#: costs at most ~7s and converts most of those into results.
MAX_TRANSPORT_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0

#: Statuses worth another attempt. 5xx is the overloaded upstream; 429 is rate
#: limiting; a 400/401/404 is our bug and retrying it just wastes the demo's clock. 413 is here for a provider-specific reason worth
#: writing down: **Groq reports tokens-per-minute exhaustion as 413**, not only as 429.
#: Measured 2026-08-26 against the live endpoint — the code interpreter's real payload is
#: ~17 KiB / ~3.7k tokens (an order of magnitude under the 12k budget), a deliberately
#: oversized 40k-character message returns 200, and the identical tool-calling request
#: returns 200 with a genuine `read_method` call when the account is not throttled. Under
#: back-to-back runs the same request alternates 413 and 429.
#:
#: While 413 was excluded, `_exchange_with_retry` re-raised on the first attempt, the tool
#: loop returned None, and `_guarded` swallowed it — so one momentary quota ceiling cost
#: the job its entire code-interpretation stage and the dashboard rendered the result as
#: "0 retrieval tool calls", which reads as a choice rather than a failure.
RETRYABLE_STATUS = frozenset({408, 413, 429, 500, 502, 503, 504, 520, 522, 524})

#: Longest provider-requested pause we will actually sit through. Groq's free tier asks
#: for ~19s when TPM is exhausted, which is worth waiting for; an unbounded sleep read out
#: of an error body would be a hang rather than a retry.
MAX_RETRY_AFTER_S = 30.0

#: "Please try again in 18.87s" — the provider states the wait in prose when it does not
#: send a Retry-After header.
_RETRY_AFTER_TEXT = re.compile(r"try again in\s+([0-9]+(?:\.[0-9]+)?)\s*s", re.IGNORECASE)

#: Gemini states it as machine-readable JSON instead of prose: a `google.rpc.RetryInfo`
#: detail carrying `"retryDelay": "17s"`. Same meaning, different envelope — without this
#: a 429 from Gemini would fall back to our 1s/2s backoff and be guaranteed to fail again.
_RETRY_DELAY_JSON = re.compile(r'"retryDelay"\s*:\s*"([0-9]+(?:\.[0-9]+)?)s"', re.IGNORECASE)

#: Groq answers with 413 in two situations that need OPPOSITE handling, and the status
#: alone cannot tell them apart. Measured on 2026-08-26 within a single job:
#:
#:   round 0  "Rate limit reached ... Used 4932, Requested 5584. Please try again in
#:             18.87s"                        -> transient. The window rolls; waiting works.
#:   round 1  "Request too large ... Limit 8000, Requested 8528, please reduce your
#:             message size and try again"    -> permanent for THIS request. One request
#:                                               exceeds the whole per-minute ceiling, so
#:                                               no amount of waiting can ever help.
#:
#: Retrying the second kind burned 38 seconds per job to arrive at the same failure.
#: Gemini phrases the same permanent condition as "The input token count (N) exceeds the
#: maximum number of tokens allowed (M)" on a 400. It is listed here for the same reason:
#: no wait shrinks the request. (A 400 is not retryable anyway, so this is belt and
#: braces — but the classification is what the log and the report read.)
_TOO_LARGE_TO_EVER_SUCCEED = re.compile(
    r"reduce your message size|request too large|exceeds the maximum number of tokens",
    re.IGNORECASE,
)

#: A billing wall wearing a rate limit's clothes. Narrow on purpose: an ordinary quota
#: message ("You exceeded your current quota", "rate limit reached") must stay retryable,
#: because waiting genuinely fixes those.
_PERMANENTLY_REFUSED = re.compile(
    r"prepayment credits are depleted|billing account .{0,40}(?:disabled|closed|not found)",
    re.IGNORECASE,
)

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def is_permanently_too_large(exc: Exception | None) -> bool:
    """True when the provider says this single request can never fit, so do not retry.

    Distinguished from an ordinary rate limit by the provider's own wording: a rolling
    window says "try again in Ns", while an oversized request says "reduce your message
    size". Only the first is worth waiting for.
    """
    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    return bool(_TOO_LARGE_TO_EVER_SUCCEED.search(exc.response.text or ""))


def is_permanently_refused(exc: Exception | None) -> bool:
    """True when a retryable STATUS carries an unretryable CAUSE.

    Two of these are known, both measured, both answered with a status that normally means
    "wait and try again":

      * the request cannot fit at all (`is_permanently_too_large`);
      * the account cannot pay. MEASURED 2026-08-26 on the supplied Gemini key: `429
        RESOURCE_EXHAUSTED — "Your prepayment credits are depleted"`, with no `retryDelay`.
        Indistinguishable by status from a per-minute quota, and no wait ever clears it, so
        the retries cost 5s per call — 25 calls a job — to reach the same failure while a
        demo watches.
    """
    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    return is_permanently_too_large(exc) or bool(
        _PERMANENTLY_REFUSED.search(exc.response.text or "")
    )


def retry_delay_from(exc: Exception | None) -> float | None:
    """How long the provider asked us to wait, or None if it did not say.

    Retrying sooner than the stated delay is arithmetically the same as not retrying.
    Groq's free tier answers an over-TPM request with "Please try again in 18.87s" while
    our own backoff waits 1s then 2s — so every attempt was guaranteed to fail and the
    code interpreter never ran. The `Retry-After` header is preferred when present because
    a header is a contract and a message is prose.
    """
    if not isinstance(exc, httpx.HTTPStatusError):
        return None
    header = exc.response.headers.get("retry-after")
    if header:
        try:
            return min(max(float(header), 0.0), MAX_RETRY_AFTER_S) or None
        except ValueError:
            pass  # a date-formatted Retry-After is not worth parsing for this
    body = exc.response.text or ""
    match = _RETRY_AFTER_TEXT.search(body) or _RETRY_DELAY_JSON.search(body)
    if not match:
        return None
    seconds = float(match.group(1))
    if seconds <= 0:
        return None
    return min(seconds, MAX_RETRY_AFTER_S)


def _explain(exc: Exception | None) -> str:
    """Include the provider's own words, not just the status line.

    `raise_for_status()` produces "Client error '413 Payload Too Large'" and discards the
    body — which is where Groq actually says *why*, e.g. whether a 413 is a real size
    limit or tokens-per-minute exhaustion. Debugging the code interpreter cost an hour
    for exactly this reason: the status was visible and the explanation was not.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "").strip().replace("\n", " ")
        return f"{exc.response.status_code}: {body[:300]}" if body else str(exc)
    return str(exc)


class LLMError(Exception):
    """The provider could not be reached or refused the request."""


class BudgetExceededError(LLMError):
    """A hard budget from 00_GUIDING_MAP.md §12 was hit. Not retryable."""


@dataclass
class CallStat:
    """What one completion actually cost.

    `prompt_tokens` is the provider's own count when it reports one and the crude
    chars/4 estimate otherwise; `measured` records which, because a report that
    quotes an estimate as a measurement is exactly what the honesty requirements
    forbid. A cache hit costs nothing and is recorded with `cached=True` so the
    per-job figure can be stated both ways.
    """

    purpose: str
    prompt_chars: int
    prompt_tokens: int
    completion_tokens: int = 0
    measured: bool = False
    cached: bool = False
    attempts: int = 0
    latency_ms: int = 0
    outcome: str = "ok"


@dataclass
class BudgetReport:
    """Aggregate of a job's LLM spend, for the UI and for STATUS.md."""

    calls: int = 0
    cache_hits: int = 0
    max_prompt_tokens: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    measured_calls: int = 0
    failures: int = 0
    stats: tuple[CallStat, ...] = field(default_factory=tuple)


def strip_fences(text: str) -> str:
    """Remove markdown code fences. Models add them regardless of instructions."""
    return _FENCE.sub("", text).strip()


def parse_and_validate(text: str, model: type[ModelT]) -> ModelT | None:
    """Parse model output into a contract, or return None.

    Returns `None` rather than raising: unparseable output is an expected outcome that
    the caller degrades on, not an exceptional one. The caller decides whether to spend
    a repair round-trip.
    """
    try:
        payload = json.loads(strip_fences(text))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        # strict=True on purpose. In lax mode pydantic coerces "yes" -> True and "1" -> 1,
        # so a model answering sloppily would have its output silently upgraded to a real
        # boolean before any guard could see it. LLM output is untrusted input; it gets
        # the same strictness as the detonator wire contract (01_DATA_CONTRACTS.md A2).
        return model.model_validate(payload, strict=True)
    except ValidationError:
        return None


# ── Gemini wire translation ──────────────────────────────────────────────────
# Gemini is not OpenAI-shaped. Everything above and below this block speaks the OpenAI
# message shape, so the difference is contained to these four functions: the tool loop,
# the budgets, the caching and the validation stay single-path for both providers.

#: Gemini's `Schema` is an OpenAPI 3.0 subset, not JSON Schema. Anything outside this set
#: is a 400 (`Invalid JSON payload received. Unknown name "…"`), so a schema pydantic
#: generated happily — `title`, `$defs`, `additionalProperties`, `exclusiveMinimum` — kills
#: the whole call rather than being ignored. Strip, do not hope.
_GEMINI_SCHEMA_KEYS = frozenset(
    {
        "type",
        "description",
        "enum",
        "items",
        "properties",
        "required",
        "nullable",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "pattern",
    }
)

#: The proto enum names. Proto3 JSON accepts the enum name; lowercase JSON-Schema spelling
#: is accepted by some paths and not others, so normalise once and stop guessing.
_GEMINI_TYPES = {
    "string": "STRING",
    "number": "NUMBER",
    "integer": "INTEGER",
    "boolean": "BOOLEAN",
    "array": "ARRAY",
    "object": "OBJECT",
}

#: `format` is a closed vocabulary here. Pydantic emits `uri`, `uuid`, `date` and friends,
#: none of which Gemini knows, and an unknown format is a 400 rather than a hint ignored.
_GEMINI_FORMATS = frozenset({"float", "double", "int32", "int64", "enum", "date-time"})

#: Depth guard for a self-referential `$ref`. None of the analysis toolbox's argument
#: models nest, but a schema loop must not become an unbounded recursion in the demo path.
_MAX_SCHEMA_DEPTH = 8


def gemini_url(model: str) -> str:
    """REST endpoint for one model. No credential in it — see `GEMINI_API_BASE`."""
    return f"{GEMINI_API_BASE}/{model.removeprefix('models/')}:generateContent"


def sanitise_tool_schema(
    schema: dict[str, Any] | None,
    defs: dict[str, Any] | None = None,
    depth: int = 0,
) -> dict[str, Any]:
    """Rewrite one JSON Schema into the subset Gemini's `functionDeclarations` accepts.

    Constraints that are dropped are not lost: `AnalysisToolbox.execute` validates every
    argument against the same pydantic model before anything runs, so the schema is a hint
    to the model and the guard is elsewhere.
    """
    if not isinstance(schema, dict) or depth > _MAX_SCHEMA_DEPTH:
        return {}
    defs = defs if defs is not None else schema.get("$defs") or {}
    ref = schema.get("$ref")
    if isinstance(ref, str):
        target = defs.get(ref.rsplit("/", 1)[-1])
        merged = dict(target) if isinstance(target, dict) else {}
        merged.update({k: v for k, v in schema.items() if k != "$ref"})
        schema = merged

    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "properties" and isinstance(value, dict):
            out["properties"] = {
                name: sanitise_tool_schema(child, defs, depth + 1) for name, child in value.items()
            }
        elif key == "items":
            out["items"] = sanitise_tool_schema(value, defs, depth + 1)
        elif key == "const":
            # Gemini has no `const`; a one-value enum says the same thing.
            out["enum"] = [value]
        elif key == "format":
            if value in _GEMINI_FORMATS:
                out["format"] = value
        elif key == "type" and isinstance(value, str):
            mapped = _GEMINI_TYPES.get(value.lower())
            if mapped:
                out["type"] = mapped
        elif key in _GEMINI_SCHEMA_KEYS:
            out[key] = value

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        # `int | None` becomes `anyOf: [{integer}, {null}]`, and NULL is not a Gemini type.
        # Collapse it to the real branch plus `nullable`, which is what it meant.
        concrete = [b for b in any_of if isinstance(b, dict) and b.get("type") != "null"]
        if len(concrete) < len(any_of):
            out["nullable"] = True
        branches = [sanitise_tool_schema(b, defs, depth + 1) for b in concrete]
        branches = [b for b in branches if b]
        if len(branches) == 1:
            for key, value in branches[0].items():
                out.setdefault(key, value)
        elif branches:
            out["anyOf"] = branches

    if "properties" in out:
        out.setdefault("type", "OBJECT")
    return out


def to_gemini_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """OpenAI `tools` -> Gemini `[{functionDeclarations: [...]}]`.

    One entry holding every declaration, which is the shape the API expects; a list of
    single-declaration tools is accepted by some versions and rejected by others.
    """
    declarations: list[dict[str, Any]] = []
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        function = function if isinstance(function, dict) else tool
        if not isinstance(function, dict) or not function.get("name"):
            continue
        declaration: dict[str, Any] = {"name": str(function["name"])}
        if function.get("description"):
            declaration["description"] = str(function["description"])
        parameters = sanitise_tool_schema(function.get("parameters"))
        # A declaration with an empty parameter object is rejected; omitting the field is
        # how you say "this tool takes nothing".
        if parameters.get("properties"):
            declaration["parameters"] = parameters
        declarations.append(declaration)
    return [{"functionDeclarations": declarations}] if declarations else []


def _as_object(value: Any) -> dict[str, Any]:
    """Coerce a tool payload into the JSON object Gemini requires on both directions."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return {"result": value}
        return parsed if isinstance(parsed, dict) else {"result": parsed}
    return {"result": value}


def to_gemini_contents(
    messages: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """OpenAI messages -> `(systemInstruction, contents)`.

    Four shape differences, each of which is a 400 if you get it wrong: the system prompt
    is a separate top-level field rather than a message, the assistant is called `model`,
    a tool call is a `functionCall` part rather than a sibling key, and a tool *result* is
    a `functionResponse` part sent with role `user` — Gemini has no `tool` role at all.
    """
    system_texts: list[str] = []
    contents: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        content = message.get("content") or ""
        if role == "system":
            if content:
                system_texts.append(str(content))
            continue
        if role == "tool":
            part = {
                "functionResponse": {
                    "name": str(message.get("name") or ""),
                    "response": _as_object(content),
                }
            }
            last = contents[-1] if contents else None
            if (
                last
                and last["role"] == "user"
                and all("functionResponse" in p for p in last["parts"])
            ):
                # Every result for one assistant turn belongs in that turn, not in N turns.
                last["parts"].append(part)
            else:
                contents.append({"role": "user", "parts": [part]})
            continue
        if role == "assistant":
            parts: list[dict[str, Any]] = []
            if content:
                parts.append({"text": str(content)})
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                call_part: dict[str, Any] = {
                    "functionCall": {
                        "name": str(function.get("name") or ""),
                        "args": _as_object(function.get("arguments")),
                    }
                }
                signature = call.get("thought_signature")
                if isinstance(signature, str):
                    # Gemini 3 requires its own signature back on the part it signed.
                    call_part["thoughtSignature"] = signature
                parts.append(call_part)
            if parts:
                contents.append({"role": "model", "parts": parts})
            continue
        contents.append({"role": "user", "parts": [{"text": str(content)}]})

    system = {"parts": [{"text": "\n\n".join(system_texts)}]} if system_texts else None
    return system, contents


def message_from_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    """Gemini candidate -> the OpenAI-shaped message the rest of this module speaks."""
    candidates = payload.get("candidates") or []
    if not candidates:
        # A safety block returns 200 with no candidates and the reason in promptFeedback.
        # Reporting "no candidates" without it sends the reader looking for a bug.
        feedback = payload.get("promptFeedback") or {}
        raise LLMError(f"gemini returned no candidates (promptFeedback={feedback})"[:300])
    candidate = candidates[0] if isinstance(candidates[0], dict) else {}
    parts = (candidate.get("content") or {}).get("parts") or []

    texts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for index, part in enumerate(parts):
        if not isinstance(part, dict) or part.get("thought"):
            continue  # a thought summary is reasoning, not the answer
        call = part.get("functionCall")
        if isinstance(call, dict):
            tool_call: dict[str, Any] = {
                # Gemini does not issue call ids; the loop only needs a stable handle.
                "id": f"call_{index}",
                "type": "function",
                "function": {
                    "name": str(call.get("name") or ""),
                    "arguments": json.dumps(call.get("args") or {}, ensure_ascii=True),
                },
            }
            if isinstance(part.get("thoughtSignature"), str):
                # Gemini 3 signs the reasoning behind a function call and requires the
                # signature back on the same part in the next turn; dropping it is a 400
                # ("Function call is missing thought_signature") on exactly the round that
                # carries the tool results — the round this provider was adopted for. It
                # rides on the OpenAI-shaped tool call so the loop stays provider-neutral;
                # Groq never sets it, and `to_gemini_contents` only re-emits what it finds.
                tool_call["thought_signature"] = part["thoughtSignature"]
            tool_calls.append(tool_call)
            continue
        if isinstance(part.get("text"), str):
            texts.append(part["text"])

    message: dict[str, Any] = {"content": "".join(texts)}
    if tool_calls:
        message["tool_calls"] = tool_calls
    if not message["content"] and not tool_calls:
        # MAX_TOKENS here usually means a thinking model spent the whole output budget on
        # thoughts. Worth a line, because the symptom is an empty answer with a 200.
        log.warning("gemini_empty_candidate", finish_reason=candidate.get("finishReason"))
    return message


class LLMClient:
    """Groq or Gemini completion with caching, budgets and validation."""

    #: Transport attempts spent on the most recent request, successful or not. A class
    #: attribute so it exists even on instances built with `__new__` in tests.
    _last_attempts: int = 0

    #: Why the most recent tool loop returned `None`, in the caller's words-for-a-human.
    #: `complete_with_tools_as` collapses three different failures — a transport error,
    #: a reply that did not parse, and a loop that hit its round cap — into one `None`.
    #: An agent that reports all three as "provider unavailable" is making a claim it
    #: has not checked, which is exactly what this project refuses to do elsewhere.
    #: A class attribute so it exists on instances built with `__new__` in tests.
    last_failure: str | None = None

    def __init__(self, settings: Settings, *, use_cache: bool | None = None) -> None:
        self._settings = settings
        self._model = settings.resolved_llm_model
        self._provider = settings.llm_provider
        self._use_cache = settings.llm_cache_enabled if use_cache is None else use_cache
        self._cache_dir = Path(settings.llm_cache_dir)
        self.calls_made = 0
        #: Every completion attempted this job, in order. The budget figures the UI and
        #: STATUS.md quote are read from here rather than guessed.
        self.stats: list[CallStat] = []
        #: Set by `_dispatch` when the provider reports real usage for the last call.
        self._last_usage: dict[str, int] | None = None

    # ── measurement ──────────────────────────────────────────────────────────
    def budget_report(self) -> BudgetReport:
        """What this job actually spent, measured. Never an estimate when one exists."""
        billable = [s for s in self.stats if not s.cached]
        return BudgetReport(
            calls=self.calls_made,
            cache_hits=sum(1 for s in self.stats if s.cached),
            max_prompt_tokens=max((s.prompt_tokens for s in self.stats), default=0),
            total_prompt_tokens=sum(s.prompt_tokens for s in billable),
            total_completion_tokens=sum(s.completion_tokens for s in billable),
            measured_calls=sum(1 for s in self.stats if s.measured),
            failures=sum(1 for s in self.stats if s.outcome != "ok"),
            stats=tuple(self.stats),
        )

    # ── budgets ──────────────────────────────────────────────────────────────
    def _check_budgets(self, prompt: str) -> None:
        if self.calls_made >= self._settings.llm_max_calls_per_job:
            raise BudgetExceededError(
                f"LLM call budget exhausted: {self.calls_made} calls, limit "
                f"{self._settings.llm_max_calls_per_job} (00_GUIDING_MAP.md §12)"
            )
        estimated = len(prompt) // CHARS_PER_TOKEN
        if estimated > self._settings.llm_max_prompt_tokens:
            raise BudgetExceededError(
                f"prompt is ~{estimated} tokens, limit "
                f"{self._settings.llm_max_prompt_tokens} — truncate the evidence, "
                "do not raise the budget"
            )

    # ── cache ────────────────────────────────────────────────────────────────
    def _cache_key(self, system: str, user: str) -> str:
        digest = hashlib.sha256(f"{self._model}\x00{system}\x00{user}".encode()).hexdigest()
        return digest

    def _cached(self, key: str) -> str | None:
        if not self._use_cache:
            return None
        path = self._cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            return str(json.loads(path.read_text())["completion"])
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def _store(self, key: str, completion: str) -> None:
        if not self._use_cache:
            return
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        (self._cache_dir / f"{key}.json").write_text(
            json.dumps({"model": self._model, "completion": completion})
        )

    # ── completion ───────────────────────────────────────────────────────────
    def complete(
        self,
        *,
        system: str,
        user: str,
        max_output_tokens: int = 2000,
        json_mode: bool = False,
        purpose: str = "completion",
    ) -> str | None:
        """One completion. Returns None on any provider failure — never raises upward.

        `BudgetExceededError` is the exception, and it propagates on purpose: a blown
        budget is a bug in the caller's loop, not a flaky network.
        """
        prompt = system + user
        self._check_budgets(prompt)
        key = self._cache_key(system, user + f"\x00json={json_mode}")
        hit = self._cached(key)
        if hit is not None:
            log.info("llm_cache_hit", model=self._model, key=key[:12], purpose=purpose)
            self.stats.append(
                CallStat(
                    purpose=purpose,
                    prompt_chars=len(prompt),
                    prompt_tokens=len(prompt) // CHARS_PER_TOKEN,
                    cached=True,
                )
            )
            return hit

        started = time.monotonic()
        self._last_usage = None
        try:
            completion, attempts = self._dispatch_with_retry(
                system, user, max_output_tokens, json_mode
            )
        except BudgetExceededError:
            raise
        except Exception as exc:
            # Degrade, do not crash (00_GUIDING_MAP.md §9.2). A failed VLM call must not
            # lose the static report.
            log.error(
                "llm_call_failed", provider=self._provider, error=_explain(exc), purpose=purpose
            )
            # `_last_attempts`, not MAX_TRANSPORT_ATTEMPTS: a 404 is refused on the first
            # attempt and recording three is a number nobody measured. Seen for real — a
            # deprecated model logged `attempts=3` after one request, which reads as a
            # flaky network rather than a wrong model name.
            self._record(purpose, prompt, started, self._last_attempts, outcome="failed")
            return None

        self.calls_made += 1
        self._record(purpose, prompt, started, attempts)
        if completion is not None:
            self._store(key, completion)
        return completion

    def _record(
        self,
        purpose: str,
        prompt: str,
        started: float,
        attempts: int,
        *,
        outcome: str = "ok",
    ) -> None:
        """Log what the call cost, preferring the provider's own token count."""
        usage = self._last_usage or {}
        measured = "prompt_tokens" in usage
        stat = CallStat(
            purpose=purpose,
            prompt_chars=len(prompt),
            prompt_tokens=int(usage.get("prompt_tokens", len(prompt) // CHARS_PER_TOKEN)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            measured=measured,
            attempts=attempts,
            latency_ms=round((time.monotonic() - started) * 1000),
            outcome=outcome,
        )
        self.stats.append(stat)
        log.info(
            "llm_call",
            purpose=purpose,
            model=self._model,
            prompt_tokens=stat.prompt_tokens,
            measured=measured,
            completion_tokens=stat.completion_tokens,
            attempts=attempts,
            latency_ms=stat.latency_ms,
            outcome=outcome,
        )

    def _dispatch_with_retry(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool
    ) -> tuple[str | None, int]:
        """Dispatch, retrying only what is worth retrying. Returns (completion, attempts).

        A retried request is not a second LLM call against the budget: the first one
        produced nothing. What the budget counts is answers, not TCP attempts.
        """
        last: Exception | None = None
        for attempt in range(1, MAX_TRANSPORT_ATTEMPTS + 1):
            self._last_attempts = attempt
            try:
                return self._dispatch(system, user, max_output_tokens, json_mode), attempt
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in RETRYABLE_STATUS:
                    raise
                if is_permanently_refused(exc):
                    raise LLMError(f"provider refused this request: {_explain(exc)}") from exc
                last = exc
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = exc
            if attempt < MAX_TRANSPORT_ATTEMPTS:
                delay = retry_delay_from(last) or (
                    BACKOFF_BASE_S * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                )
                log.warning(
                    "llm_retrying",
                    provider=self._provider,
                    attempt=attempt,
                    delay_s=round(delay, 2),
                    error=_explain(last)[:200],
                )
                time.sleep(delay)
        # `_explain`, not `str`: `raise_for_status()` keeps the status line and throws away
        # the body, and the body is where the provider says WHY. A live 429 read
        # "Too Many Requests" here while the discarded body said "Your prepayment credits
        # are depleted" — one of those sends you to the billing page, the other does not.
        raise LLMError(
            f"provider unavailable after {MAX_TRANSPORT_ATTEMPTS} attempts: {_explain(last)}"
        )

    def complete_as(
        self,
        *,
        system: str,
        user: str,
        schema: type[ModelT],
        max_output_tokens: int = 2000,
        purpose: str = "completion",
    ) -> ModelT | None:
        """Completion validated into `schema`, with exactly one repair attempt.

        The repair turn shows the model its own output and the error. One attempt, not a
        loop: a model that cannot produce the schema twice will not produce it on the
        fifth try, and each attempt costs budget the job may need elsewhere.
        """
        raw = self.complete(
            system=system,
            user=user,
            max_output_tokens=max_output_tokens,
            json_mode=True,
            purpose=purpose,
        )
        if raw is None:
            return None
        parsed = parse_and_validate(raw, schema)
        if parsed is not None:
            return parsed

        log.warning("llm_output_invalid_repairing", model=self._model)
        repair_user = (
            f"{user}\n\nYour previous reply could not be parsed as the required JSON "
            f"schema. Reply with ONLY valid JSON matching the schema, no prose and no "
            f"code fences.\n\nPrevious reply:\n{raw[:1000]}"
        )
        retry = self.complete(
            system=system,
            user=repair_user,
            max_output_tokens=max_output_tokens,
            purpose=f"{purpose}:repair",
        )
        if retry is None:
            return None
        repaired = parse_and_validate(retry, schema)
        if repaired is None:
            log.error("llm_output_invalid_after_repair", model=self._model)
        return repaired

    def complete_with_tools_as(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict[str, Any]],
        execute: Callable[[str, str | dict[str, Any]], dict[str, Any]],
        schema: type[ModelT],
        max_rounds: int = 3,
        max_output_tokens: int = 3000,
        purpose: str = "tool_loop",
    ) -> ModelT | None:
        """Run a bounded tool loop against the provider and validate its final JSON.

        This is how the Code Interpreter reaches the six allowlisted read-only analysis
        tools — it is the reverse-engineering workspace. The Groq migration removed this
        method while leaving `code_interpreter` calling it, so every interpretation
        raised `AttributeError`, was swallowed by the degrade-gracefully wrapper, and
        came back as `None`. Restored rather than deleting the caller.

        Groq speaks the OpenAI tool-calling shape, so the loop is unchanged from the
        previous provider; only the endpoint and the key differ.

        Bounded three ways, because an agent loop is a bill and a hung demo: `max_rounds`
        caps the round trips, each round is charged to the call budget, and a round that
        still wants to call a tool at the limit returns `None` rather than continuing.
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        # Cleared up front so a caller never reads a diagnosis left by an earlier call.
        self.last_failure = None
        for round_index in range(max_rounds + 1):
            prompt = json.dumps(messages, ensure_ascii=True)
            self._check_budgets(prompt)
            started = time.monotonic()
            self._last_usage = None
            try:
                message, attempts = self._exchange_with_retry(
                    messages=messages,
                    tools=tools,
                    max_output_tokens=max_output_tokens,
                )
            except Exception as exc:
                log.error("llm_tool_round_failed", round=round_index, error=_explain(exc))
                self._record(
                    f"{purpose}:round{round_index}",
                    prompt,
                    started,
                    self._last_attempts,
                    outcome="failed",
                )
                self.last_failure = (
                    f"the request to the model failed on round {round_index} after "
                    f"{self._last_attempts} attempt(s): {_explain(exc)}"
                )
                return None
            self.calls_made += 1
            self._record(f"{purpose}:round{round_index}", prompt, started, attempts)

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                content = str(message.get("content") or "")
                validated = parse_and_validate(content, schema)
                if validated is None:
                    # Distinguished from a transport failure on purpose: the provider
                    # answered, so blaming its availability would be false. Say which
                    # of the two it was, and keep a slice of the reply for the log.
                    self.last_failure = (
                        "the model replied but its output is not a valid "
                        f"{schema.__name__} JSON object"
                        if content.strip()
                        else "the model returned an empty reply"
                    )
                    log.warning(
                        "llm_tool_output_invalid",
                        purpose=purpose,
                        schema=schema.__name__,
                        reply_chars=len(content),
                        reply_head=content.strip()[:200],
                    )
                return validated
            if round_index >= max_rounds:
                log.error("llm_tool_round_budget_exhausted", rounds=max_rounds)
                self.last_failure = (
                    f"the model was still requesting tools after {max_rounds} rounds; the "
                    "bounded tool loop stopped before it produced an answer"
                )
                return None

            messages.append(
                {
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": tool_calls,
                }
            )
            for call in tool_calls:
                function = call.get("function") or {}
                name = str(function.get("name") or "")
                arguments = function.get("arguments") or "{}"
                # `execute` is the allowlisted dispatcher. It validates the name and the
                # arguments; nothing here trusts what the model asked for.
                result = execute(name, arguments)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": str(call.get("id") or "missing"),
                        "name": name,
                        "content": json.dumps(result, ensure_ascii=True),
                    }
                )
        self.last_failure = (
            f"the bounded tool loop ran its {max_rounds} rounds without the model "
            "returning a final answer"
        )
        return None

    def _exchange_with_retry(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_output_tokens: int,
    ) -> tuple[dict[str, Any], int]:
        """One tool round, retried only on the overloaded-upstream shapes."""
        exchange = (
            self._gemini_exchange if self._provider_name() == "gemini" else self._groq_exchange
        )
        last: Exception | None = None
        for attempt in range(1, MAX_TRANSPORT_ATTEMPTS + 1):
            self._last_attempts = attempt
            try:
                message = exchange(
                    messages=messages, tools=tools, max_output_tokens=max_output_tokens
                )
                return message, attempt
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in RETRYABLE_STATUS:
                    raise
                if is_permanently_refused(exc):
                    # Waiting cannot shrink the request, and it cannot buy credits either.
                    # Fail now with the provider's own words so the fix (a smaller
                    # workspace, or a topped-up account) is obvious from the log.
                    raise LLMError(f"provider refused this request: {_explain(exc)}") from exc
                last = exc
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = exc
            if attempt < MAX_TRANSPORT_ATTEMPTS:
                # Same rule on the tool loop, where it matters most: the code interpreter
                # runs after the checklist has already spent most of the minute's tokens.
                stated = retry_delay_from(last)
                delay = stated or BACKOFF_BASE_S * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                log.warning(
                    "llm_tool_retrying",
                    attempt=attempt,
                    delay_s=round(delay, 2),
                    stated=bool(stated),
                )
                time.sleep(delay)
        raise LLMError(
            f"tool round failed after {MAX_TRANSPORT_ATTEMPTS} attempts: {_explain(last)}"
        )

    def _groq_exchange(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_output_tokens: int,
    ) -> dict[str, Any]:
        """One Groq message exchange for the bounded tool loop."""
        key = self._settings.groq_api_key
        if key is None:
            raise LLMError("groq selected but GROQ_API_KEY is unset")
        response = httpx.post(
            GROQ_CHAT_COMPLETIONS_URL,
            headers={
                "Authorization": f"Bearer {key.get_secret_value()}",
                "Content-Type": "application/json",
            },
            json={
                "model": self._model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "max_tokens": max_output_tokens,
            },
            timeout=120.0,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        if "error" in payload:
            raise LLMError(str(payload["error"])[:200])
        self._capture_usage(payload)
        choices = payload.get("choices") or []
        if not choices:
            raise LLMError("provider returned no choices")
        message = choices[0].get("message") or {}
        if not isinstance(message, dict):
            raise LLMError("provider returned an invalid message")
        return message

    def _capture_usage(self, payload: dict[str, Any]) -> None:
        """Record the provider's own token counts for the call just completed.

        `_last_usage` was declared and read by the call-stat path, but nothing populated
        it — `_dispatch` called this method and it did not exist. Because every LLM call
        degrades gracefully, the resulting `AttributeError` was caught, logged once, and
        turned into `None`: the client returned no completion for ANY request while the
        pipeline carried on and the GenAI stage produced nothing. A total outage hidden
        by the very mechanism meant to stop one sub-analyser failure killing a job.

        Provider counts are preferred over the `len(text) // CHARS_PER_TOKEN` estimate
        because the budget is an assert, and asserting against an estimate is asserting
        against a guess. `measured` on the emitted stat records which was used.
        """
        usage = payload.get("usage")
        if not isinstance(usage, dict):
            self._last_usage = self._gemini_usage(payload)
            return
        captured = {
            field_name: int(usage[field_name])
            for field_name in ("prompt_tokens", "completion_tokens", "total_tokens")
            if isinstance(usage.get(field_name), (int, float))
        }
        self._last_usage = captured or None

    @staticmethod
    def _gemini_usage(payload: dict[str, Any]) -> dict[str, int] | None:
        """Gemini's `usageMetadata` in the same units as Groq's `usage`.

        `thoughtsTokenCount` is added to the completion count rather than ignored: a
        thinking model's thoughts are billed as output and consume the same
        `maxOutputTokens`, so leaving them out would understate what the call cost — the
        exact kind of number the honesty requirements say must be measured, not massaged.
        """
        meta = payload.get("usageMetadata")
        if not isinstance(meta, dict):
            return None

        def count(name: str) -> int | None:
            value = meta.get(name)
            return int(value) if isinstance(value, (int, float)) else None

        prompt = count("promptTokenCount")
        candidates = count("candidatesTokenCount")
        thoughts = count("thoughtsTokenCount") or 0
        total = count("totalTokenCount")
        captured: dict[str, int] = {}
        if prompt is not None:
            captured["prompt_tokens"] = prompt
        if candidates is not None or thoughts:
            captured["completion_tokens"] = (candidates or 0) + thoughts
        if total is not None:
            captured["total_tokens"] = total
        return captured or None

    # ── transport ────────────────────────────────────────────────────────────
    def _provider_name(self) -> str:
        """Read from settings, not from `self._provider`.

        Some call sites build a client with `__new__` to avoid touching the network, so
        the instance attribute may not exist; the settings object always does.
        """
        return str(getattr(self._settings, "llm_provider", "groq"))

    def _dispatch(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool = False
    ) -> str | None:
        if self._provider_name() == "gemini":
            return self._gemini(system, user, max_output_tokens, json_mode)
        return self._groq(system, user, max_output_tokens, json_mode)

    def _groq(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool = False
    ) -> str | None:
        key = self._settings.groq_api_key
        if key is None:
            raise LLMError("groq selected but GROQ_API_KEY is unset")
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_output_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        response = httpx.post(
            GROQ_CHAT_COMPLETIONS_URL,
            headers={
                "Authorization": f"Bearer {key.get_secret_value()}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=120.0,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        if "error" in payload:
            raise LLMError(str(payload["error"])[:200])
        self._capture_usage(payload)
        choices = payload.get("choices") or []
        if not choices:
            return None
        return str(choices[0]["message"].get("content") or "")

    # ── Gemini transport ─────────────────────────────────────────────────────
    def _gemini_post(self, body: dict[str, Any]) -> dict[str, Any]:
        """One `generateContent` call. The key is a header, never a query parameter."""
        key = getattr(self._settings, "gemini_api_key", None)
        if key is None:
            raise LLMError("gemini selected but GEMINI_API_KEY is unset")
        response = httpx.post(
            gemini_url(self._model),
            headers={
                "x-goog-api-key": key.get_secret_value(),
                "Content-Type": "application/json",
            },
            json=body,
            timeout=120.0,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        if "error" in payload:
            raise LLMError(str(payload["error"])[:200])
        self._capture_usage(payload)
        return payload

    def _gemini(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool = False
    ) -> str | None:
        """One Gemini completion, with the same contract as `_groq`."""
        generation: dict[str, Any] = {"maxOutputTokens": max_output_tokens}
        if json_mode:
            # Gemini's equivalent of `response_format={"type": "json_object"}`. Note it is
            # NOT usable together with `tools` — see `_gemini_exchange`.
            generation["responseMimeType"] = "application/json"
        body: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": generation,
        }
        if system:
            # Rule 6 depends on this staying a separate field: sample-derived text goes in
            # `contents`, and nothing sample-derived is ever concatenated into it.
            body["systemInstruction"] = {"parts": [{"text": system}]}
        return str(message_from_gemini(self._gemini_post(body)).get("content") or "")

    def _gemini_exchange(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_output_tokens: int,
    ) -> dict[str, Any]:
        """One Gemini message exchange for the bounded tool loop.

        Deliberately no `responseMimeType: application/json` here even though the final
        round must return JSON: Gemini rejects the combination outright ("Function calling
        with a response mime type ... is unsupported"), so the schema is carried by the
        prompt and enforced by `parse_and_validate`, exactly as on the Groq path.
        """
        system, contents = to_gemini_contents(messages)
        body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": max_output_tokens},
        }
        if system:
            body["systemInstruction"] = system
        declarations = to_gemini_tools(tools)
        if declarations:
            body["tools"] = declarations
            body["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
        return message_from_gemini(self._gemini_post(body))
