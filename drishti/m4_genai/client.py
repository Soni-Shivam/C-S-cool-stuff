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

#: Status codes worth another attempt. 5xx is the overloaded upstream; 429 is rate
#: limiting. A 400/401/404 is our bug and retrying it just wastes the demo's clock.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504, 520, 522, 524})

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


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


class LLMClient:
    """Groq completion with caching, budgets and validation."""

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
            log.error("llm_call_failed", provider=self._provider, error=str(exc), purpose=purpose)
            self._record(purpose, prompt, started, MAX_TRANSPORT_ATTEMPTS, outcome="failed")
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
            try:
                return self._dispatch(system, user, max_output_tokens, json_mode), attempt
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in RETRYABLE_STATUS:
                    raise
                last = exc
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = exc
            if attempt < MAX_TRANSPORT_ATTEMPTS:
                delay = BACKOFF_BASE_S * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                log.warning(
                    "llm_retrying",
                    provider=self._provider,
                    attempt=attempt,
                    delay_s=round(delay, 2),
                    error=str(last)[:160],
                )
                time.sleep(delay)
        raise LLMError(f"provider unavailable after {MAX_TRANSPORT_ATTEMPTS} attempts: {last}")

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

    # ── Groq transport ───────────────────────────────────────────────────────
    def _dispatch(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool = False
    ) -> str | None:
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
