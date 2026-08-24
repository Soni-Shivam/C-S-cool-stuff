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
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from drishti.config import Settings
from drishti.logging import get_logger

log = get_logger(__name__)

ModelT = TypeVar("ModelT", bound=BaseModel)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

#: Roughly 4 characters per token. Deliberately crude: the point is to refuse an
#: obviously oversized prompt before paying for it, not to bill anyone accurately.
CHARS_PER_TOKEN = 4

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


class LLMError(Exception):
    """The provider could not be reached or refused the request."""


class BudgetExceededError(LLMError):
    """A hard budget from 00_GUIDING_MAP.md §12 was hit. Not retryable."""


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
    """Provider-agnostic completion with caching, budgets and validation."""

    def __init__(self, settings: Settings, *, use_cache: bool | None = None) -> None:
        self._settings = settings
        self._model = settings.resolved_llm_model
        self._provider = settings.llm_provider
        self._use_cache = settings.llm_cache_enabled if use_cache is None else use_cache
        self._cache_dir = Path(settings.llm_cache_dir)
        self.calls_made = 0

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
        self, *, system: str, user: str, max_output_tokens: int = 2000, json_mode: bool = False
    ) -> str | None:
        """One completion. Returns None on any provider failure — never raises upward.

        `BudgetExceededError` is the exception, and it propagates on purpose: a blown
        budget is a bug in the caller's loop, not a flaky network.
        """
        self._check_budgets(system + user)
        key = self._cache_key(system, user + f"\x00json={json_mode}")
        hit = self._cached(key)
        if hit is not None:
            log.info("llm_cache_hit", model=self._model, key=key[:12])
            return hit

        try:
            completion = self._dispatch(system, user, max_output_tokens, json_mode)
        except BudgetExceededError:
            raise
        except Exception as exc:
            # Degrade, do not crash (00_GUIDING_MAP.md §9.2). A failed VLM call must not
            # lose the static report.
            log.error("llm_call_failed", provider=self._provider, error=str(exc))
            return None

        self.calls_made += 1
        if completion is not None:
            self._store(key, completion)
        return completion

    def complete_as(
        self, *, system: str, user: str, schema: type[ModelT], max_output_tokens: int = 2000
    ) -> ModelT | None:
        """Completion validated into `schema`, with exactly one repair attempt.

        The repair turn shows the model its own output and the error. One attempt, not a
        loop: a model that cannot produce the schema twice will not produce it on the
        fifth try, and each attempt costs budget the job may need elsewhere.
        """
        raw = self.complete(
            system=system, user=user, max_output_tokens=max_output_tokens, json_mode=True
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
        retry = self.complete(system=system, user=repair_user, max_output_tokens=max_output_tokens)
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
    ) -> ModelT | None:
        """Run a bounded OpenRouter tool loop and validate its final JSON response.

        Other providers retain the ordinary structured completion path until their
        native adapters are implemented. The analysis tools themselves remain useful
        and tested independently; provider availability never fails the pipeline.
        """
        if self._provider != "openrouter":
            return self.complete_as(
                system=system,
                user=user,
                schema=schema,
                max_output_tokens=max_output_tokens,
            )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        for round_index in range(max_rounds + 1):
            prompt = json.dumps(messages, ensure_ascii=True)
            self._check_budgets(prompt)
            try:
                message = self._openrouter_exchange(
                    messages=messages,
                    tools=tools,
                    max_output_tokens=max_output_tokens,
                )
            except Exception as exc:
                log.error("llm_tool_round_failed", round=round_index, error=str(exc))
                return None
            self.calls_made += 1
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                if round_index >= max_rounds:
                    log.error("llm_tool_round_budget_exhausted", rounds=max_rounds)
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
                    result = execute(name, arguments)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": str(call.get("id") or "missing"),
                            "name": name,
                            "content": json.dumps(result, ensure_ascii=True),
                        }
                    )
                continue
            return parse_and_validate(str(message.get("content") or ""), schema)
        return None

    # ── providers ────────────────────────────────────────────────────────────
    def _dispatch(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool = False
    ) -> str | None:
        if self._provider == "mock":
            return self._mock(system, user)
        if self._provider == "openrouter":
            return self._openrouter(system, user, max_output_tokens, json_mode)
        raise LLMError(
            f"provider {self._provider!r} is configured but not implemented. "
            "openrouter and mock are verified working; gemini and anthropic are not "
            "wired because neither could be tested (see STATUS.md)."
        )

    def _openrouter(
        self, system: str, user: str, max_output_tokens: int, json_mode: bool = False
    ) -> str | None:
        key = self._settings.openrouter_api_key
        if key is None:
            raise LLMError("openrouter selected but DRISHTI_OPENROUTER_API_KEY is unset")
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_output_tokens,
        }
        if json_mode:
            # Reasoning models emit their chain of thought as `content`. Measured on this
            # model: the real analysis prompt came back as 7,669 characters of prose with
            # the JSON buried inside, and response_format alone did NOT stop it — that
            # only held on a trivial probe. Disabling reasoning is what actually produces
            # clean JSON (1,360 chars, parses first time), and it stops the completion
            # budget being spent on thinking tokens as well.
            #
            # Scraping the object out of the prose was the alternative, and it is the
            # thing 00_GUIDING_MAP 9.4 warns against. Fixing the request beats parsing
            # around the answer.
            body["reasoning"] = {"enabled": False}
            body["response_format"] = {"type": "json_object"}
        response = httpx.post(
            OPENROUTER_URL,
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
        choices = payload.get("choices") or []
        if not choices:
            return None
        return str(choices[0]["message"].get("content") or "")

    def _openrouter_exchange(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_output_tokens: int,
    ) -> dict[str, Any]:
        """One OpenRouter message exchange for the bounded tool loop."""
        key = self._settings.openrouter_api_key
        if key is None:
            raise LLMError("openrouter selected but DRISHTI_OPENROUTER_API_KEY is unset")
        response = httpx.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {key.get_secret_value()}",
                "Content-Type": "application/json",
            },
            json={
                "model": self._model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "reasoning": {"enabled": False},
                "response_format": {"type": "json_object"},
                "max_tokens": max_output_tokens,
            },
            timeout=120.0,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        if "error" in payload:
            raise LLMError(str(payload["error"])[:200])
        choices = payload.get("choices") or []
        if not choices:
            raise LLMError("provider returned no choices")
        message = choices[0].get("message") or {}
        if not isinstance(message, dict):
            raise LLMError("provider returned an invalid message")
        return message

    def _mock(self, system: str, user: str) -> str:
        """Deterministic offline stand-in.

        It asserts no behaviours. Mock mode exists to exercise contracts and UI states,
        not to generate plausible-looking risk signals that could be mistaken for a
        model result during an offline presentation.
        """
        from drishti.m4_genai.safety import BEHAVIOUR_WEIGHTS

        names = sorted(BEHAVIOUR_WEIGHTS)
        behaviours = dict.fromkeys(names, False)
        return json.dumps(
            {
                "behaviours": behaviours,
                "summary": "Deterministic mock verdict; no model was called.",
                "claims": [],
            }
        )
