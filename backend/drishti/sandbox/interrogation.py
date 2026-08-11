"""Bounded M2→M4→M3 adversarial interrogation controller.

The executor is supplied only validated catalogue entries. The public API never
constructs or invokes this controller.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Callable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from drishti.ledger import Ledger
from drishti.sandbox.catalog import CatalogueEntry, require_allowlisted


class StructuralHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    statement: str
    evidence_refs: list[str] = Field(min_length=1)
    depth: int = Field(default=0, ge=0, le=8)


class InstrumentationSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    hook_ids: list[str] = Field(default_factory=list, max_length=8)
    stimulus_ids: list[str] = Field(default_factory=list, max_length=8)
    rationale: str = Field(max_length=500)


class AttemptResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    state: Literal["observed", "no_observation", "crashed", "hook_error", "timeout"]
    observations: list[str] = Field(default_factory=list, max_length=1000)
    crash_summary: str | None = Field(default=None, max_length=1000)
    new_hypotheses: list[StructuralHypothesis] = Field(default_factory=list, max_length=8)


class Selector(Protocol):
    def __call__(self, hypothesis: StructuralHypothesis, attempt: int, prior: AttemptResult | None) -> InstrumentationSelection: ...


class Executor(Protocol):
    def __call__(self, hypothesis: StructuralHypothesis, hooks: list[CatalogueEntry], stimuli: list[CatalogueEntry], timeout_s: int) -> AttemptResult: ...


@dataclass(frozen=True)
class InterrogationLimits:
    max_attempts_per_hypothesis: int = 3
    max_recursion_depth: int = 3
    max_total_runtime_s: int = 1800
    attempt_timeout_s: int = 300

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts_per_hypothesis <= 3:
            raise ValueError("M3 permits one to three attempts per hypothesis")
        if not 0 <= self.max_recursion_depth <= 3:
            raise ValueError("M3 recursion depth must be at most three")
        if not 1 <= self.max_total_runtime_s <= 1800:
            raise ValueError("M3 total runtime must be at most 30 minutes")


@dataclass
class InterrogationSummary:
    attempts: int = 0
    observed: int = 0
    stopped_reason: str = "queue_exhausted"
    results: list[AttemptResult] = field(default_factory=list)


class InterrogationController:
    def __init__(
        self,
        *,
        selector: Selector,
        executor: Executor,
        ledger: Ledger,
        timestamp: str,
        limits: InterrogationLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.selector = selector
        self.executor = executor
        self.ledger = ledger
        self.timestamp = timestamp
        self.limits = limits or InterrogationLimits()
        self.monotonic = monotonic

    def run(self, hypotheses: list[StructuralHypothesis]) -> InterrogationSummary:
        queue = deque(hypotheses)
        seen = {hypothesis.id for hypothesis in hypotheses}
        started = self.monotonic()
        summary = InterrogationSummary()

        while queue:
            if self.monotonic() - started >= self.limits.max_total_runtime_s:
                summary.stopped_reason = "total_runtime_limit"
                self._append("m3_stop", "Total runtime limit reached; interrogation stopped.")
                break
            hypothesis = queue.popleft()
            usage: Counter[str] = Counter()
            if hypothesis.depth > self.limits.max_recursion_depth:
                self._append("m3_stop", f"Hypothesis {hypothesis.id} exceeded recursion depth.", hypothesis.evidence_refs)
                continue
            prior: AttemptResult | None = None
            for attempt in range(1, self.limits.max_attempts_per_hypothesis + 1):
                selection = self.selector(hypothesis, attempt, prior)
                hooks = require_allowlisted(selection.hook_ids, "hook")
                stimuli = require_allowlisted(selection.stimulus_ids, "stimulus")
                for entry in hooks + stimuli:
                    usage[entry.id] += 1
                    if usage[entry.id] > entry.max_uses:
                        raise ValueError(f"catalogue use limit exceeded: {entry.id}")
                plan = self._append(
                    "m3_plan",
                    f"Hypothesis {hypothesis.id}; attempt {attempt}; hooks={selection.hook_ids}; stimuli={selection.stimulus_ids}; rationale={selection.rationale}",
                    hypothesis.evidence_refs,
                )
                for stimulus in stimuli:
                    self._append("m3_stimulus", f"Applied allowlisted stimulus {stimulus.id} for attempt {attempt}.", [plan.id])
                remaining = self.limits.max_total_runtime_s - int(self.monotonic() - started)
                timeout = max(1, min(self.limits.attempt_timeout_s, remaining))
                result = self.executor(hypothesis, hooks, stimuli, timeout)
                summary.attempts += 1
                summary.results.append(result)
                prior = result
                if result.state == "observed":
                    summary.observed += 1
                    for observation in result.observations:
                        self._append("dynamic_obs", f"[OBSERVED] {observation}", [plan.id])
                    for child in result.new_hypotheses:
                        if child.id not in seen and child.depth <= self.limits.max_recursion_depth:
                            seen.add(child.id)
                            queue.append(child)
                            self._append("m3_hypothesis", f"New bounded hypothesis {child.id}: {child.statement}", child.evidence_refs + [plan.id])
                    break
                self._append(
                    "m3_retry",
                    f"Attempt {attempt} state={result.state}; diagnostic={result.crash_summary or 'no observation'}",
                    [plan.id],
                )
                if result.state == "no_observation":
                    break
            else:
                self._append("m3_stop", f"Hypothesis {hypothesis.id} exhausted three repaired attempts.", hypothesis.evidence_refs)
        return summary

    def _append(self, type_: str, content: str, refs: list[str] | None = None):
        return self.ledger.append(
            type_, "m3_interrogation", content,
            location="sealed-runtime", confidence=1.0,
            timestamp=self.timestamp, refs=refs or [],
        )
