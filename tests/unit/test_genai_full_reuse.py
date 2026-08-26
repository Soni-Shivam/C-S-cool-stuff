"""Reusing the static verdict is an outcome, not a failure — and the reason must be true.

`_genai_full` appended this to `GenAIVerdict.errors` on **every** run:

    full pass reused the static verdict: no dynamic evidence available

Two things were wrong with it, and both reached the screen.

**It was not checked.** The string was unconditional; the stage never looked at the
trace. A job that replayed a real captured detonation — with a dropped-dex path, a C2
URL and pre-encryption plaintext in hand — still reported that no dynamic evidence was
available. The one place the pipeline states what it did about dynamic evidence was
saying the opposite of what happened.

**It was filed as an error.** `ui/src/components/primitives.tsx` renders any non-empty
`errors` on a non-partial result as **"Completed with errors"**, so every successful run
carried a warning banner. `AnalyserResult.errors` means a sub-analyser failed
(CLAUDE.md rule 2). Reuse is a deliberate design decision — re-sending an identical
prompt to get an identical answer would be worse — and filing it as a failure trained
the reader to ignore the banner that exists to report real ones.

What replaces it: the accurate reason, recorded in the ledger node where the stage's
decision belongs, and `errors` left for things that actually broke.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.contracts.dynamic_trace import ApiEvent, DexLoadEvent, DynamicTrace, TraceSourceKind
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.ledger.store import LedgerStore
from drishti.pipeline import Context, _genai_full

SHA = "d" * 64


@pytest.fixture
def ctx(tmp_path: Path) -> Context:
    from drishti.config import Settings

    settings = Settings(
        llm_provider="groq",
        llm_model="qwen/qwen3.8-27b",
        groq_api_key="gsk-test",
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )
    ledger = LedgerStore(settings.db_path, settings.ledger_key_path)
    ledger.open("job_reuse")
    return Context(settings=settings, ledger=ledger)


def _static_verdict() -> GenAIVerdict:
    return GenAIVerdict(sha256=SHA, provider="gemini", behavioural_risk_B=0.4, partial=False)


def _detonated() -> DynamicTrace:
    """A real replayed capture: it detonated and produced structured evidence."""
    return DynamicTrace(
        run_id="run_x",
        source=TraceSourceKind.REPLAY,
        detonated=True,
        outcome="completed",
        synthetic=False,
        api_events=(ApiEvent(t_ms=0, api="DexClassLoader.$init"),),
        dex_loads=(
            DexLoadEvent(t_ms=0, loader="DexClassLoader", path="/data/user/0/x/cache/a.jar"),
        ),
    )


def _nothing_observed() -> DynamicTrace:
    return DynamicTrace(
        run_id="run_y",
        source=TraceSourceKind.UNAVAILABLE,
        detonated=False,
        outcome="inconclusive",
        synthetic=True,
    )


# ── the banner ───────────────────────────────────────────────────────────────
def test_reuse_is_not_reported_as_an_error(ctx: Context) -> None:
    """The UI shows any non-empty `errors` as "Completed with errors"."""
    ctx.record("genai", _static_verdict())
    ctx.record("dynamic", _nothing_observed())
    assert _genai_full(ctx, SHA).errors == ()


def test_a_real_failure_in_the_static_pass_still_survives(ctx: Context) -> None:
    """Only the reuse note goes; a genuine failure must not be swallowed with it."""
    failed = _static_verdict().model_copy(
        update={"partial": True, "errors": ("GenAI unavailable: provider returned nothing",)}
    )
    ctx.record("genai", failed)
    ctx.record("dynamic", _nothing_observed())

    out = _genai_full(ctx, SHA)
    assert out.errors == ("GenAI unavailable: provider returned nothing",)
    assert out.partial is True, "a degraded static pass stays degraded"


def test_no_static_verdict_at_all_is_still_an_error(ctx: Context) -> None:
    ctx.record("dynamic", _nothing_observed())
    out = _genai_full(ctx, SHA)
    assert out.partial is True
    assert out.errors, "having nothing to build on is a real failure"


# ── the reason must match what happened ──────────────────────────────────────
def test_the_ledger_records_that_evidence_existed_when_it_did(ctx: Context) -> None:
    """A replayed detonation is dynamic evidence. Saying otherwise is false."""
    ctx.record("genai", _static_verdict())
    ctx.record("dynamic", _detonated())
    _genai_full(ctx, SHA)

    note = _last_note(ctx)
    assert "no dynamic evidence" not in note.lower(), f"claimed no evidence, but had it: {note}"
    assert "not implemented" in note.lower() or "not re-reason" in note.lower()


def test_the_ledger_says_so_when_nothing_was_observed(ctx: Context) -> None:
    ctx.record("genai", _static_verdict())
    ctx.record("dynamic", _nothing_observed())
    _genai_full(ctx, SHA)
    assert "no dynamic evidence" in _last_note(ctx).lower()


def test_the_behavioural_signal_survives_reuse(ctx: Context) -> None:
    """The scorer drops B for a partial verdict; reuse must not make it partial."""
    ctx.record("genai", _static_verdict())
    ctx.record("dynamic", _detonated())
    out = _genai_full(ctx, SHA)
    assert out.partial is False
    assert out.behavioural_risk_B == 0.4


def _last_note(ctx: Context) -> str:
    rows = ctx.ledger.query(job_id="job_reuse")
    for node in reversed(list(rows)):
        content = node.content if isinstance(node.content, dict) else {}
        if "note" in content:
            return str(content["note"])
    raise AssertionError("no ledger node carrying a note was appended")
