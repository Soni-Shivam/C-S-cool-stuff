"""The post-sandbox GenAI pass must not degrade the verdict it reuses.

`_genai_full` re-uses the static-pass verdict when there is no dynamic evidence.
That is the right call — re-sending an identical prompt and presenting the same
answer as a second opinion would be dishonest. But it previously also stamped
`partial=True` on that verdict, and `m6_score.engine` drops `B` from the fused
term for any partial GenAI report. The combination meant a complete behavioural
checklist was silently deleted from the score on every un-detonated run.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from drishti.config import Settings
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.ledger.store import LedgerStore
from drishti.pipeline import Context, _genai_full

SHA = "a" * 64


@pytest.fixture
def ctx(tmp_path: Path) -> Iterator[Context]:
    settings = Settings(
        groq_api_key="gsk-test",
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_genai_full")
    yield Context(settings=settings, ledger=store)
    store.close()


def _static_pass_verdict(**overrides: object) -> GenAIVerdict:
    base = {
        "sha256": SHA,
        "provider": "groq",
        "behavioural_risk_B": 0.6,
        "behaviours": {"gates_behaviour_on_installed_apps": True},
        "partial": False,
    }
    base.update(overrides)
    return GenAIVerdict(**base)  # type: ignore[arg-type]


def test_reusing_a_complete_static_verdict_does_not_mark_it_partial(ctx: Context) -> None:
    """Reuse is not degradation: B must survive into the final score."""
    ctx.artefacts["genai"] = _static_pass_verdict()

    result = _genai_full(ctx, SHA)

    assert result.partial is False, (
        "a complete static verdict is not partial merely by being reused"
    )
    assert result.behavioural_risk_B == 0.6
    assert result.behaviours == {"gates_behaviour_on_installed_apps": True}


def test_the_reuse_is_still_disclosed_in_errors(ctx: Context) -> None:
    """Honesty is preserved by saying what happened, not by faking degradation."""
    ctx.artefacts["genai"] = _static_pass_verdict()

    result = _genai_full(ctx, SHA)

    assert any("no dynamic evidence" in e for e in result.errors)


def test_a_genuinely_partial_static_verdict_stays_partial(ctx: Context) -> None:
    """Reuse must not launder a degraded static pass into a complete one."""
    ctx.artefacts["genai"] = _static_pass_verdict(partial=True, errors=("llm timed out",))

    result = _genai_full(ctx, SHA)

    assert result.partial is True


def test_no_static_verdict_at_all_is_still_partial(ctx: Context) -> None:
    """Nothing to reuse is a real degradation."""
    result = _genai_full(ctx, SHA)

    assert result.partial is True
    assert result.behavioural_risk_B == 0.0
