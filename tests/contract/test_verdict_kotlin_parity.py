"""The Kotlin end of contract A15 may not drift from the Python end.

`drishti/contracts/verdict.py` is the single source of truth for the `Verdict` shape.
The consumer Android screen cannot import it, so `shield/…/ConsumerVerdict.kt` is a
hand-written adapter over the same JSON — and a hand-written mirror of a contract is
exactly the drift failure `CLAUDE.md` rule 1 exists to prevent.

So the mirror is not maintained by anyone remembering. These tests read the pydantic
models and the Kotlin file and fail if a field exists on one side and not the other,
in either direction. Adding a field to `verdict.py` breaks this test until the
adapter learns it; parsing a key in Kotlin that no longer exists in the model breaks
it too.

The last test is a different guarantee, for the same screen: the consumer verdict
screen must never render an analyst-only field. Score, confidence, MITRE technique
IDs, evidence refs and the severity band belong to the analyst portal. A consumer
about to lose money to a fake bank app does not need a number, and putting one on
that screen has historically been how a warning stops being read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from drishti.contracts.verdict import (
    DynamicTraceView,
    Verdict,
    VictimProfileView,
)

REPO = Path(__file__).resolve().parents[2]
SHIELD = REPO / "shield/app/src/main/java/in/drishti/shield"
ADAPTER = SHIELD / "ConsumerVerdict.kt"
CONSUMER_SCREEN = SHIELD / "ui/ConsumerVerdictActivity.kt"

#: Every contract key in the adapter is read through an `opt…`/`get…` call, either as
#: `json.optString("key")` or as the list helper `getStrings(json, "key")`. Matching on
#: the call rather than on bare string literals is what keeps an unrelated literal —
#: `it != "null"`, a log tag — from being mistaken for a contract field.
_KEY_CALL = re.compile(r"\b(?:opt|get)[A-Za-z]*\(\s*(?:json,\s*)?\"([a-z0-9_]+)\"")


def _model_fields() -> set[str]:
    """Every field name across the three models that make up one `Verdict` JSON."""
    fields: set[str] = set()
    for model in (Verdict, VictimProfileView, DynamicTraceView):
        fields |= set(model.model_fields)
    return fields


def _adapter_keys() -> set[str]:
    return set(_KEY_CALL.findall(ADAPTER.read_text()))


def test_adapter_file_exists() -> None:
    assert ADAPTER.is_file(), f"the Kotlin end of contract A15 is missing: {ADAPTER}"


def test_adapter_names_its_source_of_truth() -> None:
    """A reader of the Kotlin file must be told where the contract actually lives."""
    assert "drishti/contracts/verdict.py" in ADAPTER.read_text()


def test_every_contract_field_is_parsed_by_the_adapter() -> None:
    missing = sorted(_model_fields() - _adapter_keys())
    assert not missing, (
        "fields exist in drishti/contracts/verdict.py but are not parsed in "
        f"{ADAPTER.relative_to(REPO)}: {missing}"
    )


def test_the_adapter_parses_nothing_the_contract_does_not_define() -> None:
    stale = sorted(_adapter_keys() - _model_fields())
    assert not stale, (
        f"{ADAPTER.relative_to(REPO)} parses keys that contract A15 no longer defines: {stale}"
    )


@pytest.mark.parametrize(
    "literal",
    ["STATIC_ONLY", "REPLAY", "LIVE", "BLOCK", "REVIEW", "MONITOR"],
)
def test_enumerated_values_are_all_handled(literal: str) -> None:
    """`provenance` and `recommended_action` are closed sets; the UI branches on them."""
    assert literal in ADAPTER.read_text(), (
        f"contract A15 allows {literal!r} but the adapter never mentions it"
    )


FIXTURES = sorted((SHIELD.parents[3] / "assets/verdicts").glob("*.json"))


def test_the_rehearsal_fixtures_exist() -> None:
    assert FIXTURES, "the consumer screen ships no bundled verdict fixtures"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_every_bundled_fixture_is_a_real_verdict(path: Path) -> None:
    """A fixture that does not validate is a fixture that lies about the contract.

    `DrishtiModel` forbids extra fields, so this also catches a fixture carrying a key
    the contract dropped — the failure that would otherwise show up as a blank line on
    a projector.
    """
    Verdict.model_validate_json(path.read_text())


#: Fields that belong to the analyst portal and must not reach a consumer's screen.
#: Named as they appear in the Kotlin adapter.
ANALYST_ONLY = (
    "threatScore",
    "severityBand",
    "confidence",
    "attackTechniques",
    "evidenceRefs",
    "adversarialElicitationDeployed",
    "limitations",
    "dynamicTrace",
)


@pytest.mark.parametrize("field", ANALYST_ONLY)
def test_no_analyst_field_reaches_the_consumer_screen(field: str) -> None:
    source = CONSUMER_SCREEN.read_text()
    # Comments are where this rule is explained, so they are allowed to name it.
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith(("*", "//", "/*"))
    )
    assert field not in code, (
        f"{CONSUMER_SCREEN.relative_to(REPO)} renders `{field}`, which is an "
        "analyst-only field. The consumer screen shows consumerSummary, "
        "impersonatedTarget and recommendedAction only."
    )
