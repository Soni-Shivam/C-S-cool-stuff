"""The sentence a victim reads must describe what we observed, not a stock fear.

The REVIEW branch of `consumer_summary` returned one hardcoded string for every sample:

    "We could not confirm this app is safe. It asks for permissions that could be used to
     read your messages or show fake screens over your banking app. Install it only if
     you are certain you trust the sender."

REVIEW is the MEDIUM band — where most real samples land — so in practice almost every
user saw a sentence naming two specific harms, **SMS interception and banking overlays**,
whether or not either behaviour had been asserted. The product owner spotted it
immediately: "why is this everywhere".

That is the exact failure the project's honesty requirements exist to prevent. It is
worse than a vague sentence, because it is precise: it tells a frightened person their
banking app is being overlaid when nothing in the analysis said so. The BLOCK branch had
this right already — it calls `_plain_harm`, which describes only behaviours the model
actually asserted.

The fix keeps the honest structure of the fallback. When nothing specific was observed,
the sentence says we could not rule harm out — which is true, and is a different
statement from naming a harm we never saw.
"""

from __future__ import annotations

import pytest

from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.verdict import _consumer_summary


def consumer_summary(action, genai, static):
    """Thin adapter so each test reads as the sentence it is about."""
    band = {"BLOCK": SeverityBand.HIGH, "REVIEW": SeverityBand.MEDIUM}.get(action, SeverityBand.LOW)
    score = CompositeScore(S=50, band=band, C=0.5, gamma=0.6)
    return _consumer_summary(score, static, genai, action)


SHA = "c" * 64


def _genai(**behaviours: bool) -> GenAIVerdict:
    return GenAIVerdict(sha256=SHA, provider="gemini", behaviours=dict(behaviours))


# ── the bug ──────────────────────────────────────────────────────────────────
def test_review_does_not_invent_sms_or_overlay_harm() -> None:
    """Nothing was asserted, so no specific harm may be named."""
    text = consumer_summary("REVIEW", _genai(), None)
    lowered = text.lower()
    assert "text message" not in lowered and "your messages" not in lowered
    assert "banking app" not in lowered
    assert "fake screen" not in lowered


def test_review_with_no_genai_verdict_at_all_names_nothing_specific() -> None:
    text = consumer_summary("REVIEW", None, None).lower()
    assert "banking app" not in text and "your messages" not in text


def test_review_still_tells_the_user_it_is_unconfirmed() -> None:
    """Dropping the invented harm must not drop the warning."""
    text = consumer_summary("REVIEW", _genai(), None).lower()
    assert "could not confirm" in text or "not confirm" in text
    assert "trust" in text, "the actionable instruction must survive"


# ── it must still describe what WAS observed ─────────────────────────────────
def test_review_names_the_overlay_harm_when_overlay_was_asserted() -> None:
    text = consumer_summary("REVIEW", _genai(overlays_other_apps=True), None).lower()
    assert "fake screen" in text or "on top of" in text


def test_review_names_the_sms_harm_when_sms_reading_was_asserted() -> None:
    text = consumer_summary("REVIEW", _genai(reads_sms_content=True), None).lower()
    assert "text message" in text or "one-time password" in text


def test_the_worst_behaviour_wins_when_several_were_asserted() -> None:
    """`_PLAIN_HARM` is ordered worst-first; REVIEW must respect that ordering too."""
    text = consumer_summary(
        "REVIEW",
        _genai(harvests_device_identifiers=True, overlays_other_apps=True),
        None,
    ).lower()
    assert "fake screen" in text or "on top of" in text


# ── the other bands are unchanged ────────────────────────────────────────────
def test_block_still_describes_the_observed_harm() -> None:
    text = consumer_summary("BLOCK", _genai(reads_sms_content=True), None).lower()
    assert "do not install" in text
    assert "text message" in text or "one-time password" in text


def test_monitor_stays_reassuring_but_hedged() -> None:
    text = consumer_summary("MONITOR", _genai(), None).lower()
    assert "nothing harmful" in text


@pytest.mark.parametrize("action", ["BLOCK", "REVIEW", "MONITOR"])
def test_every_band_produces_a_non_empty_sentence(action: str) -> None:
    assert consumer_summary(action, _genai(), None).strip()  # type: ignore[arg-type]
