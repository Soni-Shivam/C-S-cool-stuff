"""The shared `Verdict` is a projection, and it must not be able to lie.

Five workstreams build against this shape. These tests pin the properties that would
otherwise drift as each surface starts rendering it.
"""

from __future__ import annotations

import pytest

from drishti.contracts.dynamic_trace import (
    ApiEvent,
    DecryptedBlob,
    DynamicTrace,
    TraceSourceKind,
)
from drishti.contracts.genai_verdict import GenAIVerdict, TechniqueMapping, VictimProfile
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import CertificateInfo, FileMeta, StaticReport
from drishti.contracts.verdict import build_verdict


@pytest.fixture
def meta() -> FileMeta:
    return FileMeta(
        sha256="a" * 64, size_bytes=4_000_000, filename="RTO_Challan.apk", package="in.rto.challan"
    )


@pytest.fixture
def static() -> StaticReport:
    return StaticReport(
        sha256="a" * 64,
        package="in.rto.challan",
        app_label="RTO Challan",
        version_name="1.0",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        certificate=CertificateInfo(
            sha256="b" * 64,
            subject="CN=Unknown",
            issuer="CN=Unknown",
            not_before="2026-08-01T00:00:00Z",
            not_after="2056-08-01T00:00:00Z",
            age_days=5,
            self_signed=True,
        ),
    )


def _score(band: SeverityBand, s: int) -> CompositeScore:
    return CompositeScore(S=s, band=band, C=0.8, gamma=0.7)


def _trace(**kwargs) -> DynamicTrace:
    base = {"run_id": "r1", "source": TraceSourceKind.LIVE}
    return DynamicTrace(**{**base, **kwargs})


# ── provenance is derived, never declared ────────────────────────────────────
def test_no_trace_is_static_only(meta, static) -> None:
    v = build_verdict(meta=meta, score=_score(SeverityBand.HIGH, 70), static=static)
    assert v.provenance == "STATIC_ONLY"
    assert v.dynamic_trace is None


def test_a_replay_can_never_present_as_live(meta, static) -> None:
    """The badge is the honesty affordance; a config flag must not be able to fake it."""
    replay = _trace(source=TraceSourceKind.REPLAY, detonated=True)
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.HIGH, 70), trace=replay).provenance
        == "REPLAY"
    )


def test_a_hand_authored_trace_is_replay_even_if_it_claims_live(meta) -> None:
    """`synthetic` beats `source`. A fixture somebody typed is never LIVE."""
    fake = _trace(source=TraceSourceKind.LIVE, synthetic=True, detonated=True)
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.HIGH, 70), trace=fake).provenance
        == "REPLAY"
    )


def test_a_real_run_is_live(meta) -> None:
    live = _trace(source=TraceSourceKind.LIVE, detonated=True, synthetic=False)
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.HIGH, 70), trace=live).provenance
        == "LIVE"
    )


# ── silence is not innocence ─────────────────────────────────────────────────
def test_detonated_but_silent_is_distinguishable_from_never_run(meta) -> None:
    """`detonated=True` with nothing observed is its own state, not 'no trace'.

    Environment-aware malware stalls and looks exactly like a clean app. Collapsing the
    two into a null trace would erase the distinction the whole frontier layer exists to
    make.
    """
    silent = _trace(detonated=True, outcome="inconclusive")
    v = build_verdict(meta=meta, score=_score(SeverityBand.MEDIUM, 50), trace=silent)
    assert v.dynamic_trace is not None
    assert v.dynamic_trace.detonated is True
    assert v.dynamic_trace.api_calls == ()
    assert v.recommended_action != "MONITOR"


# ── recovered plaintext is redacted before it leaves the lab ─────────────────
def test_decrypted_strings_are_redacted(meta) -> None:
    """This object is rendered on a phone screen and in a browser.

    Plaintext recovered from a real sample can carry a victim's OTP or card number.
    """
    trace = _trace(
        detonated=True,
        decrypted_blobs=(
            DecryptedBlob(t_ms=10, plaintext_preview="otp is 483920 for card 4111111111111111"),
        ),
    )
    v = build_verdict(meta=meta, score=_score(SeverityBand.CRITICAL, 95), trace=trace)
    joined = " ".join(v.dynamic_trace.decrypted_strings)
    assert "4111111111111111" not in joined
    assert "483920" not in joined


def test_api_call_arguments_never_reach_the_verdict(meta) -> None:
    """Hooked arguments are sample-derived and can carry the same plaintext."""
    trace = _trace(
        detonated=True,
        api_events=(
            ApiEvent(t_ms=1, api="SmsManager.sendTextMessage", args=("4111111111111111",)),
        ),
    )
    v = build_verdict(meta=meta, score=_score(SeverityBand.CRITICAL, 95), trace=trace)
    assert v.dynamic_trace.api_calls == ("SmsManager.sendTextMessage",)
    assert "4111111111111111" not in " ".join(v.dynamic_trace.api_calls)


# ── the consumer sentence is grounded and jargon-free ───────────────────────
def test_consumer_summary_names_the_impersonated_brand(meta, static) -> None:
    genai = GenAIVerdict(
        sha256="a" * 64,
        victim=VictimProfile(impersonated_target="SBI", language="Hindi", tactic="urgency"),
        behaviours={"reads_sms": True},
    )
    v = build_verdict(
        meta=meta, score=_score(SeverityBand.CRITICAL, 95), static=static, genai=genai
    )
    assert "SBI" in v.consumer_summary
    assert v.impersonated_target == "SBI"


def test_consumer_summary_carries_no_jargon(meta, static) -> None:
    """This is the text a frightened non-technical person reads and acts on."""
    genai = GenAIVerdict(sha256="a" * 64, behaviours={"overlays_other_apps": True})
    v = build_verdict(
        meta=meta, score=_score(SeverityBand.CRITICAL, 95), static=static, genai=genai
    )
    lowered = v.consumer_summary.lower()
    for jargon in ("mitre", "t15", "sink", "payload", "exfiltrat", "apk", "sha256", "confidence"):
        assert jargon not in lowered, f"consumer summary leaked jargon: {jargon}"


# ── only asserted behaviours and real techniques are carried ─────────────────
def test_only_true_behaviours_are_listed(meta) -> None:
    genai = GenAIVerdict(
        sha256="a" * 64,
        behaviours={"reads_sms": True, "hides_icon": False},
        techniques=(
            TechniqueMapping(
                technique_id="T1582", name="SMS Control", tactic="Impact", layer="static"
            ),
        ),
    )
    v = build_verdict(meta=meta, score=_score(SeverityBand.HIGH, 70), genai=genai)
    assert v.behaviors_detected == ("reads_sms",)
    assert v.attack_techniques == ("T1582",)


def test_bands_map_to_the_three_consumer_actions(meta) -> None:
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.CRITICAL, 95)).recommended_action
        == "BLOCK"
    )
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.HIGH, 70)).recommended_action == "BLOCK"
    )
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.MEDIUM, 50)).recommended_action
        == "REVIEW"
    )
    assert (
        build_verdict(meta=meta, score=_score(SeverityBand.LOW, 10)).recommended_action == "MONITOR"
    )


# ── the consumer sentences must cover every behaviour the model can assert ───
def test_every_behaviour_key_has_a_consumer_sentence() -> None:
    """A behaviour with no sentence is silently invisible to the person at risk.

    Measured regression: an earlier draft invented shorter key names (`reads_sms`,
    `hides_icon`) that match nothing `BEHAVIOUR_WEIGHTS` ever emits. Every real sample
    fell through to the generic fallback while the fixture-based tests passed, because
    the fixtures used the invented names too. This asserts against the REAL table, so a
    new behaviour cannot be added to the weight table without someone writing the
    sentence a victim will read.
    """
    from drishti.contracts.verdict import _PLAIN_HARM
    from drishti.m4_genai.safety import BEHAVIOUR_WEIGHTS

    covered = {key for key, _ in _PLAIN_HARM}
    missing = sorted(set(BEHAVIOUR_WEIGHTS) - covered)
    assert missing == [], f"behaviours with no consumer sentence: {missing}"

    unknown = sorted(covered - set(BEHAVIOUR_WEIGHTS))
    assert unknown == [], f"consumer sentences for keys the model never emits: {unknown}"


def test_the_worst_behaviour_is_the_one_shown() -> None:
    """Ordering is deliberate: a fake banking screen outranks a device-id read."""
    from drishti.contracts.verdict import build_verdict

    genai = GenAIVerdict(
        sha256="a" * 64,
        behaviours={"harvests_device_identifiers": True, "overlays_other_apps": True},
    )
    v = build_verdict(
        meta=FileMeta(sha256="a" * 64, size_bytes=1, filename="x.apk"),
        score=_score(SeverityBand.CRITICAL, 95),
        genai=genai,
    )
    assert "fake screens" in v.consumer_summary
