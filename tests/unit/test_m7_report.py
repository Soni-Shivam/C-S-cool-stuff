"""M7 export honesty invariants.

Every test here guards a claim the product makes to a human reader. They are written
as tests rather than trusted to care because CLAUDE.md's honesty requirements are
supposed to track reality automatically — "the report discloses replay" is worth
nothing if it depends on the next person remembering.
"""

from __future__ import annotations

import pytest

from drishti.contracts.dynamic_trace import DynamicTrace, NetworkFlow, TraceSourceKind
from drishti.contracts.genai_verdict import GenAIVerdict, GroundedClaim, VerifierStatus
from drishti.contracts.job import Job, JobStage
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import CertificateInfo, FileMeta, StaticReport
from drishti.m7_report import dossier, html, stix, yara


@pytest.fixture
def meta() -> FileMeta:
    return FileMeta(
        sha256="a" * 64,
        size_bytes=4_182_233,
        filename="RTO_Challan.apk",
        package="in.gov.rto.challan",
        app_label="RTO Challan",
    )


@pytest.fixture
def job() -> Job:
    return Job(
        id="job_test000000",
        sha256="a" * 64,
        filename="RTO_Challan.apk",
        stage=JobStage.DONE,
        created_at="2026-08-26T00:00:00Z",
    )


@pytest.fixture
def score() -> CompositeScore:
    return CompositeScore(S=91, band=SeverityBand.CRITICAL, C=0.83, gamma=0.7)


@pytest.fixture
def static() -> StaticReport:
    return StaticReport(
        sha256="a" * 64,
        package="in.gov.rto.challan",
        app_label="RTO Challan",
        version_name="1.0",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        certificate=CertificateInfo(
            sha256="b" * 64,
            subject="CN=Unknown",
            issuer="CN=Unknown",
            not_before="2026-01-01T00:00:00Z",
            not_after="2046-01-01T00:00:00Z",
            age_days=12,
            self_signed=True,
        ),
        urls=("https://challan-status-verify.example-c2.net/collect",),
        crypto_constants=("MIIBIjANBgkqhkiG9w0BAQ",),
        native_libs=("libchallan_native.so",),
    )


def _trace(**kwargs) -> DynamicTrace:
    base = {"run_id": "run_1", "source": TraceSourceKind.REPLAY}
    return DynamicTrace(**{**base, **kwargs})


# ── limitations are derived, never written ──────────────────────────────────
def test_hand_authored_trace_is_disclosed_as_not_a_measurement(job, meta, score) -> None:
    trace = _trace(synthetic=True, detonated=True, outcome="completed")
    body = html.render(job=job, meta=meta, score=score, trace=trace)
    assert "hand-authored" in body.lower()
    assert "NOT A MEASUREMENT" in body


def test_replay_is_disclosed_and_not_presented_as_live(job, meta, score) -> None:
    trace = _trace(source=TraceSourceKind.REPLAY, detonated=True, outcome="completed")
    body = html.render(job=job, meta=meta, score=score, trace=trace)
    assert "REPLAY OF A REAL CAPTURE" in body
    assert "LIVE DETONATION" not in body


def test_a_sample_that_did_nothing_is_inconclusive_never_benign(job, meta, score) -> None:
    """The single most important sentence in the document.

    Environment-aware malware stalls in a sandbox and is indistinguishable from a
    clean app when it does. A quiet run must never read as a clean one.
    """
    trace = _trace(detonated=False, outcome="inconclusive")
    body = html.render(job=job, meta=meta, score=score, trace=trace)
    assert "INCONCLUSIVE, not benign" in body


def test_a_synthesised_reply_is_disclosed_as_ours_not_as_c2_behaviour(job, meta, score) -> None:
    """We answered a dead C2. The report may never let that read as the C2 answering."""
    trace = _trace(
        detonated=True,
        outcome="completed",
        network_flows=(
            NetworkFlow(
                t_ms=10,
                method="POST",
                url="http://gate.evil.tk/api",
                host="gate.evil.tk",
                synthesised=True,
            ),
        ),
    )
    body = html.render(job=job, meta=meta, score=score, trace=trace)
    assert "1 network response(s) were synthesised by DRISHTI" in body


def test_destinations_withheld_from_the_ioc_export_are_disclosed(job, meta, score) -> None:
    """A caveat derived from a flag, not a sentence someone remembered to paste in."""
    trace = _trace(
        detonated=True,
        outcome="completed",
        network_flows=(
            NetworkFlow(
                t_ms=10,
                method="GET",
                url="http://127.0.0.1:9/inert",
                host="127.0.0.1",
                injected_destination=True,
            ),
        ),
    )
    body = html.render(job=job, meta=meta, score=score, trace=trace)
    assert "1 network destination(s) were DRISHTI lab infrastructure" in body


def test_unverified_containment_is_disclosed(job, meta, score) -> None:
    trace = _trace(detonated=True, outcome="completed", containment_verified=False)
    body = html.render(job=job, meta=meta, score=score, trace=trace)
    assert "containment was not verified" in body.lower()


def test_rejected_claims_are_counted_but_never_asserted(job, meta, score) -> None:
    genai = GenAIVerdict(
        sha256="a" * 64,
        claims=(
            GroundedClaim(
                text="VERIFIED: forwards SMS to a remote endpoint.",
                evidence_refs=("ev_1",),
                agent="interpreter",
                verifier_status=VerifierStatus.PASS,
            ),
            GroundedClaim(
                text="UNVERIFIED: exfiltrates the device keystore.",
                evidence_refs=(),
                agent="interpreter",
                verifier_status=VerifierStatus.REJECTED_NO_EVIDENCE,
            ),
        ),
    )
    body = html.render(job=job, meta=meta, score=score, genai=genai)
    assert "VERIFIED: forwards SMS" in body
    assert "UNVERIFIED: exfiltrates" not in body, "a rejected claim must not be asserted"
    assert "failed verification" in body


def test_mock_provider_is_disclosed(job, meta, score) -> None:
    genai = GenAIVerdict(sha256="a" * 64, provider="mock")
    body = html.render(job=job, meta=meta, score=score, genai=genai)
    assert "mock provider" in body


# ── STIX must not launder our own output into intelligence ──────────────────
def test_stix_excludes_destinations_we_injected(meta, score) -> None:
    """A destination WE put in front of the sample is not attacker infrastructure.

    The exclusion keys on the provenance of the destination, not on who answered:
    `synthesised` says only that we authored the response body, and the on-VM proxy
    stamps that on every response it serves — sinkhole included. Keying on it would
    empty the bundle the moment a real detonation ran.
    """
    trace = _trace(
        detonated=True,
        outcome="completed",
        network_flows=(
            NetworkFlow(t_ms=10, method="POST", url="http://real-c2.test/x", host="real-c2.test"),
            NetworkFlow(
                t_ms=20,
                method="POST",
                url="http://ours.test/y",
                host="ours.test",
                synthesised=True,
                injected_destination=True,
            ),
        ),
    )
    bundle = stix.build_bundle(meta=meta, score=score, dynamic=trace)
    hosts = {o["value"] for o in bundle["objects"] if o["type"] == "domain-name"}
    assert hosts == {"real-c2.test"}


def test_stix_publishes_only_verified_claims(meta, score) -> None:
    genai = GenAIVerdict(
        sha256="a" * 64,
        claims=(
            GroundedClaim(
                text="verified finding",
                evidence_refs=("ev_1",),
                agent="a",
                verifier_status=VerifierStatus.PASS,
            ),
            GroundedClaim(
                text="rejected finding",
                evidence_refs=(),
                agent="a",
                verifier_status=VerifierStatus.REJECTED_NO_EVIDENCE,
            ),
        ),
    )
    bundle = stix.build_bundle(meta=meta, score=score, genai=genai)
    notes = [o["content"] for o in bundle["objects"] if o["type"] == "note"]
    assert notes == ["verified finding"]


def test_stix_is_deterministic(meta, score, static) -> None:
    a = stix.build_bundle(meta=meta, score=score, static=static)
    b = stix.build_bundle(meta=meta, score=score, static=static)
    assert a == b


def test_stix_carries_its_own_limitations(meta) -> None:
    score = CompositeScore(
        S=91,
        band=SeverityBand.CRITICAL,
        C=0.4,
        gamma=0.5,
        limitations=("ML model unavailable",),
    )
    bundle = stix.build_bundle(meta=meta, score=score)
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["x_drishti_limitations"] == ["ML model unavailable"]


# ── YARA must be honest about its own quality ───────────────────────────────
def test_yara_disables_itself_without_enough_distinctive_strings(meta, score) -> None:
    rule = yara.build_rule(meta=meta, score=score, static=None)
    assert rule.enabled is False
    assert "DISABLED" in rule.text
    assert "condition:" in rule.text


def test_yara_uses_repack_resistant_strings(meta, score, static) -> None:
    rule = yara.build_rule(meta=meta, score=score, static=static)
    assert rule.enabled is True
    assert "example-c2.net" in rule.text
    # The hash identifies the analysed build; it must not gate the match.
    condition = rule.text.split("condition:", 1)[1]
    assert meta.sha256 not in condition


def test_yara_drops_ubiquitous_android_strings(meta, score, static) -> None:
    """A rule matching schemas.android.com matches every APK ever compiled."""
    noisy = static.model_copy(update={"urls": ("http://schemas.android.com/apk/res/android",)})
    rule = yara.build_rule(meta=meta, score=score, static=noisy)
    assert "schemas.android.com" not in rule.text


def test_yara_drops_toolchain_boilerplate(meta, score, static) -> None:
    """Measured regression: a run over the canary keyed the rule on the Kotlin
    reflection warning, which ships in every Kotlin app and would match most of the
    Play Store. Prose that merely contains a URL is not an endpoint."""
    noisy = static.model_copy(
        update={
            "urls": (
                "Kotlin reflection is not yet supported. Please upvote "
                "https://youtrack.jetbrains.com/issue/KT-55980",
                "https://real-c2.example-evil.net/collect",
            )
        }
    )
    rule = yara.build_rule(meta=meta, score=score, static=noisy)
    assert "youtrack" not in rule.text
    assert "Kotlin reflection" not in rule.text
    assert "real-c2.example-evil.net" in rule.text


# ── the dossier must never overstate what it did ────────────────────────────
def test_dossier_never_claims_to_have_been_submitted(meta, score) -> None:
    """NCRP has no public submission API. Nothing here files a complaint."""
    pack = dossier.build(meta=meta, score=score)
    assert pack.submission_is_manual is True
    assert "NOT been submitted" in pack.as_text()
    assert pack.portal_url.startswith("https://cybercrime.gov.in")


def test_dossier_gates_reporting_on_the_band(meta) -> None:
    """A national complaint on a low-confidence result wastes an investigator's time."""
    high = dossier.build(
        meta=meta, score=CompositeScore(S=91, band=SeverityBand.CRITICAL, C=0.8, gamma=0.7)
    )
    low = dossier.build(
        meta=meta, score=CompositeScore(S=12, band=SeverityBand.LOW, C=0.8, gamma=0.7)
    )
    assert high.reportable is True
    assert low.reportable is False
    # Still produced, and it says why it should not be filed.
    assert "below the reporting threshold" in low.reason


def test_dossier_lists_only_infrastructure_the_sample_chose(meta, score) -> None:
    trace = _trace(
        detonated=True,
        outcome="completed",
        network_flows=(
            NetworkFlow(t_ms=1, method="POST", url="http://real.test/a", host="real.test"),
            NetworkFlow(
                t_ms=2,
                method="POST",
                url="http://ours.test/b",
                host="ours.test",
                synthesised=True,
                injected_destination=True,
            ),
        ),
    )
    pack = dossier.build(meta=meta, score=score, dynamic=trace)
    joined = " ".join(pack.indicators)
    assert "real.test" in joined
    assert "ours.test" not in joined, "our own harness is not attacker infrastructure"


def test_dossier_discloses_what_it_withheld_from_the_indicator_list(meta, score) -> None:
    """Failing toward not-publishing is only honest if the reader is told it happened."""
    trace = _trace(
        detonated=True,
        outcome="completed",
        network_flows=(
            NetworkFlow(
                t_ms=1,
                method="GET",
                url="http://127.0.0.1:9/inert",
                host="127.0.0.1",
                injected_destination=True,
            ),
        ),
    )
    pack = dossier.build(meta=meta, score=score, dynamic=trace)
    assert any("DRISHTI" in c and "infrastructure" in c for c in pack.caveats)


def test_dossier_carries_its_caveats_into_the_text(meta) -> None:
    score = CompositeScore(
        S=91,
        band=SeverityBand.CRITICAL,
        C=0.4,
        gamma=0.5,
        limitations=("ML model unavailable",),
    )
    pack = dossier.build(meta=meta, score=score)
    assert "LIMITATIONS OF THIS AUTOMATED ANALYSIS" in pack.as_text()
    assert "ML model unavailable" in pack.as_text()


def test_dossier_does_not_embed_the_sample(meta, score, static) -> None:
    """Hashes and derived facts only. The APK never leaves the analysis project."""
    pack = dossier.build(meta=meta, score=score, static=static)
    blob = pack.as_text()
    assert meta.sha256 in blob
    # The filename legitimately appears as a fact; what must never appear is the
    # sample itself or a route to it.
    for forbidden in ("base64,", "attachment", "download", "http://", "gs://"):
        assert forbidden not in blob.lower()
