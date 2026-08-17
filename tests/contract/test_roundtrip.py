"""Every contract model survives a JSON round-trip, and none is left untested.

docs/01_DATA_CONTRACTS.md §9.1. This is a CI gate.

Two things are being asserted, and the second is the one that earns its keep:

1. `M.model_validate(json.loads(m.model_dump_json())) == m` for every model. This
   catches a field whose type cannot survive serialisation — a `set`, a bare
   `datetime`, a tuple-keyed dict — before it reaches the ledger, where a model that
   does not round-trip breaks hash-chain verification on a different machine.

2. **Every `DrishtiModel` subclass has a factory here.** Discovery is by
   `__subclasses__()`, so adding a model without adding a factory FAILS. That is
   deliberate: a contract nobody constructs in a test is a contract the other two
   tracks will discover is wrong at integration time.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from drishti import contracts as C
from drishti.contracts.base import DrishtiModel
from drishti.m3_dynamic.trace_source import FixtureProvenance, TraceFixture

SHA = "a" * 64

#: Base classes are not contracts in their own right.
ABSTRACT: frozenset[str] = frozenset({"DrishtiModel", "AnalyserResult", "StrictWireModel"})


def _certificate() -> C.CertificateInfo:
    return C.CertificateInfo(
        sha256=SHA,
        subject="CN=Example",
        issuer="CN=Example",
        not_before="2024-01-01T00:00:00.000Z",
        not_after="2044-01-01T00:00:00.000Z",
        age_days=400,
        self_signed=True,
    )


def _harness_metadata() -> C.HarnessMetadata:
    return C.HarnessMetadata(
        harness_version="m3-harness-2.0.0",
        hook_version="m3-hooks-2.0.0",
        emulator_image="drishti-m3-tools-v1",
        emulator_serial="emulator-5554",
        avd_name="drishti-x86_64-api30",
        sample_kind="inert_fixture",
        containment_verified=True,
    )


def _observation_event() -> C.ObservationEvent:
    return C.ObservationEvent(
        technique="Runtime DEX load",
        mitre="T1407",
        detail="cache/payload.dex",
        source_hook="dexload",
        occurred_at="2026-08-13T00:00:00.000Z",
    )


#: One minimal-but-valid instance per concrete contract model.
FACTORIES: dict[str, Any] = {
    # ── corpus ──
    "CorpusSample": lambda: C.CorpusSample(
        sha256="a" * 64,
        label=1,
        split="train",
        time_band="2021-2023",
        dex_date="2022-02-01",
        pkg_name="com.example.app",
        vt_detection=37,
        apk_size=4_812_003,
    ),
    # ── evidence ──
    "EvidenceNode": lambda: C.EvidenceNode(
        id="ev_01932ab8f4c1",
        job_id="job_01932ab90e2f",
        seq=0,
        type=C.EvidenceType.FILE_META,
        source_tool="androguard",
        content={"sha256": SHA},
        location="AndroidManifest.xml#L42",
        confidence=1.0,
        timestamp="2026-08-13T00:00:00.000Z",
        prev_hash="0" * 64,
        node_hash="b" * 64,
        signature="c" * 128,
    ),
    "ChainVerification": lambda: C.ChainVerification(ok=True, node_count=13),
    # ── static / ingest ──
    "Component": lambda: C.Component(
        name="com.example.MainActivity",
        kind=C.ComponentKind.ACTIVITY,
        exported=True,
        intent_filters=("android.intent.action.MAIN",),
    ),
    "PermissionCombo": lambda: C.PermissionCombo(
        rule_id="OTP_THEFT_SURFACE",
        permissions=("android.permission.RECEIVE_SMS", "android.permission.INTERNET"),
        severity=C.Severity.HIGH,
        description="SMS read plus network egress with no launcher activity.",
        mitre="T1582",
    ),
    "CertificateInfo": _certificate,
    "CallPath": lambda: C.CallPath(
        sink_id="sms_read",
        sink_signature="Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;",
        path=("Lc/a/d;->onReceive(...)V", "Lc/a/d;->parseSms(...)V", "<sink>"),
        entrypoint="Lc/a/d;->onReceive(...)V",
        entrypoint_kind="broadcast_receiver",
        reachable_from_lifecycle=True,
    ),
    "Hypothesis": lambda: C.Hypothesis(
        id="hyp_0193",
        kind=C.HypothesisKind.TARGET_APP_PROBE,
        statement="Checks whether a target banking app is installed before acting.",
        target_methods=("Lc/a/d;->h()Z",),
        target_apis=("android.content.pm.PackageManager.getPackageInfo",),
        suggested_probe={"morph": "install_packages", "candidates": ["com.sbi.yono"]},
        priority=1,
    ),
    "ThreatIntel": lambda: C.ThreatIntel(
        sha256=SHA, detections=39, total_engines=40, source="virustotal", verdict="confirmed_bad"
    ),
    "FileMeta": lambda: C.FileMeta(
        sha256=SHA, size_bytes=4_194_304, filename="sample.apk", package="com.example"
    ),
    "StaticReport": lambda: C.StaticReport(
        sha256=SHA,
        package="com.example",
        app_label="Example",
        version_name="1.0",
        version_code=1,
        min_sdk=21,
        target_sdk=33,
        certificate=_certificate(),
    ),
    # ── dynamic ──
    "ApiEvent": lambda: C.ApiEvent(
        t_ms=3412,
        api="android.app.ApplicationPackageManager.getPackageInfo",
        args=("com.sbi.yono", "0"),
        retval=None,
        stack=("c.a.d.h", "c.a.d.check"),
    ),
    "NetworkFlow": lambda: C.NetworkFlow(
        t_ms=5000, method="POST", url="http://c2.invalid/a", host="c2.invalid", status=200
    ),
    "DecryptedBlob": lambda: C.DecryptedBlob(
        t_ms=1200,
        algorithm="AES/CBC/PKCS5Padding",
        plaintext_preview="http://c2.invalid/x",
        length_bytes=18,
        contains_url=True,
        occurrences=1925,
    ),
    "DexLoadEvent": lambda: C.DexLoadEvent(
        t_ms=800, loader="DexClassLoader", path="cache/payload.dex", in_original_apk=False
    ),
    "FileWrite": lambda: C.FileWrite(t_ms=900, path="/data/data/com.example/cache/x.dex"),
    "EvasionObservation": lambda: C.EvasionObservation(
        probe_kind="installed_package",
        queried="com.sbi.yono",
        result="MISS",
        t_ms=210,
        followed_by_stall=True,
        stall_duration_ms=3000,
        inferred_requirement="target banking app present",
    ),
    "DynamicTrace": lambda: C.DynamicTrace(
        run_id="run_01932ab90e2f", source=C.TraceSourceKind.REPLAY, outcome="completed"
    ),
    "ObservationEvent": _observation_event,
    "FailureRecord": lambda: C.FailureRecord(
        code="install_unsupported",
        stage="install",
        message="API 30 refused the APK: INSTALL_PARSE_FAILED_NO_CERTIFICATES",
        occurred_at="2026-08-13T00:00:00.000Z",
    ),
    "SnapshotLifecycle": lambda: C.SnapshotLifecycle(
        name="clean_base",
        before_restore="passed",
        after_restore="passed",
        package_absent_after=True,
    ),
    "HarnessMetadata": _harness_metadata,
    "ObservationArtifact": lambda: C.ObservationArtifact(
        sha256=SHA,
        package="com.example",
        outcome="completed",
        observations=(_observation_event(),),
        metadata=_harness_metadata(),
        started_at="2026-08-13T00:00:00.000Z",
        finished_at="2026-08-13T00:01:00.000Z",
    ),
    # ── genai ──
    "GroundedClaim": lambda: C.GroundedClaim(
        text="Registers a dynamic SMS receiver and forwards message bodies to a remote host.",
        evidence_refs=("ev_01932ab8f4c1",),
        agent="code_interpreter",
        verifier_status=C.VerifierStatus.PASS,
    ),
    "TechniqueMapping": lambda: C.TechniqueMapping(
        technique_id="T1582", name="SMS Control", tactic="Impact", layer="both"
    ),
    "VictimProfile": lambda: C.VictimProfile(
        language="hi", tactic="urgency: KYC block threat", confidence=0.7
    ),
    "VisionMatch": lambda: C.VisionMatch(
        matched_brand="sbi", similarity=0.91, threshold=0.85, method="perceptual_hash"
    ),
    "GenAIVerdict": lambda: C.GenAIVerdict(sha256=SHA, behavioural_risk_B=0.41),
    # ── ml / score ──
    "FeatureAttribution": lambda: C.FeatureAttribution(
        feature="perm:RECEIVE_SMS", value=1.0, shap=0.21, direction="+"
    ),
    "MLPrediction": lambda: C.MLPrediction(
        p_malicious_raw=0.83,
        p_calibrated=0.71,
        labels={"banker": 0.8, "dropper": 0.6},
        model_version="xgb-v1",
        feature_schema_version="1.0.0",
    ),
    "ScoreFactor": lambda: C.ScoreFactor(
        symbol="F_AI",
        label="Fused AI intelligence",
        raw=0.83,
        weight=0.50,
        contribution=41.5,
        inputs={"P_cal": 0.71, "B": 0.41},
        evidence_refs=("ev_01932ab8f4c1",),
    ),
    "ProposedAction": lambda: C.ProposedAction(action="block", rationale="Critical band."),
    "CompositeScore": lambda: C.CompositeScore(
        S=92, band=C.SeverityBand.CRITICAL, C=0.86, gamma=1.0
    ),
    # ── frontier ──
    "Morph": lambda: C.Morph(
        kind=C.MorphKind.INSTALL_PACKAGES,
        params={"packages": ["com.sbi.yono"]},
        rationale="Sample probed three Indian banking packages and stalled on MISS.",
        derived_from=("ev_01932ab8f4c1",),
    ),
    "MorphPlan": lambda: C.MorphPlan(
        id="morph_01932ab90e2f", generated_by="gemini:adversarial_elicitor"
    ),
    "SandboxPlan": lambda: C.SandboxPlan(hooks=("sms_read", "dex_load"), duration_s=120),
    # ── replay fixture format (drishti/m3_dynamic/trace_source.py) ──
    # On-disk format, so it must round-trip like any other serialised contract: a
    # fixture that cannot be re-read is a fixture that fails at the H40 tripwire.
    "FixtureProvenance": lambda: FixtureProvenance(
        kind="hand_authored",
        note="P0 placeholder; nothing here was measured.",
        authored_at="2026-08-14T00:00:00.000Z",
    ),
    "TraceFixture": lambda: TraceFixture(
        sha256="deadbeef" * 8,
        provenance=FixtureProvenance(kind="captured", source_sha256="a" * 64),
        pre_morph={"detonated": False},
        post_morph={"detonated": True},
    ),
    # ── job ──
    "StageEvent": lambda: C.StageEvent(
        stage=C.JobStage.STATIC, status="completed", at="2026-08-13T00:00:00.000Z", duration_ms=8200
    ),
    "Job": lambda: C.Job(
        id="job_01932ab90e2f",
        sha256=SHA,
        filename="sample.apk",
        stage=C.JobStage.QUEUED,
        created_at="2026-08-13T00:00:00.000Z",
    ),
}


def _all_models(root: type[DrishtiModel] = DrishtiModel) -> dict[str, type[DrishtiModel]]:
    """Every concrete DrishtiModel subclass, recursively."""
    found: dict[str, type[DrishtiModel]] = {}

    def walk(cls: type[DrishtiModel]) -> None:
        for sub in cls.__subclasses__():
            if sub.__name__ not in ABSTRACT:
                found[sub.__name__] = sub
            walk(sub)

    walk(root)
    return found


DISCOVERED = _all_models()


def test_at_least_twenty_models_exist() -> None:
    """T0.3 acceptance criterion."""
    assert len(DISCOVERED) >= 20, f"only {len(DISCOVERED)} contract models discovered"


def test_every_model_has_a_factory() -> None:
    """A new contract model must arrive with a constructed example.

    This is the test that keeps the suite honest as the contracts grow. Without it,
    round-trip coverage silently decays every time someone adds a model.
    """
    missing = sorted(set(DISCOVERED) - set(FACTORIES))
    assert missing == [], (
        f"contract models with no factory in test_roundtrip.py: {missing}. "
        "Add one — a contract nobody constructs is a contract that is wrong."
    )


def test_no_orphan_factories() -> None:
    """And a factory for a model that no longer exists is dead weight."""
    orphans = sorted(set(FACTORIES) - set(DISCOVERED))
    assert orphans == [], f"factories for models that no longer exist: {orphans}"


@pytest.mark.parametrize("name", sorted(FACTORIES))
def test_json_roundtrip(name: str) -> None:
    """model -> JSON -> model is lossless and compares equal."""
    original = FACTORIES[name]()
    revived = type(original).model_validate(json.loads(original.model_dump_json()))
    assert revived == original


@pytest.mark.parametrize("name", sorted(FACTORIES))
def test_models_are_frozen(name: str) -> None:
    """Evidence must be immutable once created (§0).

    A mutable contract would let a later stage edit what an earlier stage observed,
    leaving the hash chain attesting something that no longer matches what was
    reasoned over.
    """
    instance = FACTORIES[name]()
    field = next(iter(type(instance).model_fields))
    with pytest.raises(Exception, match=r"frozen|immutable"):
        setattr(instance, field, None)


@pytest.mark.parametrize("name", sorted(FACTORIES))
def test_models_forbid_unknown_fields(name: str) -> None:
    """A typo in a field name is an error, not a silently dropped value."""
    instance = FACTORIES[name]()
    payload = json.loads(instance.model_dump_json())
    payload["definitely_not_a_real_field"] = 1
    with pytest.raises(Exception, match=r"extra_forbidden|Extra inputs"):
        type(instance).model_validate(payload)
