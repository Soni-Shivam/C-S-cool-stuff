import hashlib

import pytest

from drishti.llm import MockProvider
from drishti.pipeline import run_pipeline
from drishti.static.androguard_adapter import CertInfo, ParsedApk

TS = "2026-08-11T00:00:00Z"
P = "android.permission."


class _Classifier:
    def predict_proba(self, feats): return 0.72
    def top_features(self, feats, k=5): return ["combo_otp_interception"]


@pytest.fixture
def pipeline_input(tmp_path, monkeypatch):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"PK\x03\x04safe-static-fixture")
    parsed = ParsedApk(
        package="in.drishti.fixture",
        permissions=[P + "RECEIVE_SMS", P + "READ_SMS"],
        cert=CertInfo(),
    )
    monkeypatch.setattr("drishti.pipeline.pipeline.parse_apk", lambda _: parsed)
    monkeypatch.setattr("drishti.pipeline.pipeline.compile_rules", lambda: object())
    monkeypatch.setattr("drishti.pipeline.pipeline.scan_bytes", lambda *_: [])
    return apk


def _run(apk, mode, observations=None):
    return run_pipeline(
        str(apk), timestamp=TS, provider=MockProvider(), classifier=_Classifier(),
        known_bad={}, dynamic_mode=mode, observations=observations,
    )


def test_absent_and_simulated_are_distinct_and_simulation_does_not_raise_score(pipeline_input):
    absent = _run(pipeline_input, "absent")
    simulated = _run(pipeline_input, "simulated")
    assert absent.verdict.dynamic_status == "absent"
    assert absent.verdict.dynamic_simulated is False
    assert simulated.verdict.dynamic_status == "simulated"
    assert simulated.verdict.dynamic_simulated is True
    assert simulated.verdict.threat_score == absent.verdict.threat_score
    assert all(n["source_tool"] != "sandbox_sim" for n in absent.ledger)
    assert any(n["source_tool"] == "sandbox_sim" for n in simulated.ledger)


def test_observed_artifact_is_sha_bound_and_can_add_runtime_score(pipeline_input):
    sha = hashlib.sha256(pipeline_input.read_bytes()).hexdigest()
    payload = {
        "sha256": sha,
        "package": "in.drishti.fixture",
        "simulated": False, "outcome": "completed",
        "started_at": TS, "finished_at": "2026-08-11T00:01:00Z", "duration_s": 60.0,
        "metadata": {"harness_version": "test", "hook_version": "test", "emulator_image": "test-image",
                     "emulator_serial": "emulator-5554", "avd_name": "drishti", "containment_manifest_sha256": "b" * 64,
                     "containment_verified": True, "containment_verified_at": TS},
        "snapshot": {"name": "clean", "before_restore": "passed", "after_restore": "passed", "package_absent_after": True},
        "observations": [{"type": "observation", "technique": "SMS receiver activity", "mitre": "T1582",
                          "detail": "captured by sealed fixture harness", "source_hook": "SmsMessage.getMessageBody",
                          "redacted": True, "occurred_at": "2026-08-11T00:00:30Z"}],
        "failures": [], "diagnostics": [], "mitre_observed": ["T1582"],
    }
    absent = _run(pipeline_input, "absent")
    observed = _run(pipeline_input, "observed", payload)
    assert observed.verdict.dynamic_status == "observed"
    assert observed.verdict.threat_score > absent.verdict.threat_score
    assert any(n["content"].startswith("[OBSERVED]") for n in observed.ledger)
    with pytest.raises(ValueError, match="SHA-256"):
        _run(pipeline_input, "observed", {**payload, "sha256": "0" * 64})


def test_requested_observed_mode_never_falls_back_to_simulation(pipeline_input):
    with pytest.raises(ValueError, match="require"):
        _run(pipeline_input, "observed")
