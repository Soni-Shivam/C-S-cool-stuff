from drishti.genai import reason
from drishti.ledger import Ledger
from drishti.llm import MockProvider
from drishti.llm.provider import LLMProvider
from drishti.ml import MlResult
from drishti.static.analyzer import analyze_parsed
from drishti.static.androguard_adapter import CertInfo, ParsedApk

TS = "2026-07-26T00:00:00Z"
P = "android.permission."


def _setup():
    parsed = ParsedApk(
        package="com.evil.fakebank",
        permissions=[P + "SYSTEM_ALERT_WINDOW", P + "BIND_ACCESSIBILITY_SERVICE",
                     P + "RECEIVE_SMS", P + "READ_SMS"],
        strings=["http://evil/c2", "1.2.3.4"],
        cert=CertInfo(subject="CN=SBI", issuer="CN=SBI", self_signed=True),
    )
    led = Ledger()
    static_result = analyze_parsed(parsed, bundle=None, led=led, timestamp=TS)
    ml_result = MlResult(p_cal=0.88, label="malicious", top_features=["combo_otp_interception"])
    bundle = type("B", (), {"sha256": "abc"})()
    return static_result, ml_result, bundle, led


def test_reason_produces_grounded_verdict():
    static_result, ml_result, bundle, led = _setup()
    v = reason(static_result, ml_result, bundle, led, MockProvider(), TS)
    assert 0.0 <= v.behavioral_risk <= 1.0
    assert {"T1417", "T1582"} <= set(v.attack_techniques)
    # every cited ref is a real ledger node, and the claim verifies
    existing = {n.id for n in led.nodes}
    assert v.evidence_refs and all(r in existing for r in v.evidence_refs)
    assert v.verified is True
    assert any(n.type == "genai_claim" for n in led.nodes)
    assert any(n.type == "mitre_tag" for n in led.nodes)


class _HallucinatingProvider(LLMProvider):
    name = "halluc"
    live = False

    def generate(self, system, user_data):
        return ""

    def generate_json(self, system, user_data, schema):
        return {
            "summary": "fabricated",
            "behavioral_risk": 5.0,  # out of range on purpose
            "attack_techniques": ["T1417"],
            "evidence_refs": ["n1", "n99999"],  # n99999 does not exist
        }


def test_verifier_drops_hallucinated_refs_and_clamps_risk():
    static_result, ml_result, bundle, led = _setup()
    v = reason(static_result, ml_result, bundle, led, _HallucinatingProvider(), TS)
    assert v.behavioral_risk == 1.0  # clamped from 5.0
    assert "n99999" not in v.evidence_refs  # hallucinated id filtered out
    assert "n1" in v.evidence_refs
