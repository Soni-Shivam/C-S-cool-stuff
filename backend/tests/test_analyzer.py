from drishti.ledger import Ledger
from drishti.static.analyzer import analyze_parsed
from drishti.static.androguard_adapter import CertInfo, ParsedApk

TS = "2026-07-26T00:00:00Z"
P = "android.permission."


def _banking_trojan_apk() -> ParsedApk:
    return ParsedApk(
        package="com.evil.fakebank",
        permissions=[
            P + "SYSTEM_ALERT_WINDOW", P + "BIND_ACCESSIBILITY_SERVICE",
            P + "RECEIVE_SMS", P + "READ_SMS", P + "INTERNET",
        ],
        strings=["c2 http://evil.example/gate", "185.199.108.153"],
        cert=CertInfo(subject="CN=SBI Secure", issuer="CN=SBI Secure", self_signed=True),
    )


def test_analyze_detects_combos_and_mitre():
    led = Ledger()
    res = analyze_parsed(_banking_trojan_apk(), bundle=None, led=led, timestamp=TS)
    combo_ids = {c["id"] for c in res.combos}
    assert "banker_overlay_accessibility" in combo_ids
    assert "otp_interception" in combo_ids
    assert {"T1417", "T1516", "T1582"} <= set(res.mitre)
    assert res.signature_severity == 0.95


def test_analyze_extracts_iocs_and_cert():
    led = Ledger()
    res = analyze_parsed(_banking_trojan_apk(), bundle=None, led=led, timestamp=TS)
    assert "http://evil.example/gate" in res.iocs["urls"]
    assert "185.199.108.153" in res.iocs["ips"]
    assert res.cert["self_signed"] is True
    assert res.cert["brand_mismatch"] is True  # "SBI" in cert, not in package


def test_analyze_writes_ledger_nodes():
    led = Ledger()
    analyze_parsed(_banking_trojan_apk(), bundle=None, led=led, timestamp=TS)
    types = {n.type for n in led.nodes}
    assert "manifest" in types
    assert "api_sink" in types
    assert "ioc" in types
    assert "cert" in types
    assert led.verify_chain() is True
