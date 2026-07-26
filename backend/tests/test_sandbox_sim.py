from drishti.ledger import Ledger
from drishti.ml import MlResult
from drishti.sandbox import interrogate
from drishti.static.analyzer import analyze_parsed
from drishti.static.androguard_adapter import ParsedApk

TS = "2026-07-26T00:00:00Z"
P = "android.permission."


def _static(led):
    parsed = ParsedApk(
        package="com.evil",
        permissions=[P + "SYSTEM_ALERT_WINDOW", P + "BIND_ACCESSIBILITY_SERVICE",
                     P + "RECEIVE_SMS", P + "READ_SMS"],
    )
    return analyze_parsed(parsed, bundle=None, led=led, timestamp=TS)


def test_simulated_observations_labelled_and_scored():
    led = Ledger()
    static = _static(led)
    ml = MlResult(p_cal=0.9, label="malicious")
    dyn = interrogate(static, ml, led, TS)
    assert dyn.simulated is True
    assert dyn.observations
    assert all(o.startswith("[SIMULATED]") for o in dyn.observations)
    assert 0.0 <= dyn.b_dynamic <= 1.0
    assert any(n.type == "dynamic_obs" for n in led.nodes)


def test_benign_yields_no_high_risk_behaviour():
    led = Ledger()
    static = analyze_parsed(ParsedApk(package="com.good", permissions=[P + "INTERNET"]),
                            bundle=None, led=led, timestamp=TS)
    dyn = interrogate(static, MlResult(p_cal=0.1, label="benign"), led, TS)
    assert dyn.observations == []
    assert dyn.b_dynamic == 0.0
