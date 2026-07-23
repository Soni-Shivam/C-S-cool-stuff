from drishti.ledger import Ledger

TS = "2026-07-23T00:00:00Z"


def test_valid_chain_verifies():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    led.append("cert", "androguard", "b", timestamp=TS)
    assert led.verify_chain() is True


def test_tampered_content_fails_verification():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    led.append("cert", "androguard", "b", timestamp=TS)
    led._nodes[0].content = "TAMPERED"  # tamper internal node
    assert led.verify_chain() is False


def test_empty_ledger_verifies():
    assert Ledger().verify_chain() is True
