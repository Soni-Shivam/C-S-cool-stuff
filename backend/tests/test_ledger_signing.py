from drishti.ledger import Ledger
from drishti.ledger.signing import generate_key, sign_ledger, verify_signature

TS = "2026-07-23T00:00:00Z"


def test_sign_and_verify_roundtrip():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    key = generate_key()
    sig = sign_ledger(led, key)
    assert verify_signature(led.head_hash, sig["signature"], sig["pubkey"]) is True


def test_verify_fails_on_wrong_hash():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    key = generate_key()
    sig = sign_ledger(led, key)
    assert verify_signature("f" * 64, sig["signature"], sig["pubkey"]) is False
