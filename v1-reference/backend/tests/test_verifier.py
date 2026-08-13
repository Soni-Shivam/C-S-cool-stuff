from drishti.ledger import Ledger
from drishti.ledger.verifier import filter_verified_claims, verify_claim

TS = "2026-07-23T00:00:00Z"


def _ledger():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)  # n1
    led.append("api_sink", "androguard", "b", timestamp=TS)  # n2
    return led


def test_claim_with_existing_refs_passes():
    led = _ledger()
    assert verify_claim(["n1", "n2"], led) is True


def test_claim_with_missing_ref_rejected():
    led = _ledger()
    assert verify_claim(["n1", "n99"], led) is False


def test_claim_with_no_refs_rejected():
    led = _ledger()
    assert verify_claim([], led) is False


def test_filter_drops_unverified_claims():
    led = _ledger()
    claims = [
        {"text": "grounded", "evidence_refs": ["n1"]},
        {"text": "hallucinated", "evidence_refs": ["n42"]},
    ]
    kept = filter_verified_claims(claims, led)
    assert [c["text"] for c in kept] == ["grounded"]
