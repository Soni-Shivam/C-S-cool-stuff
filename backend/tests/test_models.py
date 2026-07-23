from drishti.models import EvidenceNode


def test_canonical_payload_excludes_hash_and_is_deterministic():
    n = EvidenceNode(
        id="n1", type="manifest", source_tool="androguard",
        content="RECEIVE_SMS declared", location="manifest#L42",
        confidence=0.9, timestamp="2026-07-23T00:00:00Z",
        refs=[], prev_hash="0" * 64, hash="SHOULD_NOT_APPEAR",
    )
    payload = n.canonical_payload()
    assert "SHOULD_NOT_APPEAR" not in payload
    assert '"id":"n1"' in payload.replace(" ", "")
    # deterministic: same object -> same payload
    assert payload == n.canonical_payload()


def test_defaults():
    n = EvidenceNode(id="n1", type="ioc", source_tool="static",
                     content="hxxp://evil", timestamp="2026-07-23T00:00:00Z")
    assert n.confidence == 1.0
    assert n.refs == []
    assert n.location is None
