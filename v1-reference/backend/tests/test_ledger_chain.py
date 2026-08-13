import hashlib

from drishti.ledger import Ledger

TS = "2026-07-23T00:00:00Z"


def test_first_node_links_to_genesis():
    led = Ledger()
    n = led.append("manifest", "androguard", "perm X", timestamp=TS)
    assert n.id == "n1"
    assert n.prev_hash == "0" * 64
    assert n.hash != ""


def test_hash_is_sha256_of_prevhash_plus_payload():
    led = Ledger()
    n = led.append("ioc", "static", "hxxp://evil", timestamp=TS)
    expected = hashlib.sha256((("0" * 64) + n.canonical_payload()).encode()).hexdigest()
    assert n.hash == expected


def test_chain_links_sequentially():
    led = Ledger()
    a = led.append("manifest", "androguard", "a", timestamp=TS)
    b = led.append("cert", "androguard", "b", timestamp=TS)
    assert b.prev_hash == a.hash
    assert led.head_hash == b.hash
    assert [x.id for x in led.nodes] == ["n1", "n2"]
