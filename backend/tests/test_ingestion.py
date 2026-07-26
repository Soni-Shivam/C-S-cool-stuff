import hashlib

from drishti.ingestion import ingest, sha256_file
from drishti.ledger import Ledger

TS = "2026-07-26T00:00:00Z"


def test_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "x.apk"
    f.write_bytes(b"hello")
    assert sha256_file(f) == hashlib.sha256(b"hello").hexdigest()


def test_ingest_detects_intel_and_appends_nodes(tmp_path):
    f = tmp_path / "x.apk"
    f.write_bytes(b"malware-bytes")
    sha = hashlib.sha256(b"malware-bytes").hexdigest()
    led = Ledger()
    bundle = ingest(f, led, TS, known_bad={sha: "Cerberus"})
    assert bundle.sha256 == sha
    assert bundle.intel_hit is True
    assert bundle.intel_family == "Cerberus"
    assert led.nodes[0].type == "ingest"
    assert any(n.type == "intel" for n in led.nodes)


def test_ingest_clean_sample(tmp_path):
    f = tmp_path / "x.apk"
    f.write_bytes(b"clean-bytes")
    led = Ledger()
    bundle = ingest(f, led, TS, known_bad={})
    assert bundle.intel_hit is False
    assert bundle.intel_family is None
    assert len(led.nodes) == 1
