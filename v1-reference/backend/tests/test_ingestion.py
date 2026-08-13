import hashlib

from drishti.ingestion import ingest, sha256_file
from drishti.ingestion.reputation import R_UNKNOWN, ReputationFeed
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
    # Ingest + a reputation node. The reputation node is appended even when no feed
    # recognises the file, because "unknown to every feed" is itself auditable evidence
    # that a zero-day claim must be able to cite.
    assert [n.type for n in led.nodes] == ["ingest", "intel"]


def test_unknown_sample_gets_reputation_floor_not_zero(tmp_path):
    """Absence of detections must never be treated as evidence of benignity."""
    f = tmp_path / "x.apk"
    f.write_bytes(b"novel-zero-day")
    led = Ledger()
    bundle = ingest(f, led, TS, known_bad={})
    assert bundle.reputation_r == R_UNKNOWN > 0.0
    assert bundle.reputation_detections is None
    assert bundle.reputation_verdict == "unknown"


def test_graded_reputation_raises_r_for_strong_consensus(tmp_path):
    f = tmp_path / "x.apk"
    f.write_bytes(b"known-bad-bytes")
    sha = hashlib.sha256(b"known-bad-bytes").hexdigest()
    feed = ReputationFeed({sha: {"detections": 39, "family": "banker"}},
                          source="test-feed", label_derived=False)
    led = Ledger()
    bundle = ingest(f, led, TS, known_bad={}, reputation_feed=feed)
    assert bundle.reputation_r == 1.0
    assert bundle.reputation_verdict == "confirmed_bad"
    assert bundle.reputation_detections == 39


def test_label_derived_feed_is_suppressed_during_labelled_evaluation(tmp_path):
    """A feed that also produced our labels must not leak them into the R term."""
    f = tmp_path / "x.apk"
    f.write_bytes(b"corpus-sample")
    sha = hashlib.sha256(b"corpus-sample").hexdigest()
    feed = ReputationFeed({sha: {"detections": 39, "family": None}},
                          source="androzoo-vt-offline", label_derived=True)
    led = Ledger()
    suppressed = ingest(f, led, TS, known_bad={}, reputation_feed=feed)
    assert suppressed.reputation_r == R_UNKNOWN
    assert suppressed.reputation_detections is None
    # Production lookups against a live feed opt in explicitly.
    allowed = ingest(f, Ledger(), TS, known_bad={}, reputation_feed=feed,
                     allow_label_derived_reputation=True)
    assert allowed.reputation_r == 1.0
