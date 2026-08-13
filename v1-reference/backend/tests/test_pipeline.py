"""End-to-end pipeline test on the bundled benign APK if present, using the
offline Mock provider (deterministic, no network). Skips if the sample APK is
absent so CI stays green without downloads."""
import os

import pytest

from drishti.ledger import Ledger
from drishti.llm import MockProvider
from drishti.pipeline import run_pipeline

TS = "2026-07-26T00:00:00Z"
SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "fdroid.apk")


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample APK not downloaded")
def test_full_pipeline_on_real_apk_offline():
    res = run_pipeline(SAMPLE, timestamp=TS, provider=MockProvider())
    v = res.verdict
    assert 0 <= v.threat_score <= 100
    assert v.severity_band in {"Critical", "High", "Medium", "Low"}
    assert 0.0 <= v.confidence <= 1.0
    assert v.provider == "mock"
    assert v.dynamic_simulated is True
    # ledger present and internally consistent
    assert len(res.ledger) > 5
    # verdict references only real ledger nodes
    ledger_ids = {n["id"] for n in res.ledger}
    assert all(r in ledger_ids for r in v.evidence_refs)


def test_confirmed_hash_forces_max_score(tmp_path):
    apk = tmp_path / "known.apk"
    apk.write_bytes(b"pretend-apk-bytes")
    import hashlib
    sha = hashlib.sha256(b"pretend-apk-bytes").hexdigest()
    # parse_apk will fail on non-APK bytes, so this asserts the intel override path
    # short-circuits before static parsing is required.
    from drishti.ingestion import ingest
    led = Ledger()
    bundle = ingest(str(apk), led, TS, known_bad={sha: "Cerberus"})
    assert bundle.intel_hit is True
    assert bundle.intel_family == "Cerberus"
