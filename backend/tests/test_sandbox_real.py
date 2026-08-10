"""Real-detonation ingestion: converts observations.json from the sealed VM into
measured evidence nodes. No execution here — this only parses a JSON artefact."""
import json

from drishti.ledger import Ledger
from drishti.sandbox import ingest_real, load_real_observations, result_from_payload

TS = "2026-08-03T00:00:00Z"

PAYLOAD = {
    "package": "com.evil.fakebank",
    "simulated": False,
    "mitre_observed": ["T1407", "T1582"],
    "observations": [
        {"type": "observation", "technique": "SMS body read (OTP interception surface)",
         "mitre": "T1582", "detail": "Your OTP is 448122"},
        {"type": "observation", "technique": "Dynamic code loaded via DexClassLoader",
         "mitre": "T1407", "detail": "/data/data/com.evil.fakebank/files/payload.dex"},
    ],
}


def test_real_observations_are_labelled_observed_not_simulated():
    res = result_from_payload(PAYLOAD)
    assert res.simulated is False
    assert all(o.startswith("[OBSERVED]") for o in res.observations)
    assert "T1582" in res.mitre_observed


def test_b_dynamic_reflects_highest_severity_behaviour():
    res = result_from_payload(PAYLOAD)
    # T1582 (0.95) is the strongest, +0.05 corroboration from a second distinct severity
    assert 0.95 <= res.b_dynamic <= 1.0


def test_ingest_real_appends_evidence_nodes():
    led = Ledger()
    res = ingest_real(PAYLOAD, led, TS)
    nodes = [n for n in led.nodes if n.type == "dynamic_obs"]
    assert len(nodes) == 2
    assert all(n.source_tool == "sandbox_real" for n in nodes)
    assert led.verify_chain() is True
    assert res.simulated is False


def test_clean_sample_records_no_behaviour():
    led = Ledger()
    res = ingest_real({"package": "com.good.app", "observations": []}, led, TS)
    assert res.b_dynamic == 0.0
    assert len(led.nodes) == 1
    assert "no high-risk runtime behaviour" in led.nodes[0].content


def test_load_from_file(tmp_path):
    p = tmp_path / "observations.json"
    p.write_text(json.dumps(PAYLOAD))
    res = load_real_observations(p)
    assert res.simulated is False
    assert len(res.observations) == 2
