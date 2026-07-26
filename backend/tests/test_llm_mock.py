from types import SimpleNamespace

from drishti.llm import MockProvider, get_provider


def test_get_provider_returns_mock_without_key():
    settings = SimpleNamespace(gemini_api_key=None, gemini_model=None)
    assert isinstance(get_provider(settings), MockProvider)


def test_get_provider_returns_gemini_with_key():
    settings = SimpleNamespace(gemini_api_key="k", gemini_model="gemini-3.1-pro-preview")
    p = get_provider(settings)
    assert p.name == "gemini"
    assert p.live is True


def test_mock_reads_embedded_evidence():
    mp = MockProvider()
    user = ('junk <<EVIDENCE_JSON>>{"permission_combos": [{"id":"x","mitre":["T1417"]}], '
            '"p_cal": 0.9, "evidence_node_ids": ["n1","n2"]}<<END_EVIDENCE_JSON>>')
    out = mp.generate_json("sys", user, {})
    assert out["behavioral_risk"] > 0
    assert out["attack_techniques"] == ["T1417"]
    assert out["evidence_refs"] == ["n1", "n2"]
