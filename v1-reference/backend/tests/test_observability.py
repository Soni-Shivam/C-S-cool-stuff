from drishti.observability import sanitize_evidence


def test_trace_sanitizer_drops_ioc_values_and_dynamic_details():
    safe = sanitize_evidence({
        "package": "demo", "sha256": "a" * 64, "permission_combos": [], "p_cal": .2,
        "iocs": {"urls": ["https://sensitive.invalid/path"]},
        "certificate": {"subject": "private", "self_signed": True},
        "dynamic_evidence": {"status": "observed", "observations": ["secret detail"]},
    })
    rendered = str(safe)
    assert "sensitive.invalid" not in rendered
    assert "secret detail" not in rendered
    assert "private" not in rendered
    assert safe["iocs"]["urls"] == 1
    assert safe["dynamic_evidence"]["observation_count"] == 1
