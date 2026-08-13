from drishti.reporting import build_android_report

from tests.test_pipeline_provenance import _run, pipeline_input  # noqa: F401


def test_report_is_android_friendly_and_conservative(pipeline_input):
    result = _run(pipeline_input, "simulated")
    report = build_android_report(result, analysis_id="a1", gemini_live=False)
    assert report.provenance.dynamic_status == "simulated"
    assert report.provenance.gemini_status == "mock"
    assert "was not observed" in report.provenance.notice
    assert report.suspicious_capabilities
    assert report.potential_consequences
    assert all("could" in item.text.lower() for item in report.potential_consequences)
    ids = {item.id for item in report.evidence}
    for statement in [report.genai_summary, *report.potential_consequences, *report.mitre_mobile_techniques]:
        assert set(statement.evidence_refs) <= ids


def test_report_omits_unsupported_genai_summary(pipeline_input):
    result = _run(pipeline_input, "absent")
    result.verdict.verified = False
    result.verdict.summary = "The app stole every password"
    result.verdict.evidence_refs = ["n999"]
    report = build_android_report(result, analysis_id="a2")
    assert "stole every password" not in report.genai_summary.text
    assert report.genai_summary.evidence_refs == []
