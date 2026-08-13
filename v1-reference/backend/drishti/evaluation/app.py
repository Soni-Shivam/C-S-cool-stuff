from drishti.genai.reason import SYSTEM_PROMPT, VERDICT_SCHEMA, _wrap_user_data
from drishti.llm import get_provider
from drishti.observability import safe_span, sanitize_evidence, set_safe_outputs


def predict_evidence(evidence: dict, provider=None) -> dict:
    """MLflow predict_fn: structured evidence only; never accepts an APK or bytes."""
    provider = provider or get_provider()
    with safe_span(
        "drishti.m4.evaluation",
        span_type="CHAIN",
        inputs={"evidence": sanitize_evidence(evidence), "provider": provider.name},
    ) as span:
        result = provider.generate_json(SYSTEM_PROMPT, _wrap_user_data(evidence), VERDICT_SCHEMA)
        set_safe_outputs(span, {
            "behavioral_risk": result.get("behavioral_risk"),
            "evidence_refs": list(result.get("evidence_refs", []))[:500],
            "techniques": list(result.get("attack_techniques", []))[:100],
        })
        return result
