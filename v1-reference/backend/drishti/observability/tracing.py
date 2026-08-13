from contextlib import contextmanager
from typing import Any, Iterator


def sanitize_evidence(evidence: dict) -> dict:
    """Keep structured security signals while excluding APK bytes and secrets."""
    return {
        "package": str(evidence.get("package", ""))[:200],
        "sha256": str(evidence.get("sha256", ""))[:64],
        "permission_combos": list(evidence.get("permission_combos", []))[:30],
        "p_cal": float(evidence.get("p_cal", 0.0)),
        "ml_top_features": list(evidence.get("ml_top_features", []))[:20],
        "iocs": {
            key: len(values) for key, values in (evidence.get("iocs", {}) or {}).items()
        },
        "certificate_flags": {
            key: value for key, value in (evidence.get("certificate", {}) or {}).items()
            if key in {"self_signed", "brand_mismatch"}
        },
        "yara_hits": list(evidence.get("yara_hits", []))[:20],
        "dynamic_evidence": {
            "status": (evidence.get("dynamic_evidence", {}) or {}).get("status", "absent"),
            "observation_count": len(
                (evidence.get("dynamic_evidence", {}) or {}).get("observations", [])
            ),
        },
        "evidence_node_ids": list(evidence.get("evidence_node_ids", []))[:500],
    }


@contextmanager
def safe_span(name: str, *, span_type: str, inputs: dict) -> Iterator[Any]:
    """Create an MLflow span with explicit sanitized I/O, or no-op if unavailable."""
    try:
        import mlflow
    except ImportError:
        yield None
        return
    with mlflow.start_span(name=name, span_type=span_type) as span:
        span.set_inputs(inputs)
        yield span


def set_safe_outputs(span: Any, outputs: dict) -> None:
    if span is not None:
        span.set_outputs(outputs)
