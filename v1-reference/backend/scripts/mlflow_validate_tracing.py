import argparse

import mlflow

from drishti.evaluation import predict_evidence
from drishti.llm import MockProvider


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", default="drishti-genai-evaluation")
    args = parser.parse_args()
    experiment = mlflow.set_experiment(args.experiment)
    predict_evidence({
        "package": "org.demo.safe",
        "sha256": "0" * 64,
        "permission_combos": [],
        "p_cal": 0.05,
        "ml_top_features": [],
        "iocs": {},
        "certificate": {},
        "yara_hits": [],
        "dynamic_evidence": {"status": "absent", "observations": []},
        "evidence_node_ids": ["n1"],
    }, provider=MockProvider())
    traces = mlflow.search_traces(experiment_ids=[experiment.experiment_id])
    if len(traces) == 0:
        raise SystemExit("No traces found")
    serialized = traces.to_json().lower()
    if "apk bytes" in serialized or "gemini_api_key" in serialized:
        raise SystemExit("Sensitive trace content detected")
    print(f"tracing verified: {len(traces)} trace(s) found")


if __name__ == "__main__":
    main()
