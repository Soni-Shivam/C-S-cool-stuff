import argparse

import mlflow
from mlflow import MlflowClient


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    args = parser.parse_args()
    experiment_id = MlflowClient().get_run(args.run_id).info.experiment_id
    traces = mlflow.search_traces(run_id=args.run_id, locations=[experiment_id])
    failures = []
    for _, row in traces.iterrows():
        failed = [
            assessment.get("assessment_name")
            for assessment in row.get("assessments", [])
            if assessment.get("feedback", {}).get("value") in (False, "no", 0)
        ]
        if failed:
            failures.append({"trace_id": row.get("trace_id"), "failed": failed})
    print(f"traces={len(traces)} failures={len(failures)}")
    for failure in failures:
        print(failure)


if __name__ == "__main__":
    main()
