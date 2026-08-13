import argparse

import mlflow
from mlflow.genai.datasets import get_dataset

from drishti.evaluation import predict_evidence
from drishti.evaluation.scorers import ALL_SCORERS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--experiment", default="drishti-genai-evaluation")
    args = parser.parse_args()
    mlflow.set_experiment(args.experiment)
    dataset = get_dataset(name=args.dataset)
    result = mlflow.genai.evaluate(
        data=dataset,
        predict_fn=predict_evidence,
        scorers=ALL_SCORERS,
    )
    print(f"run_id={result.run_id}")
    for name, value in sorted(result.metrics.items()):
        print(f"{name}={value}")


if __name__ == "__main__":
    main()
