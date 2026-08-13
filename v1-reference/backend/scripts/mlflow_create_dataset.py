import argparse
import json
from pathlib import Path

import mlflow
from mlflow.genai.datasets import create_dataset, search_datasets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--experiment", default="drishti-genai-evaluation")
    parser.add_argument("--records", type=Path, default=Path("evaluation/seed_cases.json"))
    args = parser.parse_args()

    experiment = mlflow.set_experiment(args.experiment)
    existing = search_datasets(
        experiment_ids=[experiment.experiment_id],
        filter_string=f"name = '{args.name}'",
        max_results=10,
    )
    dataset = existing[0] if existing else create_dataset(
        name=args.name,
        experiment_id=experiment.experiment_id,
        tags={"contains_apks": "false", "data_class": "sanitized-structured-evidence"},
    )
    records = json.loads(args.records.read_text())
    dataset.merge_records(records)
    print(f"dataset={dataset.name} id={dataset.dataset_id} records_merged={len(records)}")


if __name__ == "__main__":
    main()
