import argparse

import mlflow

from drishti.evaluation.judges import registered_judges


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", default="drishti-genai-evaluation")
    parser.add_argument("--judge-model", default=None, help="Optional provider:/model URI")
    args = parser.parse_args()
    experiment = mlflow.set_experiment(args.experiment)
    for item in registered_judges(args.judge_model):
        registered = item.register(experiment_id=experiment.experiment_id)
        print(f"registered {registered.name}")


if __name__ == "__main__":
    main()
