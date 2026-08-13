"""Process-worker entry point. It parses APKs but never executes them."""
from datetime import datetime, timezone
from pathlib import Path

from drishti.config import Settings
from drishti.ingestion import sha256_file
from drishti.llm import get_provider
from drishti.ml import MalwareClassifier, train_baseline
from drishti.pipeline import run_pipeline
from drishti.reporting import build_android_report


def analyze_quarantined(
    apk_path: str,
    analysis_id: str,
    worker_config: dict,
) -> dict:
    settings = Settings(**worker_config)
    provider = get_provider(settings)
    if settings.trained_model_path:
        model_path = Path(settings.trained_model_path)
        if not model_path.is_file():
            raise ValueError("configured trained model path does not exist")
        classifier = MalwareClassifier.load(model_path)
    else:
        # Local-demo fallback is trained in memory and never committed as a binary.
        classifier = train_baseline(n=800)

    sha256 = sha256_file(apk_path)
    observations_path = Path(settings.observations_dir) / f"{sha256}.json"
    dynamic_mode = "observed" if observations_path.is_file() else "absent"
    observations = str(observations_path) if observations_path.is_file() else None
    result = run_pipeline(
        apk_path,
        timestamp=datetime.now(timezone.utc).isoformat(),
        provider=provider,
        classifier=classifier,
        dynamic_mode=dynamic_mode,
        observations=observations,
    )
    report = build_android_report(
        result,
        analysis_id=analysis_id,
        ml_model_version=settings.ml_model_version,
        gemini_live=provider.live,
    )
    return {"sha256": sha256, "report": report.model_dump(mode="json")}
