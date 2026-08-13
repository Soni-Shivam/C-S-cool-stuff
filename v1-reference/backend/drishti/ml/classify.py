from pydantic import BaseModel, Field

from drishti.ml.features import extract_features
from drishti.ml.model import MalwareClassifier
from drishti.static.androguard_adapter import ParsedApk


class MlResult(BaseModel):
    p_cal: float
    label: str
    top_features: list[str] = Field(default_factory=list)


def classify(parsed: ParsedApk, clf: MalwareClassifier, led, timestamp: str) -> MlResult:
    feats = extract_features(parsed)
    p = clf.predict_proba(feats)
    label = "malicious" if p >= 0.5 else "benign"
    top = clf.top_features(feats)
    led.append(
        "ml_signal", "drishti.ml",
        f"Calibrated maliciousness P_cal={p:.3f} ({label})"
        + (f"; drivers: {', '.join(top)}" if top else ""),
        location="feature-vector", confidence=p, timestamp=timestamp,
    )
    return MlResult(p_cal=p, label=label, top_features=top)
