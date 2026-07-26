"""M5 classifier wrapper: a calibrated gradient-boosted-trees model that maps a
feature dict to a calibrated maliciousness probability P_cal (paper §4.5)."""
from pathlib import Path

import joblib

from drishti.ml.features import FEATURE_NAMES, to_vector


class MalwareClassifier:
    def __init__(self, model, feature_names: list[str] | None = None):
        self.model = model
        self.feature_names = feature_names or list(FEATURE_NAMES)

    def predict_proba(self, feats: dict[str, float]) -> float:
        x = [to_vector(feats)]
        return float(self.model.predict_proba(x)[0][1])

    def top_features(self, feats: dict[str, float], k: int = 5) -> list[str]:
        """Report the active dangerous signals driving this sample (interpretable
        surface for the evidence ledger; not model-internal importances)."""
        active = [name for name in self.feature_names
                  if name.startswith(("perm_", "combo_")) and feats.get(name, 0.0) > 0]
        return active[:k]

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "feature_names": self.feature_names}, path)

    @classmethod
    def load(cls, path: str | Path) -> "MalwareClassifier":
        data = joblib.load(path)
        return cls(data["model"], data["feature_names"])
