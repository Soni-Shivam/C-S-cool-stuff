"""M5 training. Two paths, both malware-file-free on the training host:

* `train_from_dataframe` — the real path: trains on a FEATURES TABLE (CSV/parquet)
  whose rows are numeric feature vectors + a label. The raw APKs are never needed
  here; extract features in an isolated environment (see scripts/androzoo_extract.py).
* `train_baseline` — a bootstrap model trained on a synthetic, rule-consistent
  feature distribution so the prototype produces a calibrated P_cal out of the box.
  Clearly a placeholder; replace with an AndroZoo-trained model for real numbers.
"""
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier

from drishti.ml.features import DANGEROUS_PERMISSIONS, FEATURE_NAMES, to_vector
from drishti.ml.model import MalwareClassifier
from drishti.static.rules import detect_permission_combos

_DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "data" / "models" / "baseline.joblib"
_P = "android.permission."


def _sample_feature_dict(rng: np.random.Generator, malicious: bool) -> dict[str, float]:
    perms: set[str] = {"INTERNET"}
    if malicious:
        # banking-trojan signal, injected with high probability
        if rng.random() < 0.75:
            perms |= {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"}
        if rng.random() < 0.7:
            perms |= {"RECEIVE_SMS", "READ_SMS"}
        for p in DANGEROUS_PERMISSIONS:
            if rng.random() < 0.45:
                perms.add(p)
    else:
        for p in ["READ_EXTERNAL_STORAGE", "READ_PHONE_STATE", "GET_ACCOUNTS", "CAMERA"]:
            if rng.random() < 0.2:
                perms.add(p)

    combos = {c.id for c in detect_permission_combos({_P + p for p in perms})}
    feats: dict[str, float] = {}
    for p in DANGEROUS_PERMISSIONS:
        feats[f"perm_{p}"] = 1.0 if p in perms else 0.0
    for name in FEATURE_NAMES:
        if name.startswith("combo_"):
            feats[name] = 1.0 if name[len("combo_"):] in combos else 0.0
    base_perm_n = len(perms)
    feats["num_permissions"] = float(base_perm_n + rng.integers(0, 6))
    feats["num_activities"] = float(rng.integers(1, 40))
    feats["num_services"] = float(rng.integers(0, 15))
    feats["num_receivers"] = float(rng.integers(0, 12))
    feats["num_providers"] = float(rng.integers(0, 5))
    feats["num_exported"] = float(rng.integers(0, 12))
    feats["num_strings"] = float(rng.integers(500, 20000))
    feats["num_urls"] = float(rng.integers(3, 40) if malicious else rng.integers(0, 15))
    feats["num_ips"] = float(rng.integers(0, 6) if malicious else rng.integers(0, 2))
    feats["num_crypto"] = float(rng.integers(0, 3) if malicious else 0)
    feats["cert_self_signed"] = 1.0
    return feats


def _synth_dataset(n: int, seed: int):
    rng = np.random.default_rng(seed)
    X, y = [], []
    for i in range(n):
        malicious = i % 2 == 0
        feats = _sample_feature_dict(rng, malicious)
        label = int(malicious)
        if rng.random() < 0.05:  # small label noise -> calibration is meaningful
            label = 1 - label
        X.append(to_vector(feats))
        y.append(label)
    return np.array(X), np.array(y)


def _fit_calibrated(X, y):
    base = HistGradientBoostingClassifier(max_depth=4, learning_rate=0.1,
                                          max_iter=150, random_state=0)
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=5)
    clf.fit(X, y)
    return clf


def train_baseline(seed: int = 42, n: int = 3000) -> MalwareClassifier:
    X, y = _synth_dataset(n, seed)
    return MalwareClassifier(_fit_calibrated(X, y))


def load_or_train_baseline(path: str | Path = _DEFAULT_MODEL_PATH) -> MalwareClassifier:
    path = Path(path)
    if path.exists():
        return MalwareClassifier.load(path)
    clf = train_baseline()
    clf.save(path)
    return clf


def train_from_dataframe(df, label_col: str = "label") -> MalwareClassifier:
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"features table missing columns: {missing[:5]}...")
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df[label_col].to_numpy(dtype=int)
    return MalwareClassifier(_fit_calibrated(X, y))
