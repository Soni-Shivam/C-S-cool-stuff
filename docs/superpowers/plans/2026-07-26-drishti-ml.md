# DRISHTI M5 ML Classification Implementation Plan

**Goal:** Calibrated maliciousness probability `P_cal` from static features, trained
malware-file-free (from a features table), with a self-training baseline for offline demos.

**Architecture:** `features.py` (pure ParsedApk→fixed-order vector, shared by train & inference —
no skew) → `train.py` (HistGradientBoosting + Platt/sigmoid `CalibratedClassifierCV`; real path
`train_from_dataframe(csv)`, bootstrap `train_baseline` on a synthetic rule-consistent
distribution) → `model.py` (`MalwareClassifier`, joblib save/load) → `classify.py`
(`MlResult` + `ml_signal` ledger node). `scripts/androzoo_extract.py` runs in an isolated
environment to turn APK hashes into a features CSV, deleting each APK after extraction.

**Safety:** No raw malware on the training host. Static extraction never executes an APK.

## Tasks (TDD; all green — 59 tests)
1. `features.py` — DANGEROUS_PERMISSIONS one-hot + combo flags + counts + cert flag; stable
   `FEATURE_NAMES`; `extract_features`, `to_vector`. Tests: vector length, flag correctness.
2. `model.py` + `train.py` — calibrated classifier; `train_baseline`, `load_or_train_baseline`,
   `train_from_dataframe`. Tests: `P_cal∈[0,1]`, banker > benign, save/load roundtrip.
3. `classify.py` — `classify()` returns `MlResult`, appends `ml_signal` node. Test: node appended.
4. `scripts/androzoo_extract.py` — isolated extractor (download→features→delete APK→CSV).

## Notes
- XGBoost/LightGBM (paper) → sklearn HistGradientBoosting (same GBM family) to avoid the libomp
  native dependency; note the substitution in the paper.
- GNN / Sequence-Transformer / Opcode-CNN heads remain documented roadmap (paper Table 3).
- Baseline is synthetic and WILL misfire on edge cases (e.g., app stores like F-Droid that hold
  dropper-like permissions); replace with an AndroZoo-trained model via `train_from_dataframe`.
