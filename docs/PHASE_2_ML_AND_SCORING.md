# PHASE 2 — M5 ML CLASSIFICATION & M6 COMPOSITE SCORING

**Window:** H10 → H24 · **Owner:** Track A (Shivam)
**Depends on:** P1 T1.1–T1.5 (features come from `StaticReport`)
**Exit criteria:** a calibrated `P_cal` on unseen APKs with a reliability curve you
can defend, plus a pure-function scorer with 20 passing tests. `INTEGRATION-1` at
H24 shows upload → score in the UI.

> This phase is where the project earns its credibility with a technical judge.
> Anyone can prompt an LLM for a number. Almost nobody at a hackathon ships an
> isotonic-calibrated classifier with a reliability diagram and a deterministic
> fusion formula. **The calibration plot is a slide.** Budget 20 minutes to make it
> pretty.

---

## Part A — M5: ML classification

### T2.1 — Feature extractor (H10 → H12) · **do this before touching a dataset**

Risk R3 (train/inference feature skew) kills more hackathon ML than anything else.
The defence is structural: **one function, used by both paths.**

`drishti/m5_ml/features.py`:

```python
FEATURE_SCHEMA_VERSION = "1.0.0"

def extract(static: StaticReport) -> FeatureVector:
    """The ONLY feature extractor. Training calls it on StaticReports produced by
    running M2 over the corpus. Inference calls it on the live StaticReport.
    There is no second code path. Ever."""
```

Feature families (Drebin-style, all binary or small-count, ~1200 dims after
hashing):

| Family | Encoding | Count |
|---|---|---|
| Requested permissions | binary, fixed vocab of top-300 | 300 |
| Permission combos fired | binary, our 14 rules | 14 |
| Component counts | log1p(count) per kind, + exported ratio | 9 |
| Intent filter actions | binary, top-150 vocab | 150 |
| Sink hits | binary, our 18 sinks | 18 |
| Sink reachable-from-lifecycle | binary, our 18 sinks | 18 |
| Suspicious API strings | binary, top-200 vocab (`getDeviceId`, `sendTextMessage`, `DexClassLoader`, `getInstalledPackages`, `Cipher`, `Runtime.exec`, …) | 200 |
| URL/domain features | count, has_ip_literal, has_shortener, tld one-hot top-20 | 25 |
| Packing/obfuscation | entropy_mean, dex_count, obf_ratio, native_lib_count, asset_entropy_max | 8 |
| Certificate | age_days (bucketed), brand_mismatch, known_bad_reuse, debug_cert | 6 |
| Over-privilege | \|declared_not_used\|, \|used_not_declared\|, ratios | 4 |
| Manifest hygiene | min_sdk, target_sdk, allowBackup, usesCleartextTraffic, debuggable | 6 |

**Vocabulary pinning:** vocabularies are computed once on the training set and
frozen into `models/vocab_v1.json`. Inference loads that file. Never recompute a
vocab at inference. Assert `len(vector) == len(vocab)` on both paths.

`tests/contract/test_feature_parity.py`: run the extractor on the canary APK,
compare to `data/fixtures/features/canary.json` element-wise. Fails loudly if
anyone changes the extractor without regenerating the golden file. **This test is
the entire mitigation for R3.**

---

### T2.2 — Dataset assembly (H10 → H13, mostly waiting)

Started downloading in P0. Priorities:

| Source | Use | Notes |
|---|---|---|
| **Drebin** | 5,560 malware + 123k benign, as *feature files* | Feature strings map ~1:1 onto our families. Fast. But it's 2014 — say so. |
| **CICMalDroid 2020** | ~11k samples, 4 categories + benign | Modern-ish. Has APKs and pre-extracted CSVs |
| **MalwareBazaar** | Recent APKs, family-tagged | The 2024–25 samples that make the time-split honest |
| **AndroZoo** | Millions | Needs an API key by email — **request at H00**, assume it won't arrive |
| **Benign baseline** | Top free apps (APKPure/F-Droid) | Grab ~500. F-Droid is scriptable and licence-clean |

**Pragmatic decision tree — decide by H13, no later:**

- **Path A (best):** enough real APKs (≥3000, ≥30% malicious) → run M2 over all of
  them (parallel, ~8 workers, ~20s each → ~2h wall for 3000; start this at H12 in
  background), extract features via `features.extract`, train. **Fully coherent
  with inference.**
- **Path B (good):** only Drebin feature files → write an adapter mapping Drebin's
  `feature_type::value` lines into our schema. Covers ~60% of our families
  (permissions, intents, API calls, URLs); the rest are zero-filled at train time
  **and must also be zero-filled at inference** or you reintroduce skew. Implement
  as `FeatureMask` — an explicit list of families the model was trained on. Ugly
  but honest and safe.
- **Path C (fallback):** no usable dataset → ship a **transparent rule-based
  `P_cal` stub**: a logistic function over the permission-combo weights, plus a
  slide that says "the classifier is trained on Drebin in our full build; the demo
  runs the rule-based prior." Do **not** fake a trained model. A judge who asks
  "what was your test AUC?" and gets a fabricated number ends your day.

Record the chosen path in `STATUS.md` with a timestamp.

---

### T2.3 — Train the classifier (H13 → H16)

```python
# m5_ml/train.py
XGBClassifier(n_estimators=400, max_depth=6, learning_rate=0.06,
              subsample=0.85, colsample_bytree=0.7,
              scale_pos_weight=neg/pos, eval_metric="aucpr",
              early_stopping_rounds=40, tree_method="hist")
```

**Splitting — use a time split, not a random split.** Sort samples by
first-seen date (Drebin has it; MalwareBazaar has it; for CICMalDroid use the
dataset's stated collection window). Train on the older 80%, test on the newer 20%.
Report **both** random-split and time-split numbers. The gap between them is a real
finding and admitting it is more impressive than hiding it:

> *"Random-split PR-AUC is 0.97. Time-split PR-AUC drops to 0.86 — that gap is
> exactly the concept drift that motivates our behavioural and GenAI layers."*

That sentence turns a weakness into the argument for the rest of the architecture.
Put it on the eval slide.

**Multi-label head:** train `k` independent binary XGBoost models (one per label:
banker, spyware, dropper, sms_fraud, ransomware, adware, riskware) using
`OneVsRestClassifier` or just a loop. Sigmoid per label, **never softmax** — a
banking trojan genuinely is dropper AND spyware AND overlay simultaneously, and a
mutually-exclusive assignment would be factually wrong. If label metadata is thin,
derive weak labels from AV-vendor family strings in the dataset metadata
(`regex: banker|bank|anatsa|cerberus|hook` → banker) and **disclose the weak
labelling**.

If labels aren't available at all: ship binary maliciousness only and drive the
multi-label panel from the GenAI behaviour checklist instead. Note the substitution
in the UI ("behaviour labels: GenAI-derived").

---

### T2.4 — Calibration (H16 → H17) · small, cheap, disproportionately valuable

```python
from sklearn.calibration import CalibratedClassifierCV
cal = CalibratedClassifierCV(base_model, method="isotonic", cv="prefit")
cal.fit(X_calib, y_calib)      # held-out third split, NOT train, NOT test
```

Three-way split: train / calib / test. Using the test set for calibration is a
subtle leak that a good judge will catch.

Produce and save:
1. `models/calibrator_v1.pkl`
2. **`docs/reliability_curve.png`** — predicted probability vs. observed frequency,
   10 bins, before and after calibration, on the same axes. This plot is the visual
   proof of the P2 design principle from the paper.
3. Brier score before/after in `STATUS.md`.

Assert in a test: after calibration, for the bin `[0.75, 0.85]`, empirical positive
rate is within ±0.10 of 0.80 on the test set. If it isn't, isotonic overfit the
calib split — fall back to Platt (`method="sigmoid"`), which is more robust on
small calibration sets.

---

### T2.5 — Anomaly detector (H17 → H18) · cut-listed, keep if smooth

`IsolationForest(n_estimators=200, contamination=0.05)` fit on **benign only**.
Output → `anomaly_score = normalised decision_function`.

Its role is architectural, not numeric: it is an **escalator, not an additive
term**. `anomaly_score > 0.85` sets `anomaly_escalate=True`, which bumps the band
to at least HIGH and forces `requires_human_review`, regardless of `P_cal`. This is
the zero-day story — a novel family that the classifier has never seen must not land
quietly in LOW.

Test: `test_anomaly_escalates_band` — a synthetic input with low `P_cal` and high
anomaly yields band ≥ HIGH.

---

### T2.6 — SHAP explanations (H18 → H19)

`shap.TreeExplainer(model)` → top-10 features per prediction, signed. Emit as
`ML_PREDICTION` ledger node content. Render in the UI as a horizontal bar chart
with human-readable feature names (`perm:RECEIVE_SMS`, not `f_0142`) — build a
`FEATURE_LABELS` map alongside the vocab.

This closes an explainability loop that the paper claims and most implementations
skip. It's 40 minutes for a visibly better demo.

---

## Part B — M6: Composite scoring engine

### T2.7 — The scorer (H19 → H22) · **pure function, most-tested file in the repo**

`drishti/m6_score/engine.py`. No I/O. No LLM. No `datetime.now()`. No randomness.

```python
def score(*, static: StaticReport | None,
             ml: MLPrediction | None,
             genai: GenAIVerdict | None,
             dynamic: DynamicTrace | None,
             intel: ThreatIntel | None,
             ledger: LedgerStore) -> CompositeScore:
```

#### The four terms

**R — reputation / threat intel (w=0.25)**
```
known_bad_hash exact match          → 1.0   (also triggers override)
fuzzy/dexofuzzy match ≥0.85 to known-bad → 0.8
signing cert seen in known-bad set  → 0.7
C2 domain on URLhaus                → 0.6
no intel available                  → 0.0   ← and γ drops; absence ≠ innocence
```
Guard against the classic error: a clean VT result must not *reduce* the score.
`R` is a floor-raiser only. Document this in a code comment; a judge may probe it.

**F_AI — fused ML + GenAI behaviour (w=0.50)**
```
F_AI = P_cal + B − (P_cal · B)
```
Noisy-OR. Two partially-correlated detectors both saying 0.7 should give ~0.91, not
1.4 clipped to 1.0. If either is missing, `F_AI` = the other one alone, and γ drops.

**G — signature severity (w=0.15)**
Max severity over YARA rules that matched, from a curated ruleset in
`data/kb/yara/` (grab community Android rules from the YARA-Rules repo and
MalwareBazaar, ~30 rules). Map rule metadata `severity: critical|high|medium` →
`1.0 | 0.7 | 0.4`. No match → 0.0.

**D — static↔dynamic drift (w=0.10)**
```
D = clamp( 0.4·(used_not_declared_static > 0)
         + 0.4·(runtime_apis_not_predicted_by_static > threshold)
         + 0.2·(dex_loaded_at_runtime_not_in_apk) , 0, 1)
```
This term is what dynamic-code-loading trips. Before Phase 4 lands, only the static
half contributes — that's correct, and γ reflects the missing evidence.

#### Composition
```python
S_raw = 0.25*R + 0.50*F_AI + 0.15*G + 0.10*D
S = int(round(100 * min(1.0, S_raw)))
if intel.known_bad_hash: S, C, override = 100, 1.0, "known_bad_hash"
```

#### Confidence
```python
γ = 0.4*has_static + 0.3*(dynamic and dynamic.detonated) + 0.2*has_ml + 0.1*has_intel
C = γ * (1 - abs(P_cal - B))          # if either missing: C = γ * 0.5
if genai.disagreement_flag: C *= 0.6; requires_human_review = True
if ml.anomaly_escalate:     band = max(band, HIGH); requires_human_review = True
```

Note the deliberate asymmetry, and put it in the UI copy: **AI disagreement lowers
confidence, it never moves the score.** A sample that scores 90 with C=0.4 because
it refused to detonate is surfaced honestly rather than quietly downgraded. That
honesty is the paper's P2 principle made executable.

#### Every factor writes a ledger node
```python
for f in factors:
    ledger.append(type=SCORE_FACTOR, source_tool="scorer",
                  content=f.model_dump(), parents=f.evidence_refs, confidence=1.0)
```
`f.evidence_refs` = the nodes that produced the inputs. **This is the mechanism
behind "every score point traces back to an artefact"** — without it, the claim is
marketing. With it, the UI can render: click `F_AI 41.5` → see `P_cal 0.71` → see
the SHAP features → see the `PERMISSION_COMBO` node → see `AndroidManifest.xml#L42`.

Rehearse that click-path. It is the strongest 20 seconds of the demo.

#### Explanation string — template, not LLM
```python
"Score {S} ({band}). Driven by fused AI intelligence ({F_AI:.2f}, contributing
{c:.1f} points): the classifier assigns {P_cal:.0%} malicious probability and
behavioural analysis observed {top_behaviour}. {intel_clause} {drift_clause}
Confidence {C:.2f} — {confidence_reason}."
```
Deterministic, fast, never hallucinates, always available even if the LLM is down.

### T2.8 — Bands and proposed actions (H22 → H23)

```python
CRITICAL 85–100 → [block, push_ioc, notify_customers]
HIGH     65–84  → [quarantine, fast_track_analyst]
MEDIUM   40–64  → [analyst_review, monitor]
LOW      0–39   → [log]
```
Every `ProposedAction` has `requires_confirmation=True`. The API endpoint
`POST /api/jobs/{id}/actions/{action}/confirm` writes an `ANALYST_ACTION` ledger
node with the confirming user. **Nothing executes without it.** Demo this — click
"Block" → modal → confirm → ledger node appears. It takes 15 seconds and it answers
the responsible-AI question before a judge asks it.

### T2.9 — Scorer test suite (H22 → H24) · 20 tests, non-negotiable

1. `test_deterministic` — identical inputs 100× → identical output
2. `test_bounds` — 10,000 randomised inputs (seeded) → S∈[0,100], C∈[0,1]
3. `test_band_boundaries` — S=39/40, 64/65, 84/85 map correctly
4. `test_noisy_or` — P=0.7,B=0.7 → F_AI≈0.91
5. `test_missing_dynamic` — γ ≤ 0.7, no crash
6. `test_missing_everything` — all None → S=0, C=0, no exception
7. `test_known_bad_override` — S=100, C=1.0, override recorded
8. `test_clean_vt_does_not_reduce` — R=0 with high P_cal still scores high
9. `test_anomaly_escalates_band`
10. `test_disagreement_lowers_C_not_S`
11. `test_every_factor_has_ledger_refs`
12. `test_explanation_mentions_top_factor`
13–20. per-term monotonicity: increasing any single input never decreases S
    (property test — catches sign errors instantly)

Monotonicity is worth the effort: it's a one-line property that catches an entire
class of formula bugs, and "our scorer is provably monotone in each signal" is a
good sentence to have available.

---

## ★ INTEGRATION-1 — H24, hard 90-minute stop, all three tracks

Run together, in one room, on one machine:

```bash
make demo && open http://localhost:5173
# upload data/samples/known_banker.apk
```

**Must pass:**
- [ ] Job completes through `SCORE_PRELIM` in < 3 minutes
- [ ] UI shows score, band, confidence, and all four factor bars
- [ ] Clicking `F_AI` expands to `P_cal` + SHAP features
- [ ] Ledger tab lists ≥50 nodes; `verify_chain()` green
- [ ] Clicking any ledger node shows raw content
- [ ] Nothing 500s; a corrupt upload returns a clean error

**Then, together, agree in writing:** what is cut, what is at risk, whether P4 goes
live or replay. Write it in `STATUS.md`. Then everyone sleeps in a staggered
rotation — Track C sleeps last since P4 starts now.

---

## Phase 2 Definition of Done

- [ ] Single shared feature extractor; parity test green
- [ ] Dataset path (A/B/C) chosen and recorded with justification
- [ ] XGBoost trained; random-split AND time-split metrics recorded
- [ ] Isotonic calibration + reliability curve PNG committed
- [ ] Multi-label head (or documented GenAI substitution)
- [ ] IsolationForest escalator wired to band bump
- [ ] SHAP top-10 in ledger and UI
- [ ] Scorer is a pure function with 20 green tests incl. monotonicity
- [ ] Every score factor emits a ledger node with real parents
- [ ] Proposed actions require human confirmation; endpoint works
- [ ] INTEGRATION-1 checklist fully green
- [ ] `git tag p2-done`
