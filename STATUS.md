# DRISHTI — STATUS

**This file is the current state of the world.** Read it first, every session.
Update it after **every** task: task → DONE, hour, commit sha, test count.
Protocol: `docs/00_GUIDING_MAP.md` §13.

- **Started:** 2026-08-13 · **Last reconciled:** 2026-08-26
- **Integration branch:** `main` · **v1 record:** branch `v1` + tag `v1-final`
- **Phase:** 24-hour demo build · corpus extracting, M7 exports landed, live LLM verified; detonation and trained model still unproven
- **Tests:** **594 contract+unit + 15 e2e, all passing** (measured 2026-08-26 at `8c5d3ec`)
- **Build design:** `docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md`
- **Narrative log:** see `PROGRESS.md`

---

## Verified environment facts

Re-established by inspection on **2026-08-17**. Every row was checked with a command.
The 2026-08-13 version of this table asserted GCP resources that no longer exist.

| Item | State |
|---|---|
| GCP (v1, legacy `drishti-m3-08130038`) | **GONE.** Absent from `gcloud projects list`; `describe` returns permission-denied/absent. The four `v1-rescue-*` boot-disk snapshots went with it |
| GCP (v2 `drishti-v2-260814`) | **GONE.** Same. The corpus bucket, artifacts bucket, `samples.csv`, the 14 rescued v1 observation artifacts and the 3 attestations are **unrecoverable** |
| Trial billing account | `01996C-C72085-6358D2` — **`open: false`** (closed) |
| Usable billing account | `017B2F-A06E63-B76B98`, INR, `open: true` |
| GCP (v3) | **`cybershield-505518`**, billing linked. compute/storage/oslogin/**IAP**/billingbudgets enabled. **3 buckets in `us-east1`** (versioned, PAP `enforced`, uniform access, noncurrent deleted @7d). **0 VMs** — bootstrap creates no compute |
| Budget guard | Project budget `drishti-cybershield-505518` = **₹4,200 (≈$50)**, alerts at 60/90/100%. Sits inside the account-wide ₹10,000 alert that already existed |
| Compute quota | `CPUS_ALL_REGIONS: 32`, `asia-south1 CPUS: 100`, `DISKS_TOTAL_GB: 4096`, `INSTANCES: 24` — no increase needed |
| Extractor VM (pre-existing) | `instance-20260817-080247`, project `internship-505513`, `us-east1-c`, `n2-standard-2`, 500GB `pd-standard`, **public IP**, **nested virt OFF**, SA scope `devstorage.read_only`. Usable for static extraction; **disqualified as a detonator** |
| Secrets | `.env` recreated (gitignored). `ANDROZOO_API_KEY` set — **exposed in a chat transcript, rotate post-demo**. `GEMINI_API_KEY` **not yet provided** |
| PR trail | **Zero PRs exist on the remote.** `gh pr list --state all` on `Soni-Shivam/CyberShield` returns nothing; `PROGRESS.md`'s PRs #1–#11 describe local branch history only |
| v1 corpus list | `v1-reference/backend/samples.csv`, 6,000 rows, 3000/3000 balanced — **split contaminated**: 1,235 rows (20.6%) dated 1980/81 all in train, 23 rows dated 2039–2107 all in test; only 62 rows from 2024, 55 from 2025 |
| Test baseline | **Measured 2026-08-17 at `615a803`: 300 contract+unit, 14 e2e, 314 total, all passing.** ruff clean, mypy clean over 41 source files. v1's claimed 124 remains unverified — do not quote it |

## Demo build — 2026-08-26 (24-hour prototype push)

Four workstreams in parallel: corpus extraction, ML training, the Android demo, and the
detonator. This section records the orchestration and the M7/report work; the ML and
lab sections are updated by their own owners.

### Lab state, re-measured 2026-08-26

The 2026-08-17 table above is **stale in three rows**. Corrected by inspection:

| Item | State on 2026-08-26 |
|---|---|
| Active gcloud account | `sonishivam.iitb@gmail.com`. The 2026-08-25 blocker (`vedant.jeecompass@gmail.com` could not list Compute) is **gone** — all projects and instances are listable |
| Extractor VM | `instance-20260817-080247`, **resized `n2-standard-8` → `n2-standard-16`**. SA scope is `devstorage.read_write`, not `read_only` as recorded on 08-17, so GCS retention works |
| Cross-project IAM | `887402914495-compute@…` already holds `roles/storage.objectAdmin` on `gs://cybershield-505518-corpus`. No grant needed |
| Detonator VM | **`m3-detonator` created**, `n2-standard-4`, `us-east1-c`, **nested virtualisation ENABLED**. The first live detonation is in progress; none has succeeded yet |
| Quota | `CPUS_ALL_REGIONS` 32, 15 in use before the resize. The resize to 16 vCPU was sized to leave headroom for the detonator |
| Untouched | `instance-20260814-133700` (e2-micro) holds the operator's personal data and is explicitly out of scope for every task |
| **XGBoost thread count on the laptop** | **`n_jobs=-1` is catastrophic, and it looks exactly like a hang.** One 400-round fit over a 276×478 matrix: `-1` **103.92s**, `16` 81.25s, `8` **0.15s**, `4` 0.16s, `1` 0.12s. OpenMP spin-wait fighting the rest of the box — 1030% CPU, load average 35, fifty threads, no forward progress. `m5_ml.models.N_JOBS` caps at `min(4, cpu_count)` (`DRISHTI_ML_JOBS` overrides), and `train_and_report.py` pins `OMP/OPENBLAS/MKL/NUMEXPR_NUM_THREADS` **before numpy is imported**, because those are read once at load |
| **shap under numpy 2** | shap 0.46 raises at import; **≥0.48 required**. Verified working: shap 0.51.0 + numpy 2.4.6 + Python 3.11 |
| **Trained model location** | `models/*` is gitignored, so the bundle exists **only** at `gs://cybershield-505518-models/` plus whatever is in a working tree. The feature JSONL it was trained on is archived at `gs://cybershield-505518-corpus/features/` |

### Corpus extraction — running

Real APKs from AndroZoo, 10,599-row time-split list, extracted through the **real M2**
into 131-feature records. `scripts/launch_extraction.sh` is the launcher and carries the
findings below in its header.

- **AndroZoo key verified live** (HTTP 206 on a ranged download). The full 3.3 GB index
  was already on the laptop from a previous session; no re-fetch needed.
- **Throughput is CPU-bound, not download-bound.** Measured: each shard pegs ~95% of a
  core in androguard while the NIC moves 1 MB/s. 4 shards on 8 vCPU → **440 rec/hr**;
  14 shards on 16 vCPU → **1,489 rec/hr**.
- **Memory is the real ceiling and it counts THREADS.** `AnalyzeAPK` holds the DEX and
  its call graph per thread, so in-flight analyses are shards × threads. At 14×4 = 56
  the 64 GB VM entered sustained `Under memory pressure, flushing caches`, starved
  sshd, and was unreachable for ~20 minutes; throughput collapsed to ~200 rec/hr before
  it died. Fixed with per-unit `MemoryHigh=2500M` / `MemoryMax=3500M` and
  `Restart=on-failure`, so one greedy shard is killed alone and resume brings it back.
  **No records were lost** — 477 survived the incident.
- **Settled at 14 shards × 3 threads**, ~680 rec/hr measured at 14×2 with memory at
  32/62 GB.
- **Evaluation splits are extracted first.** The full list will not finish inside the
  deadline, so the prefix that *does* finish was chosen deliberately: test and calib
  complete before any training row, because CI width is driven by test n while 131
  features are learnable from a modest training sample. A uniform prefix would have
  produced a test set of a few hundred rows with ~25 malware, too thin to report.
- Round-robin sharding is preserved within each split, so any prefix stays label- and
  time-band-balanced.

### ML layer — five models compared, winner shipped and wired (T2.3–T2.6)

`docs/ML_RESULTS.md` is generated by `scripts/train_and_report.py` from the run that
produced it; no number in it is typed by hand. Headline, **measured on 553 usable
samples** (32 more failed extraction and are dropped, never zero-filled):

| model | random-split PR-AUC | time-split PR-AUC | gap |
|---|---:|---:|---:|
| `logreg_l2` | 0.9773 | 0.9334 | 0.0439 |
| `linear_svm` | 0.9629 | 0.8966 | 0.0663 |
| **`random_forest`** | **0.9863** | **0.9580** | **0.0283** |
| `xgboost` | 0.9847 | 0.9270 | 0.0577 |
| `mlp` | 0.9782 | 0.9607 | 0.0175 |

**Every one of the five loses ground when the test set is strictly newer than train.**
That is the drift finding, and it is the argument for the behavioural and GenAI layers.
Time split n=107 (57 malware); random split n=111 (62 malware). Intervals in the doc.

- **Selection never touched the test set.** The winner is the highest 5-fold CV PR-AUC
  *inside the training split*. Best-of-five on test turns test into a validation set.
- **`vt_detection` cannot become a feature.** `dataset.assert_no_label_leak` raises on
  any `vt:`/`virustotal`/`avclass`/`detection` name and refuses the vocabulary outright —
  AndroZoo's label is thresholded `vt_detection`, so such a model is circular.
- **Shipped and wired.** `models/` holds classifier + calibrator + anomaly detector +
  frozen vocabulary + SHAP background + `model_card.json`; mirrored to
  **`gs://cybershield-505518-models/`** (`models/*` is gitignored, so GCS is the only
  copy). Verified on the canary: `model_version` `random_forest-504f-1.1.0`, P_cal 0.2525,
  and the scorer's `gamma` rises 0.40 → 0.60 with **"ML prediction unavailable" gone from
  `limitations`**.
- **Reproducibility.** The feature JSONL this was trained on is archived at
  `gs://cybershield-505518-corpus/features/`. The model card records the scikit-learn,
  xgboost and numpy versions the pickles were written by, and inference *declares* a
  runtime mismatch rather than letting a differently-behaving model pass silently.
- **The run refuses to report below 25 per class** and stamps everything `PILOT` if
  forced past it with `--allow-small`.
- **This is a snapshot.** Extraction was still running; training data is the binding
  constraint. `ML_RESULTS.md` §6b carries the learning curve — 49 → 396 training rows
  moved time-split PR-AUC 0.9395 → 0.9559, **still rising**, so the reported figure is a
  floor rather than a ceiling.

### LLM provider — switched to OpenRouter, verified live

`DRISHTI_LLM_PROVIDER=openrouter`, model **`nvidia/nemotron-3-ultra-550b-a55b:free`**.
Verified against the live API, not assumed:

- Model id exists; 1M context; **supports `tools`/`tool_choice`**, so the bounded
  tool loop in the RE workspace works. Pricing 0.
- A full pipeline run on the canary through the **real** provider: `genai_static`
  completed in 7.6 s, 2 MITRE techniques mapped and grounded, **4 claims generated, 4
  verified, 0 rejected** against 14 citable nodes.
- **The free endpoint is unreliable: 2 of 5 probe calls returned
  `502 Upstream error from Nvidia: Service temporarily overloaded`.** This is a demo
  risk, not a code defect. The LLM path degrades gracefully, but a live demo should
  either warm the cache first or be prepared to fall back.
- **The key was pasted into a chat transcript and must be rotated post-demo**, same as
  the AndroZoo key.

### M7 — report, STIX, YARA, dossier (T6.1, T6.2, T6.3)

`drishti/m7_report/` was **empty**; all three export routes returned 501. Now built,
with every honesty property enforced by a test rather than by care:

- **Report** (`report.html`): self-contained, no external assets, printable. The
  Limitations section is **derived** from provenance flags — partial analysers, replay
  vs live, hand-authored fixtures, unverified containment, rejected claims, mock
  provider, low confidence. A sample that produced no runtime behaviour renders
  `INCONCLUSIVE, never benign`.
- **STIX 2.1**: ids are UUIDv5 over stable keys, so two exports of a job are
  byte-identical and the scorer's determinism is not undone one layer up. Publishes
  only *verified* claims and *observed* flows — never `synthesised` ones, which were
  served by our own Generative C2.
- **YARA**: keyed on repack-resistant artefacts; the hash is metadata, never a
  condition. Below 3 distinctive strings it emits itself **disabled with the reason**.
- **Dossier** (new route, contract addendum A12): the package a cyber cell or bank
  fraud desk needs. `submission_is_manual` is always True — **NCRP has no public
  submission API and nothing here files anything**. The sample never leaves the
  analysis project.

Two defects found by running it for real rather than by reading it:

1. The YARA generator keyed its rule on the Kotlin reflection warning string, which
   ships in every Kotlin app — the rule would have matched most of the Play Store.
   Fixed with URL shape-checking and a toolchain-boilerplate filter.
2. `str()` on an asn1crypto `Name` returns the object repr, so a real run put
   `<asn1crypto.x509.Name 139086784924624 b'071\x16…>` into the investigation report
   and into a document intended for a fraud desk. Now renders `CN=…, O=…, C=…`.

### Integrity stage demos

`scripts/demo_integrity.py` — `make demo-reject`, `make demo-tamper`, `make demo-integrity`.
Throwaway DB and key, safe to run live and repeatedly.

- **reject**: an AI claim citing nothing is refused; a *fabricated* citation is refused
  by resolution; the same claim is accepted once cited. The refusals leave **no gap in
  the sequence**, because grounding is checked inside the write transaction.
- **tamper**: turned out to be a two-layer result. The append-only SQL triggers refuse
  the `UPDATE` outright; after an attacker drops the triggers and rewrites the row, the
  hash chain still reports the break **at the exact seq**. `T6.4`'s note that the tamper
  demo was deliberately unbuilt is now superseded — it is built honestly, against real
  SQL and real chain verification, not simulated in the browser.

### Paper idea → proof-of-concept status (updated 2026-08-26, later in the day)

The team's ideation paper (`REPORT/main.tex`, §17) tracks each novel claim as
validated-vs-designed. This is the operational mirror of that table, updated as PoCs
land. The bar for this hackathon is a working PoC per idea, not a finished product.

**Newly proven since the morning entry:**

- **First live detonation SUCCEEDED** (`12ac2a2`, `151d59a`). A real corpus sample was
  detonated on the sealed `m3-detonator` (Android 33 x86_64 under KVM, frida 16.7.19
  matched). Containment was proven non-vacuous: the guest reached 8.8.8.8, 1.1.1.1 and
  the metadata server *before* lockdown and none of them *after*. This clears the
  paper's §17 "GenAI-synthesised sandbox — awaits the detonator" blocker.
- **First reportable model comparison SHIPPED** (`b432c31`, `cbc781d`). Five models,
  both splits, every n stated; winner random_forest by CV, time-split PR-AUC 0.954 on
  n=107 (57 malware). Past the 25-per-class gate — no longer PILOT-only. `docs/ML_RESULTS.md`.
- **Benign-lookalike discriminator** (`048eef6`, `e9f3d9e`) — the Truecaller problem.
  Separates a banking trojan from an app with the same permissions. Found and fixed two
  real defects by measuring on real samples (certificate dates never parsed;
  `package_strings` never surfaced). Real-sample validation on 80+ samples is in flight;
  **if it does not discriminate at scale it will be cut, not shipped.**
- **Icon impersonation detection** (`dd40f15`) — the "it wears the bank's face" beat.
  Perceptual-hash floor + VLM semantic layer; verified live (synthetic blue-rupee icon →
  "imitates HDFC Bank, 0.92", grounded). VLM claims are dropped unless the named brand is
  checkable — the ledger's grounding rule applied to vision.
- **Report / STIX 2.1 / YARA / dossier exports** (`be678a3`, `691ffb3`) — M7 was empty;
  all four now built, honesty properties test-enforced.

**Still genuinely unproven / designed-only:**

- **The lookalike discriminator's real-sample performance.** It works on fixtures; the
  80-sample validation had not returned at this entry. Treat as unproven until it does.
- **Generative C2 emulation** remains designed, not built, and is bounded by CLAUDE.md's
  hard boundary — a PoC is only legitimate if the synthesised response is provably inert.
- **Environment morph → re-detonation (the D3 "sandbox-aware sample" demo)**: the morph
  *proposals* and the applicator are built and unit-tested; a live morph-then-wake on a
  real evasive sample has not been captured.
- **The end-to-end judge demo** (good-app-passes / bad-app-blocked on the emulator, with
  the Device-Owner veto) is being built by a dedicated worker and not yet rehearsed cold.

---

## Presentation hardening — 2026-08-25

- **GUI:** reverse-engineering workspace, persistent seven-view navigation, URL-deep-linked
  jobs/evidence/methods, decompiled-code inspection, verified strings, tool-call audit, score
  rail, and responsive desktop/mobile layouts landed in `7fce6f0`. Production Vite build
  passed; desktop and 390x844 browser screenshots were inspected.
- **Reverse engineering:** bounded DAD decompilation is restricted to methods on reachable
  sink paths. The model can request only six allowlisted, Pydantic-validated, read-only
  analysis tools; every call is budgeted, bounded, and written to the evidence ledger.
- **Detonation:** the VM harness now requires a signed, short-lived containment manifest,
  the immutable runtime marker, and `/dev/kvm` before snapshot restore or `adb install`.
  Frida collection, install refusal handling, and post-run snapshot restore are covered by
  faked unit tests. **No live GCP detonation has been performed or claimed.**
- **Scoring honesty:** unavailable ML/reputation placeholders, mock GenAI, and synthetic
  traces no longer inflate `S`, `gamma`, or `C`; limitations are derived from provenance.
- **Authored canary check:** local static parsing only (no install or execution) completed
  as `job_35d6a108e96a`: `S=0`, `C=0.2`, `gamma=0.4`, with unavailable and containment
  limitations visible. Real APK detonation remains VM-only.
- **Verification:** 493 contract+unit tests and 15 e2e tests passed; ruff, shell syntax,
  `git diff --check`, and the production UI build passed. `make e2e` could not access the
  sandboxed global uv cache, so its exact pytest target ran via `.venv/bin/pytest`.
- **Live blockers:** the active account `vedant.jeecompass@gmail.com` cannot list Compute
  instances in `cybershield-505518` or `internship-505513`. No GCP resource was started in
  this session; whether a pre-existing resource is running could not be independently
  established. Better-model evaluation is specified in `docs/RE_MODEL_EVALUATION.md` but
  remains unrun because no MLflow tracking target/experiment or live model credential was
  available. No metric has been invented.

---

## P0 — FOUNDATIONS (H00→H06)

- [x] T0.1  Repo skeleton + tooling                DONE  H00  tests: 26/26 · lint+mypy clean
- [x] T0.2  Config                                 DONE  H03  tests: 204/204
- [x] T0.3  All contracts, verbatim                DONE  H01  37 models · tests: 140/140
- [x] T0.4  Evidence Ledger                        DONE  H02  tests: 178/178 · CLI verified
- [x] T0.5  Job runner + pipeline skeleton          DONE  H03  11 stages · chain verified
- [x] T0.6  API surface                            DONE  H04  19 routes frozen · tests: 235/235
- [x] T0.7  TraceSource abstraction + fixture      DONE  H05  pre/post-morph arc · tests: 261/261
- [x] T0.8  UI shell                               DONE  2026-08-17 · `ui/` Vite+React+TS+Tailwind
      Four regions per the T0.8 sketch, plus the T6.4 stage strip and all seven tabs
      built against the frozen T0.6 surface. Verified in a real browser against a live
      API on the canary: upload -> SCORE_PRELIM -> factor -> evidence chip -> ledger
      node, and "Verify chain" returning 29 nodes intact. Python tests unchanged at 408.
- [~] T0.9  Sandbox VM groundwork                  WIP   2026-08-25  7fce6f0 · immutable image/runtime admission code ready; live build blocked by IAM
- [x] T0.10 Ingest module M1, for real             DONE  H07  guards+split+intel
- [x] P0.11 Ledger concurrency hardening           DONE  2026-08-17  615a803 · tests: 314/314

      Not a roadmap task — three defects found while establishing a real test baseline.
      The earlier "tests: 304/304" recorded against T0.10 counted a **failing** e2e test
      as passing: contract+unit was run, `tests/e2e` was not. True state was 303/1.

## P1 — STATIC ENGINE (H04→H16)

- [x] T1.1 Manifest & permission analysis          DONE  2026-08-17 · 14 combo rules, DoD enforced by test
- [ ] T1.2 Certificate analysis                    TODO
- [~] T1.3 Strings, constants, packing signals     WIP   H10  URLs/packages/crypto, entropy and native-lib signals
- [~] T1.4 Call-graph + backward sink walk         WIP   2026-08-25  7fce6f0 · 29 sinks, bounded BFS + path-scoped DAD decompilation
- [ ] T1.5 Over-privilege & drift                  TODO
- [~] T1.6 Hypothesis derivation                   WIP   H10  evidence-cited static→dynamic bridge (six kinds)
- [ ] T1.7 MobSF enrichment (optional)             TODO

## P2 — ML & SCORING (H10→H24)

- [x] T2.1 Feature extractor                       DONE  2026-08-17 · 12/12 families, 71 feats, parity test + vocab pinning
- [~] T2.2 Dataset assembly                        WIP   2026-08-17 · REAL sample list built; no APK downloaded
      27.6M index rows scanned, seed 20260817. 70.6% dropped for implausible dex_date.
      10,599 rows selected = 193.9 GB. 2024-2026 malware yielded only 99 of 1500 —
      MalwareBazaar backfill is now required. List archived to the corpus bucket.
      Stratified sample-list builder + contract A9 + 20 tests. The real AndroZoo index
      has not been fetched; every number so far is from a synthetic 60k-row index.
- [x] T2.3 Train the classifier                    DONE  2026-08-26  b432c31 · tests: **595 contract+unit passed** (`make test`, 106s, measured 2026-08-26; 48 of them new in m5)
      **Five models compared**, not one: logistic regression, linear SVM, random forest,
      XGBoost, MLP — identical features, identical splits, seed 20260826. Winner
      **`random_forest`**, chosen by 5-fold CV PR-AUC **inside the training split**
      (0.983 ± 0.007); the test split played no part in selection.
      **Time-split PR-AUC 0.9580 [0.9228, 0.9825] on n=107 (57 malware, 50 benign).**
      Random-split 0.9863 [0.9646, 0.9997] on n=111 (62 malware). **Gap 0.0283, and every
      one of the five loses ground on the time split** — that is the drift finding.
      **Trained on 396 samples. Never quote the PR-AUC without the n.**
      Intervals are 2000-resample bootstraps. Full table, every model x split x metric
      with n, in `docs/ML_RESULTS.md`. Corpus extraction was still running.
- [x] T2.4 Calibration                             DONE  2026-08-26  b432c31
      Isotonic and Platt fitted on the **held-out calib split**, method chosen by
      cross-validated Brier **within** calib — choosing it by test Brier is the same leak
      as calibrating on test. Shipped: sigmoid on n=50 (24 malware).
      **Brier on test 0.1494 → 0.1064**, expected calibration error **0.2049 → 0.0885**.
      `docs/figures/ml_reliability.png`, markers sized by bin count.
      `PHASE_2` T2.4's bucket check is computed but **reports "not informative"**: only 5
      test samples landed in [0.75, 0.85] after calibration. It is recorded as not
      informative rather than as a pass, and it will become meaningful as test grows.
      **Hard floor: below 10 positives no calibrator ships at all** — measured, Platt on
      a calib split with one malware row moved test Brier 0.130 → 0.595, making the
      probability confidently worse. See Deviations for the calib/test re-cut.
- [x] T2.5 Anomaly detector                        DONE  2026-08-26  b432c31
      **No longer the dead branch this file recorded.** IsolationForest, 200 trees, fitted
      on benign training rows only, published as a percentile against the frozen benign
      distribution so the 0.85 threshold means the same thing across retrainings.
      `infer.predict()` now sets `anomaly_score` and `anomaly_escalate`, and
      `tests/unit/test_m5_bundle_inference.py` asserts train → persist → load → predict
      rather than the contract in isolation.
      Measured on the test split: **28.0% of benign samples escalate** against 78.9% of
      malware. That benign rate is the analyst cost this flag creates and is reported
      next to the claim; it is high, and it is high because train benign are older than
      test benign — drift shows up in the novelty detector too.
- [x] T2.6 SHAP explanations                       DONE  2026-08-26  b432c31
      `shap.TreeExplainer` on the shipped model; signed per-sample contributions with
      readable names (`perm:READ_SMS`, not `f_0142`). Verified on the canary through the
      real bundle. **When SHAP is unavailable `top_features` is left EMPTY** and the
      reason lands in `errors` — never global importance captioned as SHAP.
      Global ranking is permutation importance measured on the test split, shortlisted to
      the model's top 60 columns first and saying so in the method string.
- [~] T2.7 The scorer                              WIP   2026-08-25  7fce6f0 · noisy-OR + override + bands; unavailable signals excluded from confidence
- [ ] T2.8 Bands and proposed actions              TODO
- [ ] T2.9 Scorer test suite                       TODO

## P3 — GENAI CORE (H16→H36)

- [~] T3.1 LLM client                              WIP   2026-08-25  7fce6f0 · bounded OpenRouter tool loop; live provider validation pending
- [ ] T3.2 Prompt-injection defence                TODO
- [ ] T3.3 Controller                              TODO
- [~] T3.4 Code Interpreter agent                  WIP   2026-08-25  7fce6f0 · grounded method interpreter + allowlisted tools; model eval pending
- [ ] T3.5 RAG grounding                           TODO
- [ ] T3.6 Behavioural risk B, bounded             TODO
- [ ] T3.7 Technique Mapper                        TODO
- [ ] T3.8 Social Engineering Analyst              TODO
- [ ] T3.9 Vision impersonation                    TODO
- [~] T3.10 Verifier integration + summariser      WIP   2026-08-25  7fce6f0 · evidence/tool verification integrated; broader eval pending
- [ ] T3.11 Disagreement meta-check                TODO
- [x] T3.12 Structured output contract             DONE  2026-08-25  7fce6f0 · tool calls, verified strings, interpretations round-trip tested

## P4 — DYNAMIC SANDBOX (H24→H48)

- [~] T4.1 Emulator control                        WIP   2026-08-25  7fce6f0 · snapshot/admission flow unit-tested; live lab pending
- [~] T4.2 Frida runner                            WIP   2026-08-25  7fce6f0 · observational harness implemented; live lab pending
- [ ] T4.3 Crash recovery & self-repair            TODO
- [ ] T4.4 TLS interception & network capture      TODO  ← v1 gap H4, see CARRIED_FINDINGS
- [ ] T4.5 Evasion observation detection           TODO
- [ ] T4.6 Trace normalisation                     TODO
- [ ] T4.7 TRIPWIRE @ H40                          TODO  ← mandatory decision point
- [ ] T4.8 Sandbox plan builder                    TODO

## P5 — FRONTIER (H44→H58)

- [ ] T5.1 Morph applicator                        TODO
- [ ] T5.2 Morph validation                        TODO
- [ ] T5.3 Adversarial Elicitor agent              TODO
- [ ] T5.4 Generative C2 emulation                 TODO
- [ ] T5.5 Frontier orchestration loop             TODO
- [ ] T5.6 Replay-mode frontier                    TODO
- [ ] T5.7 Frontier UI panel                       TODO

## P6 — REPORT / UI / DEMO (H50→H72)

- [ ] T6.1 YARA generation                         TODO
- [ ] T6.2 STIX 2.1 export                         TODO
- [ ] T6.3 HTML report                             TODO
- [~] T6.4 Dashboard completion                    WIP   2026-08-25  7fce6f0 · seven views + reverse-engineering workspace render live
      Every panel is wired to a real endpoint and renders only what the API sent. What
      remains is depth that depends on unbuilt modules (report embed T6.3, YARA T6.1,
      STIX T6.2 all render their 501s today) plus the dev-only **tamper demo**, which is
      deliberately unbuilt — see Deviations.
- [ ] T6.5 Code freeze @ H68                       TODO
- [x] T6.6 Demo script                             DONE  2026-08-26 · `docs/DEMO_SCRIPT.md`, beat-by-beat with measured timings
- [~] T6.7 Backup plan                             WIP   2026-08-26 · fallbacks per beat in DEMO_SCRIPT §5; no backup video yet
- [ ] T6.8 Q&A preparation                         TODO
- [ ] T6.9 Final hour                              TODO

### T6.10 — Live on-device interception demo · DONE 2026-08-26

The single most-demoed artefact: an Android emulator on the demo laptop running
**DRISHTI Shield**, which intercepts a malicious APK *before* it installs.

- **Emulator, local.** Android 34 `google_apis` x86_64 AVD (`drishti_demo`, 4 vCPU /
  3 GB / 3 GB data) under KVM on the laptop. `google_apis`, not `playstore`, because
  device owner requires a device with no accounts and `adb root` must work. This is
  **not** a detonation host and nothing from `data/samples/` or any corpus bucket has
  ever been on it — the only two APKs it has seen are `shield/` and
  `canary/decoy-challan/`, both compiled from source in this repo.
- **`shield/`** — Kotlin, AGP 8.7.3, minSdk 26, targetSdk 34, zero dependencies beyond
  the Android framework. Four layers: pre-install `FileObserver` watcher + 250 ms
  sweep; tap-time intent filter; `DevicePolicyManager` veto as device owner;
  post-install hash-match failsafe.
- **`canary/decoy-challan/`** — an inert decoy named "RTO Challan". Its manifest
  declares the Indian challan-fraud family's permission set; **every implementation
  body is an empty method or a `Log.i`**. `verify_inert.sh` proves it by grep (comment-
  stripped) and gates both `build.sh` and `scripts/demo_up.sh`. Not committed.
- **`scripts/demo_up.sh` / `demo_deliver.sh` / `demo_down.sh`** — cold start to ready
  in **35 s measured**, including a wiped AVD.
- **`GET /api/jobs`** added to the T0.6 surface (additive; recorded in
  `docs/PHASE_0_FOUNDATIONS.md` in the same commit) so the dashboard can discover
  jobs created by the phone. `ui/src/components/DeviceFeed.tsx` polls it and follows
  the phone with nobody touching the browser — verified in a real browser.

**Measured 2026-08-26** (never estimated; reproduce with `docs/DEMO_SCRIPT.md` §7):

| Measurement | Value |
|---|---|
| `demo_up.sh --fresh`, cold to ready | 35 s, 37 s (two runs) |
| **File landing → verdict on screen** (two-phase, final) | **5.0 / 5.4 / 8.9 s** |
| Composite score arriving after the verdict | up to 33 s total |
| — of which M2 static | 4.9–9.7 s (from `stage_history`) |
| — of which `genai_static` | **0.8 s cached, 35 s cold** |
| — of which Shield itself | < 0.3 s |
| Layer 4 detection after install | < 1 s |
| Superseded: verdict latency before the two-phase split | 7.9–13.1 s (5 runs), 41.4 s worst case on a cold LLM |
| Tests | 581 contract+unit passing at this change |

**The veto is real and was proved, not asserted.** With Shield as device owner,
`dumpsys user` reports `Device policy restrictions: no_install_unknown_sources`, and
driving the system package installer at the APK hands off to
`com.android.settings/.enterprise.ActionDisabledByAdminDialog` — Android's own
"blocked by your admin" screen. `adb install` still succeeds because the shell UID is
exempt from the restriction; that is what Layer 4 exists for, and it caught it
(`package_added` → `quarantine … suspended=true` → `failsafe_engaged`).

**Re-proved on the final full rehearsal (2026-08-26, `--fresh`, exit 0):** cold to
ready 37 s → device owner provisioned on attempt 1 → verdict in 6506 ms with
`veto=true` → forcing the system package installer landed on
`com.android.settings/.enterprise.ActionDisabledByAdminDialog` with
`Device policy restrictions: no_install_unknown_sources` and
`Effective restrictions: no_install_unknown_sources_globally` → `adb install`
(shell UID, exempt) succeeded and Layer 4 caught it with `quarantined=true`,
`suspended=true`.

**The composite score for the decoy is 0, and the phone says why.** The Shield's
`BlockDecision` blocks on **M2 static evidence** — 1 critical + 4 high permission
combinations, each MITRE-mapped — and prints "BASIS FOR THIS DECISION · M2 static
evidence" beside the zero, with the reason. No number was invented to make the demo
look better.

**Re-measured 2026-08-26 as other agents landed work.** The environment moved twice
during this task and the demo tracked it without any change to the block logic:

| When | `S` | Why |
|---|---|---|
| LLM mock, no model | 0 LOW, γ 0.40 | no admitted inputs to `F_AI` |
| LLM live (`openrouter`), no model | 0 LOW, γ 0.40 | LLM returned `B = 0.999352` (7 behaviour flags, 7 claims) and `m6_score.engine` **excluded it**: `has_behavioural` requires `not genai.partial`, and the verdict is partial because the full pass reused the static verdict with no dynamic evidence |
| LLM live + trained model | **43 MEDIUM, γ 0.60** | `random_forest-504f-1.1.0` at `p_calibrated = 0.864`, `anomaly_escalate=True`; top SHAP features `perm:READ_SMS`, `combo:count=7`, `combo:OVERLAY_CREDENTIAL_THEFT` |

43 is below the 65 HIGH floor, so `BlockDecision` correctly keeps the basis at
`STATIC_EVIDENCE` and the phone says so beside the score. **No scorer code was changed
and no threshold was moved to make a number look better.**

**A finding worth keeping: the LLM over-reads a static-only surface.** It asserted
`reads_sms_content` and `exfiltrates_over_network` for an APK containing no SMS code
and no networking code at all — it inferred behaviour from the declared manifest. This
is now a scripted answer in `docs/DEMO_SCRIPT.md` §2.3, because it demonstrates
exactly *why* `B` is computed in Python from enumerated booleans rather than taken as
the model's number.

## Salvage from v1 (see `docs/SALVAGE.md`)

- [x] known_bad_hashes.txt LIFT -> data/kb/                 DONE  H07
- [x] Lab infra LIFT (`infra/m3/**` → `infra/gcp/`)        DONE  H08  + auto_delete and snapshot-policy fixes
- [~] Containment verification LIFT                        WIP   2026-08-25  7fce6f0 · signed fail-closed admission; live lab pending
- [~] M3 harness + hook catalogue LIFT                     WIP   2026-08-25  7fce6f0 · spawn-gated harness unit-tested; live lab pending
- [x] canary/ source written to §4 spec                    DONE  H09  compile-only builder + `dist/canary.apk`; 341 tests
- [x] ~~Rescue v1 lab data off VM disks → GCS~~            **LOST**  2026-08-17

      Both GCP projects were deleted. The 4 boot-disk snapshots, the 14 rescued
      observation artifacts, the 3 attestations, `samples.csv` and the v1 feature CSV
      are gone with them. Nothing listed under this item is recoverable.

      **Surviving v1 provenance, in full:**
      - `data/fixtures/observations/` — 2 real observation artifacts, committed as CI
        fixtures and covered by `tests/contract/test_real_observation_artifacts.py`
      - `docs/CARRIED_FINDINGS.md` — the measurements and the 11 defects
      - `v1-reference/backend/samples.csv` — the 6,000-row corpus list (in-repo)

      Any claim resting on the 9-sample v1 pilot is now supported only by those three.
      Do not present the other 12 artifacts as available evidence.

---

## Gaps against the documented Definition of Done

Measured on `main` at `57823a8`, 2026-08-17. P1/P2 skeletons exist and pass their own
tests; these are the distances still to close, each traced to the doc that requires it.

| Requirement | Source | Required | Actual |
|---|---|---|---|
| Permission-combo rules | `PHASE_1` DoD | ≥ 14 | **14** — enforced by test |
| Sink taxonomy | `PHASE_1` DoD | ≥ 18 | **29** in `m2_static/sinks.py` — enforced by test |
| Feature vector width | `PHASE_2` T2.1 | 12 families | **12/12 families, 71 features on the canary** (was 5/12, 17) |
| Scorer determinism test | `00_GUIDING_MAP` §9.3 | 100× identity | **done** — plus a source-level purity assertion |
| Feature parity test | `PHASE_2` T2.1 (R3 mitigation) | golden-file element-wise | **done** — `tests/contract/test_feature_parity.py` |
| Vocabulary pinning | `PHASE_2` T2.1 | frozen vocab, width asserted both paths | **done** — `build_vocabulary`/`project`/`load_vocabulary` |

None of these is a defect in what exists — they are unbuilt depth. They are recorded here
rather than in a branch so the number in any slide can be checked against them.

## Concurrent-agent episode (2026-08-17)

Two agents worked this repo in parallel for part of the day: this one (PRs #1–#3, #10–#11)
and a Codex agent on `codex/*` branches (PRs #4–#9). **The canary was built twice**, in two
incompatible ways — `namespace`/`applicationId` split versus backtick-escaping the Kotlin
package. #6 landed first; #10 was closed as superseded and only its uncovered M1 test was
salvaged as #11.

Recorded because it is the kind of thing a retrospective forgets: the duplicated work was
not caught by any test or gate, only by reading `git log`. Single agent from here.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-13 | ML features: **full v2 ~1200-dim schema, re-extract corpus first** | v1's 35-feature vector is a strict subset; PHASE_2's feature families and the paper's Drebin-style claim need the full set |
| 2026-08-13 | Lab: **fresh GCP project for v2**, legacy project read-only until v2 detonates the canary | Clean IAM/VPC to the CLAUDE.md spec; legacy kept as the data source until rescue is proven |
| 2026-08-13 | Branches: `v1` = immutable v1 record, `main` = v2 integration | origin had only `v1`; `main` was free |
| 2026-08-13 | Corpus APKs **retained in GCS** after extraction | v1 deleted every APK post-extraction, which is exactly why a schema change now costs a full re-download |
| 2026-08-17 | Lab rebuilt in **`cybershield-505518`**, region **`us-east1`** | Co-located with the pre-existing extractor VM. Moving 120GB cross-region would cost ~$12. **Deviates from `CLAUDE.md`'s `asia-south1`** |
| 2026-08-17 | Extractor = the existing `internship-505513` VM; **detonator built separately and sealed** | Static parsing never executes a sample, so a shared project is tolerable there. Detonation is not: that VM has nested virt off, a public IP, and shares a VPC with an unrelated running VM |
| 2026-08-17 | Corpus target **12,000 rows**, 50/50, 4 time bands, download order stratified | Makes any *prefix* of the download a balanced, time-spanning corpus, so a metered transfer can be stopped at any point and still yield a valid time split |
| 2026-08-17 | Budget ceiling **$50**; every billable GCP resource confirmed before creation | The trial account is closed — there is no safety net |

## Deviations from roadmap

- **T2.3 fits five models, not one XGBoost.** `PHASE_2` T2.3 pins XGBoost. Five are
  fitted and compared on identical features, splits and seed. "We picked XGBoost" is an
  assertion; a comparison is a measurement — and on this corpus XGBoost is **not** the
  winner, so the deviation changed the answer rather than merely documenting it.
- **The winner is selected by cross-validation inside the training split, never by test
  PR-AUC.** Picking the best of five on test turns the test set into a validation set,
  and every number reported from it afterwards is the best of five draws.
- **`MIN_POSITIVES_FOR_ANY_CALIBRATION = 10`, and the calib/test boundary is re-cut when
  the shipped split falls under it.** `samples.csv` puts 7 malware rows in calib.
  Measured: Platt fitted on a calib split holding one positive moved test Brier
  0.130 → 0.595 — a calibrator making the probability confidently worse. The re-cut is
  applied to the **held-out bands only**, by `sha256` bucket, so it is label-independent
  and reproducible; **train is untouched**, so test stays strictly newer than train and
  it remains a time split. Disclosed with a before/after table in `ML_RESULTS.md`.
  `--no-repartition` keeps the shipped boundary and ships an uncalibrated probability.
- **`shap` pin raised `>=0.46,<0.47` → `>=0.48,<1`.** shap 0.46 raises at **import**
  under numpy ≥2.3 (`shap/plots/colors/_colorconv.py` calls `np.dtype(np.floating)`), so
  the entire explainability path was dead on this environment, not merely degraded.
- **The vocabulary drops feature names seen in a single training APK** once the training
  split reaches 500 rows. A name present in exactly one sample is a memorised sample id,
  and a corpus of thousands produces thousands of them.
- **Extraction reordered to test → calib → train** (owned by the extraction worker,
  recorded here because it changes what the ML numbers mean). The training driver refuses
  to fit while the training split is empty and says why; waiting for data is not an error.
- Repo layout: v1's implementation is preserved at `v1-reference/` (read-only, nothing
  imports it) rather than deleted, so ADAPT work can see the original. Not in
  `00_GUIDING_MAP.md` §8; additive only.
- `v1-reference/README.md` landed in PR #1 (restructure) rather than PR #2, so the
  directory is not unexplained at review time.
- **T0.1 dependency extras.** `PHASE_0` T0.1 lists one flat dependency block. Split into
  core + `[lab]` (frida<17, frida-tools, mitmproxy) + `[rag]` (chromadb,
  sentence-transformers) + `[yara]`. Reason: a laptop never instruments or proxies a
  sample, so installing frida/mitmproxy there contradicts the safety posture; and
  sentence-transformers pulls ~2GB of torch for a feature that is cut-listed
  (`00_GUIDING_MAP.md` §10 item 7). `make install` stays core+dev; `make install-lab` is
  for the detonator.
- **T0.1 LLM provider.** `PHASE_0` T0.2 specifies `anthropic_api_key` and
  `claude-sonnet-4-5`. Both SDKs are installed and the provider is selected at runtime
  (`DRISHTI_LLM_PROVIDER`), defaulting to **gemini** — that is the key that exists and v1
  demonstrated two live end-to-end runs with it. `mock` remains available for tests. No
  code depends on the choice yet; revisit at T3.1.
- **T0.1 added `GET /api/health`** ahead of T0.6's frozen route list, because the
  container healthcheck must be real rather than decorative. Not an analysis endpoint.
- **Contract version bumped 1.0.0 -> 1.1.0** (additive). `01_DATA_CONTRACTS.md` referenced
  eight models it never defined (`FileMeta`, `ThreatIntel`, `PermissionCombo`,
  `DecryptedBlob`, `DexLoadEvent`, `FileWrite`, `VisionMatch`, `StageEvent`). Defined, and
  the doc amended with an addendum per its own §0 rule. Also adopted v1's stricter
  detonator wire contract, which the doc did not specify at all.
- **T0.4: the `uuid7_hex[:12]` id convention in §0 is unsafe** and was corrected. Those 12
  hex chars are the 48-bit ms timestamp, so ids collided within a millisecond (50 identical
  ids in a 50-node loop). `new_id()` keeps the format but composes it from 8 hex of time +
  4 hex of a per-process counter. Documented as addendum A5.
- ~~T0.5 appends 11 ledger nodes, not 13~~ — **resolved by T0.10.** With real M1 writing
  `FILE_META` + `THREAT_INTEL` a run is **12** nodes, and **13** for a split bundle (which
  also writes `SPLIT_APK`). `PHASE_0` T0.5's "13 ledger nodes" was a fair estimate; the
  earlier 11 was only low because M1 was a stub.
- **T0.6 froze 19 routes and added 3 beyond the doc's list** (`/ingest`, `/ledger/export`,
  `/logs/stream` was listed; `/ingest` and `/ledger/export` are additive). A contract test
  asserts no *undeclared* `/api` route exists, so the surface cannot drift silently.
- **T0.6 uses two distinct "unavailable" statuses.** `PHASE_0` specifies 404 +
  `{"stage": ...}` for not-yet-produced artefacts. Frozen-but-unbuilt features (report
  T6.3, YARA T6.1, STIX T6.2) return **501** with the owning task instead, because polling
  a 404 is reasonable and polling something that will never exist is not.
- **`DynamicTrace.synthetic` added (T0.7).** `source == REPLAY` cannot distinguish
  replaying a real captured trace from replaying a hand-authored one, and the report's
  Limitations section is generated from flags like this. The loader derives it from the
  fixture's `provenance.kind` and overwrites whatever the JSON claims. Addendum A7.
- **`EvidenceType.REPORT_GENERATED` added.** The REPORT stage was mis-typed as
  `ANALYST_ACTION`, which means "a human confirmed something" — it made a rendering step
  indistinguishable from a human decision in the ledger, and the confirmation gate's audit
  trail has to be unambiguous. Caught by the API surface test. Addendum A6.
- **`DynamicTrace.outcome` added** because `detonated: bool` cannot express
  *inconclusive*, and a sample that emitted nothing must never read as benign.
- **T6.4's "tamper demo" button is not built, on purpose.** The ledger is append-only in
  SQL via triggers, so no API call can corrupt a node — and simulating the red banner in
  the browser would prove nothing about the mechanism it claims to demonstrate. Building
  it honestly needs a dev-mode endpoint that writes to the SQLite file directly. The
  Ledger tab states this on screen rather than leaving a judge wondering where it went.
- **The UI is a separate origin, not served by FastAPI.** `ui/` proxies `/api` to :8080 in
  both `dev` and `preview`. Mounting the built assets on the app would put a non-`/api`
  route into the file whose whole point (T0.6) is that its routes do not move.
- **Canary artifact path is `canary/dist/`,** not Gradle's `canary/app/build/outputs/…`.
  git cannot re-include a file whose parent directory is excluded, so a `!` allowlist
  inside an ignored `build/` directory can never fire. `tests/contract/test_repo_invariants.py`
  caught this and now guards both directions.
- **Contract version bumped 1.2.0 -> 1.3.0** (additive) for bounded decompiled methods,
  tool-call audit records, verified strings, code interpretations, and signed containment
  manifests. The documentation and Pydantic models landed together in `7fce6f0`.
- **HTTPS system-CA installation is no longer on the M3 critical path.** The immutable
  image retains proxy support, but plaintext `Cipher.doFinal` observation is sufficient
  for the initial lab gate and avoids the verified `-writable-system` failure mode.
- **Better-model evaluation is specified, not simulated.** The requested comparison
  requires real labelled examples, an MLflow tracking target, and callable provider
  credentials. `docs/RE_MODEL_EVALUATION.md` records the evaluation and promotion gate;
  no substitute metric was generated from fixtures.
- **Packer source paths and fixtures were corrected.** Image inputs now reference the
  current `drishti/` and `infra/` layout, exclude historical banking APK fixtures, and
  permit only the project-authored inert canary. The runtime fake endpoint has no upstream.

- **The evidence catalogue and the claim verifier had drifted** (2026-08-26).
  `build_evidence_catalogue` offered `certificate` nodes, and `Verifier.check_claim`
  refused a claim that cited one alone (`REJECTED_TYPE_MISMATCH`, because a certificate
  carries no behavioural information). The model would have been recorded as citing
  badly for taking an id we handed it, and a grounded sentence would have been dropped.
  Fixed by deriving the catalogue's exclusion set from the verifier's
  `NON_BEHAVIOURAL_TYPES` rather than restating it, so the two cannot drift again;
  certificate facts already reach the prompt as trusted derived facts and feed the
  deterministic score, so nothing is lost. Surfaced as an intermittent
  `PYTHONHASHSEED`-dependent failure in
  `tests/unit/test_grounded_claims.py::test_one_bad_citation_does_not_sink_the_good_ones`,
  which picked an arbitrary member of a `set[str]`; that test now picks its node
  explicitly, and `test_every_catalogue_id_can_ground_a_claim_alone` pins the invariant.
  **Verification:** 494 contract+unit tests pass, and the file passes under
  `PYTHONHASHSEED` 0–7; ruff check and format clean.

## Open risks

- **All v1 GCP provenance is unrecoverable** (2026-08-17). See the salvage section for
  what survives. Do not quote the 14 artifacts, the snapshots, or the GCS copies.
- **The Gemini key is set and authenticates, but the project has no credits.** Every
  `generateContent` call returns **429 `RESOURCE_EXHAUSTED` — "Your prepayment credits are
  depleted"**. Listing models works (HTTP 200); generation does not. **P3 is blocked until
  credits are topped up**; `mock` covers tests meanwhile. Verified 2026-08-17.
- **The Gemini model list advertises models that are not callable.** `/v1beta/models`
  returns `gemini-2.5-flash`, but calling it gives **404 — "no longer available to new
  users, use models/gemini-3.6-flash"**. Anything that selects a model by reading the list
  will break at runtime. `config.resolved_llm_model` defaults to `gemini-3.1-pro-preview`,
  which is **in the list but unverified**, because a depleted-credit 429 masks a 404. T3.1
  must call the configured model once at startup rather than trust the catalogue.
- **Both API keys were pasted into a chat transcript.** Rotate after the demo.
- **The live lab is not verified.** Immutable-image, containment-admission, and harness
  code exists as of `7fce6f0`, but the active account cannot list Compute instances in
  either relevant project. No image build, VM start, or detonation was performed in the
  2026-08-25 session. Treat VPC, image, VM, and corpus runtime state as unknown until IAM
  access is restored and `make lab-status` succeeds.
- **GitHub Actions has never run on this repo** — 0 workflows registered, 0 runs ever,
  despite valid YAML on the default branch, `enabled: true`, and a non-fork repo. The API
  returns 200 with `total_count: 0`, so it is not a token-scope problem. **PRs are being
  merged on local verification**, which is weaker than the CI gate the docs assume.
- **R1 (emulator/frida)** is no longer partially retired — it is **fully open again**. v1's
  proof that the image boots with frida 16.7.19 rested on a project that no longer exists.
  The knowledge survives in `docs/CARRIED_FINDINGS.md`; the running system does not.
- **v1 H1 — no benign controls were ever detonated**, so the dynamic false-positive rate is
  unmeasured. Any claim that observed techniques *distinguish* malware from ordinary apps is
  currently unsupported. P4 must detonate benign controls.
- **v1 H2** — 9 samples executed, 7 with data. A pilot, not an evaluation. Never quote 12.
- **v1 H4** — no HTTPS interception, so Generative C2 over HTTPS is not available;
  `Cipher.doFinal` plaintext capture is a different (and defensible) claim.
- Corpus recency: only 117 samples from 2024–25 in v1's list, while the paper names 2024–25
  families as primary targets. Needs a fresh AndroZoo index and ideally MalwareBazaar labels.
- API keys were shared in plaintext and are not yet rotated.
- **Canary compile path verified locally without execution.** `canary/build.sh` keeps its
  JDK/SDK under `$DRISHTI_TOOLS`, compiles only, and produces the committed inert artifact.
  Android execution remains deferred to the sealed GCP runtime.
- ~~A formatter in the dev environment reformats `docs/*.md`~~ — **resolved.** It was
  `ruff` itself: it formats Python code blocks inside markdown, so a repo-wide
  `ruff format` rewrote the spec (~445 lines in `01_DATA_CONTRACTS.md` alone) and CI's
  `ruff format --check .` failed on it. Fixed properly by adding `*.md` to
  `[tool.ruff] extend-exclude`, so `make fmt` and CI can both run repo-wide safely.

### Deviations — 2026-08-26 (T6.10 live demo)

- **`GET /api/jobs` added to the frozen T0.6 route surface.** Purely additive: no
  existing route's path, method, or response shape changed. Needed because the demo's
  jobs are created by the phone, so the dashboard has no job id to deep-link to.
  `docs/PHASE_0_FOUNDATIONS.md` updated in the same change.
- **The Shield's block decision is not `S >= 65`.** It cannot be, while `S` is
  structurally 0 (see above). `BlockDecision` in `shield/.../Verdict.kt` falls back to
  M2 static evidence — one CRITICAL combination, or two or more HIGH — and names its
  own basis on screen. The threshold is a **policy, not a measured metric**; no
  false-positive rate has been measured for it and the UI does not claim one. When ML
  or GenAI becomes available, `S` takes the decision back with no other code change.
- **The demo emulator is a laptop-local AVD.** `CLAUDE.md`'s rule that no real APK is
  executed on a developer machine is unchanged and unbroken: the only APKs installed
  are the two this repo compiles, and the decoy is inert by construction and by a
  gate that runs on every `demo_up.sh` invocation.
- **Layer 4's receiver is registered at runtime, not from the manifest.**
  `ACTION_PACKAGE_ADDED` is not on API 26's implicit-broadcast exemption list, so the
  manifest declaration alone never fires. Found by a failed test run, not by reading.
- **`ScanEngine.settle` checks the ZIP End Of Central Directory record, not file
  size.** Size stability produced a wrong sha256 on the first run — the verdict was
  computed over bytes that were not the file, because emulated shared storage reports
  its final size before the tail is readable.
- **`demo_up.sh` clears `global device_provisioned` and `secure user_setup_complete`
  before `dpm set-device-owner`, then restores them.** Provisioning over adb is
  refused once Android marks the user set up, and after `-wipe-data` that flag flips a
  few seconds into the first boot — so success was a race the script sometimes lost.
  Two consecutive rehearsals differing only in timing produced "provisioned" and
  "NOT HELD". It now also retries 3× and **dies** rather than warning, because Layer 3
  is the beat the demo turns on; `--allow-no-owner` is the deliberate escape hatch.
- **The Shield decides on M2 static, not on M6's score, and shows the score when it
  arrives.** The block decision needs the static report; the score sits behind the
  GenAI stage. A cold free-tier LLM call measured **35 s** (`genai_static`), which put
  a third-party endpoint's latency directly into the demo's central beat — for a layer
  the scorer then excludes as partial. `ScanEngine.analyse` now runs two phases:
  decide + engage the veto on static (~5 s, and `verdictAtMs` is frozen there so the
  displayed latency never drifts upward), then attach the score. A score can raise the
  verdict; it never lowers it. This cut worst-case time-to-verdict from 41.4 s to 8.9 s.
- **The Shield's Report screen calls `GET /api/jobs/{id}/artifacts/dossier`** rather
  than composing a complaint on the phone, and renders the backend's
  `submission_is_manual`, `reportable`, `reason`, `portal_url` and `helpline` fields.
  The button says "Prepare a report for cybercrime.gov.in", never anything implying
  filing. `reportable == false` (LOW/MEDIUM) is shown with the backend's reason rather
  than hidden. An on-device fallback exists for when the endpoint is unavailable and
  the screen labels itself as such.

### Open risks — live demo

- **The GenAI provider is a free OpenRouter endpoint that returns 502 under load**
  (2 of 5 probe calls). `docs/DEMO_SCRIPT.md` §1 now instructs warming the LLM cache
  with a throwaway delivery before the demo, and §5 names
  `DRISHTI_LLM_PROVIDER=mock` as the fallback. The block decision does not depend on
  the LLM, so a 502 degrades the demo rather than breaking it.
- **Backend latency variance (6.5–13.1 s) is the largest on-stage uncertainty**, and
  it is entirely M2 static analysis. Shield contributes under 300 ms.
- **No backup video exists yet** (T6.7). The terminal fallback in `DEMO_SCRIPT.md` §5
  is rehearsed but a recording is still the right insurance.
- **Device owner provisioning is the one failure that cannot be repaired in under a
  minute mid-demo.** `demo_up.sh` prints whether it is HELD; check it every time.
- **No dynamic analysis has been run for the demo sample**, and the phone's
  limitations list — generated by the backend, not typed — says so.
