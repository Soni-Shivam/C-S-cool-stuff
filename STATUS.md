# DRISHTI — STATUS

**This file is the current state of the world.** Read it first, every session.
Update it after **every** task: task → DONE, hour, commit sha, test count.
Protocol: `docs/00_GUIDING_MAP.md` §13.

- **Started:** 2026-08-13 · **Last reconciled:** 2026-08-26
- **Integration branch:** `main` · **v1 record:** branch `v1` + tag `v1-final`
- **Phase:** Finale build · the frontier loop closes, 115 live detonations, all seven modules built. Remaining gaps are recorded under *Measured negative results* and *Still unproven*, not hidden.
- **Tests:** **1,232 contract+unit + 15 e2e, all passing** (measured 2026-08-26 at `20a76cf`)
- **Build design:** `docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md`
- **Narrative log:** see `PROGRESS.md`

---

<!-- Carried forward from origin/main at the merge. These three sections exist only
     on main; the rest of this file is the branch's newer reconciliation, which
     supersedes main's (main's header still read 468 tests and 'P4 execution half
     unbuilt'). -->

## GUI redesign + Code-Graph RAG navigation — 2026-08-26

**Merged with `claude/malicious-apk-detection-1ffa62` on 2026-08-26.** The two
branches independently reached for the same violet identity, so the merge kept the
detection branch's *functionality* whole and the redesign's *styling* throughout.
What survived from each, explicitly, because a silent drop here would be invisible:

- **Kept from detection (all of it):** the shared `Verdict` projection (A15) and
  `GET /api/jobs/{id}/verdict`, `VerdictHeadline`, `LookalikePanel` (A13),
  `DeviceFeed`, `EvidenceResolution` in the ledger view, the
  `ungrounded — not measured` factor labelling, the adversarial-elicitation panel,
  the built report / YARA / STIX / dossier exports, and `verdict.gen.ts`.
- **Kept from the redesign:** the token system, card tiers, numbered arc rail, boot
  sequence, logo-as-loader, the eight-view shell, and view 02.
- **Reconciled by hand, not by a merge tool:** `VerdictHeadline` became the hero of
  view 01 and took the primary-card treatment — but deliberately *not* the violet
  gradient, because threat score, confidence bar, provenance badge and the
  BLOCK/REVIEW/MONITOR chip are all colour-coded and a violet field fights each one.
  The detection branch's two-token accent (`accent` for type, `accent-strong` for
  shapes) was carried onto the new ramp rather than dropped.
- **A stale claim was corrected, not merged forward.** The redesign's Report lede
  said report/YARA/STIX answer 501. On this branch all four are implemented, so the
  copy now says so. Understating what exists is the same defect as overstating it.
- **The UI tests caught a contract change**: `StaticReport` gained a required
  `lookalike` field, which failed the vitest fixture at build time rather than at
  runtime.


Full visual overhaul of `ui/` onto the supplied brand (dark indigo ground, violet
bloom, three card tiers, the numbered arc rail), plus one new view. No Python
source was touched; the frozen T0.6 route surface is unchanged.

- **Design system:** tokens rewritten in `ui/src/index.css`. Card tiers are used by
  a rule — violet-gradient / lilac-wash / white for summary surfaces, dark ground
  for code, tables, the graph and the log — so the theme survives a long triage
  session. Severity colours are kept off the violet ramp (`high` is orange) so a
  band stays separable from the accent on a washed-out projector.
- **Fonts vendored, not linked.** Space Grotesk / Inter / JetBrains Mono latin
  subsets live in `ui/src/fonts/` (217 KB). A Google Fonts `<link>` would fall back
  to system sans on a projector with no network.
- **The logo is the only loading indicator.** `LogoSpinner` at four sizes replaces
  every previous spinner and bare "Loading…" string, including `ArtefactGate`'s
  pending state. `BootSequence` plays once per browser session, skips on any input,
  and collapses to one frame under `prefers-reduced-motion`.
- **New view `02 Code Graph`** — Code-Graph RAG Navigation. Every edge comes from
  `StaticReport.call_paths`; nothing is inferred. Node fill encodes retrieval
  (hollow = no body ever recovered, so ungroundable by construction), and a tool
  call can be replayed across the graph. `nodesTouchedBy` attributes a call only
  through its validated arguments or a shared evidence ref — never by fuzzy name.
- **Layout is pure and deterministic** (`ui/src/graph/layout.ts`): longest-path
  layering, fixed barycentre sweeps, stable tie-break. A force sim would settle
  differently per mount and make a graph screenshot unreproducible. A cycle-safe
  DFS marks feedback edges rather than inflating depths — that bug was found by the
  tests below, not by inspection.
- **First JS tests in the repo:** `ui/src/graph/layout.test.ts`, 14 cases, run by
  `make ui-test` (vitest, dev dependency). Justified because the only sample
  available on a developer machine is the canary, whose graph is two nodes on one
  path and exercises none of the layering, ordering or cycle handling.
- **Verification after the merge:** `npm run build` (tsc + vite) green; 14/14
  vitest; **1,232 contract+unit Python tests passing**; `ruff check` clean. Driven
  in a real headless Chrome against a live API on the canary (`job_3da6d38ccf4f`)
  at 1680×1050 — the verdict card, lookalike panel, device feed, ungrounded factor
  labels and the real rendered report were all confirmed on screen, with no page
  errors.
- **One test failed for an environmental reason and was proved to be that:**
  `test_derive_hints_finds_the_decoys_dead_beacons` needs
  `canary/decoy-challan/dist/RTO_Challan.apk`, which `*.apk` gitignores. Restoring
  the built artefact turned the run green. Anyone checking this branch out fresh
  must build the decoy (`canary/decoy-challan/build.sh`) before `make test`.
- **Not verified, and why:** no `GEMINI_API_KEY`, so the GenAI provider is `mock`
  and this run has **zero tool calls and zero interpretations**. The retrieval
  replay animation and the `interpreted` node treatment are therefore covered by
  unit tests and by the code path only — they have not been seen on real model
  output. No GCP resource was started.
- **Pre-existing, untouched:** `ruff format --check` reports drift in
  `scripts/make_report_figures.py`. That file is not modified by this work.

## The three dead branches

Recorded together because they share a shape and a fix cost, and because each is
individually easy to mistake for working code: the contract field exists, the consumer
exists, a unit test exercises the consumer with a hand-built input, and **nothing in a
real run ever sets the field.**

| Field | Set by | Consumed by | Effect today |
|---|---|---|---|
| `StaticReport.used_not_declared` | **nothing** | `m6_score/engine.py:136` — the entire `D` term | `D` = 0.000 on every sample |
| `MLPrediction.anomaly_escalate` | **nothing** | `m6_score/engine.py:98` — LOW→HIGH escalation | Zero-day escalation never fires |
| `GenAIVerdict.disagreement_flag` | **nothing** | `m6_score/engine.py:90` — confidence ×0.6 | Meta-check never fires |

Two of the four terms in `S = 0.25R + 0.50F_AI + 0.15G + 0.10D` are therefore
structurally zero in the shipped pipeline (`D` here, and `G` because no YARA ruleset is
loaded — T6.1). Figure 12 already shows this on screen with a stated reason per term,
which is the honest presentation. It is still worth knowing before a judge asks why
three of four bars are empty.

## Grand-finale priorities

Recorded here so the next session does not have to re-derive them. Full reasoning in
`docs/ROADMAP_GENAI_RE.md`; the cut order there still stands (A7 → A8 → B4 → A5, never A1).

1. **Stop the extractor VM.** One command, ~$9/day.
2. **A1 — decompilation feed (~4h, laptop-only, no GCP).** Closes the most quotable
   weakness and unblocks A2/A3/A4. Never cut.
3. **Track C, narrowed — one real detonation is worth twenty.** Write the two missing
   harness scripts, fix the four Packer paths, fix `.env`'s region, build, detonate the
   canary plus 2–3 real samples. The moment `NO TRACE` becomes a live badge once, §9's
   caveat list shrinks and the Frontier story stops being hypothetical.
4. **T6.6 demo script.** The four trust invariants each demonstrate in under a minute
   (chain verify → one-byte tamper → rejected claim → confidence 0.02 on an undetonated
   run). That sequence is the differentiator; rehearse it rather than improvising.
5. **T6.8 Q&A prep** against this file's Open risks. Every one of them is a question a
   judge can ask, and answering first is worth more than the number they were checking.

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

### ML layer — RETRAINED on the SINGLE-EPOCH corpus (T2.3–T2.7)

`docs/ML_RESULTS.md` is generated by `scripts/train_and_report.py` from the run that
produced it; no number in it is typed by hand. **Retrained 2026-08-26 at `20a76cf`** on
the re-extracted corpus. Corpus 1,564 rows, **1,537 usable**.

**The two-epoch leak is GONE, verified rather than assumed.**
`epoch_divergent_features` over the merged corpus: schema **`1.2.0` only, n=1,537,
malware 840 (rate 0.5465), divergent columns NONE**. Nothing is excluded from either
vocabulary now — **428 features**, up from 426, because `cert:validity_days` and
`cert:validity_over_20y` are re-admitted (`cert:age_days` / `cert:is_fresh` are RETIRED
and no longer emitted at all, so "four dropped" becomes "two restored, two retired").

| model | random-split PR-AUC | time-split PR-AUC | gap | CV in train |
|---|---:|---:|---:|---|
| `logreg_l2` | 0.9823 | 0.9071 | +0.0752 | 0.9662 ± 0.0239 |
| `linear_svm` | 0.9797 | 0.8834 | +0.0963 | 0.9547 ± 0.0379 |
| `random_forest` | 0.9858 | 0.8962 | +0.0896 | 0.9828 ± 0.0074 |
| **`xgboost`** | **0.9889** | **0.9169** | **+0.0720** | **0.9829 ± 0.0061** |
| `mlp` | 0.9820 | 0.8268 | +0.1552 | 0.9744 ± 0.0125 |

Splits: train 849 (468 malware) / calib 207 (122) / test 481 (250); random split n=307
(168 malware). Bootstrap intervals are in the generated doc. `xgboost` ships —
**`xgboost-428f-1.2.0`**, threshold 0.046556 (max-F1 on calib, n=207).

**THE CERTIFICATE FEATURES ARE NOW TESTED, AND THE ANSWER IS "a little, from one
column".** Refit with and without the group on identical rows and one seed, difference
bootstrapped as a PAIRED quantity on the same test split: time-split PR-AUC **0.9169
with, 0.9085 without → +0.0085, 95% [0.0033, 0.0139]**. The interval excludes zero, so
the group carries measurable signal — a small effect. Per-column permutation importance
says the whole of it is `cert:validity_days` (0.0103); `cert:brand_mismatch` and
`cert:known_bad_reuse` are **constant across every training row** and cannot carry
anything, and `cert:debug` (12 non-zero test rows) moves nothing. The defensible claim
is "certificate *validity period* contributes a little", not "the certificate features
work". Measurement: `drishti/m5_ml/ablation.py`, reported in ML_RESULTS.md §6c.

**COMPOSITE METRICS RE-MEASURED BECAUSE `G` ACQUIRED A CALLER (`1641592`).** Every
composite number predating that commit is retracted; `S` is now computed by *calling*
`m6_score.engine.score` over the test split (`drishti/m5_ml/composite.py`), never by a
local copy of the formula. Configuration is **static + ML only** — `R=0` (no intel ran,
and a VT-derived feed would be circular) and no behavioural term (nothing detonated).

| | static+ML triage, time-split test (n=481, 250 malware) |
|---|---|
| reachable ceiling | **69**, computed from the shipped weights (was 54 before `G`) |
| max `S` observed | 65 |
| MEDIUM+ (`S`>=40) | precision **0.9143**, recall **0.7680** — 210 flagged, 192 TP, 18 FP |
| HIGH+ (`S`>=65) | precision 1.0000, recall 0.0280 — over a **four-point** window, so that 1.00 describes the window, not the model |
| CRITICAL+ | **structurally unreachable** in this configuration, not "no critical samples" |

**New negative result, found only by counting `S` and the emitted band separately: the
novelty escalator promotes 93 LOW rows to HIGH without moving `S` by a point, and 84 of
the 93 are BENIGN.** That is the analyst cost of a flag already measured as
non-discriminating (this run: malware escalation 0.3560 vs benign 0.3983 — the lift is
now **negative**, −0.0423). Both histograms are published; reporting only the emitted
band would charge those 84 rows to the score, and reporting only `S` would hide them.

**Every one of the five loses ground when the test set is strictly newer than train.**
Time split n=481 (250 malware); random split n=307 (168 malware). Intervals in the doc.

**The gap remains roughly DOUBLE the 553-sample run's, and that is the more honest
number.** The old time-split test set held 57 malware rows; 250 narrows the interval and
shows a larger true cost of drift. The previous run's `random_forest` 0.9580 time-split
PR-AUC was flattered by a thin test set.

- **HISTORY — the mixed-schema leak that forced all of this (now resolved, see above).**
  Extraction ran for days and the extractor was fixed mid-batch, so the corpus was
  written by TWO schema versions: 859 rows at 1.1.0 (**67% malware**) and 678 at 1.2.0
  (**38% malware**). Freezing a vocabulary naively puts all four certificate features in
  the matrix and zero-fills whichever half is missing — which encodes *when the row was
  extracted*, a direct proxy for the label. Same class of circularity as `vt_detection`,
  through a different door. `dataset.epoch_divergent_features` found exactly those four
  and nothing else; the metrics of that era excluded them.
- **The two-epoch leak was fixed at the ROOT, not just guarded (2026-08-26,
  `3716d07`).** Dropping the four certificate features made the metrics honest but threw
  the certificate signal away. `scripts/reextract_schema.py` re-extracts the 1.1.0 rows
  from the **retained** corpus APKs (GCS, never AndroZoo — no rate limit touched; same
  parse-as-data / MAX_APK_MB / delete-immediately discipline as the extractor) and
  re-runs the CURRENT extractor over them. **COMPLETE: it identified exactly the 859
  affected rows and converted all 859** — 631 in a first pass at the 20MB cap, then the
  remaining 228 in a resumable second pass at a 70MB cap. Both passes self-verify a
  single epoch over the output: ***0 rows still carrying `cert:age_days`, 0 missing
  `cert:validity_days`***. Final tally across both passes: **0 missing from the bucket,
  0 skipped, 0 analysis failures** — every affected row was retained and re-extractable,
  which is precisely what retaining the APKs (SALVAGE.md) bought.
  Output: `features/reextracted_cert.jsonl` on the extractor VM (859 rows), keyed by
  sha256 so the merge dedups against the existing shards.
  **DONE by the ML owner at `20a76cf`:** merged, `epoch_divergent_features` re-run and
  confirmed (single epoch, divergent NONE — confirmed, not assumed), certificate columns
  re-admitted and then **measured** rather than presumed useful. See the ablation above.
- **Two new guards, tests first.** `assert_no_retired_features` refuses a vocabulary
  listing a name the current extractor cannot emit (the defect that forced this retrain,
  and silent by construction — `project` zero-fills a missing feature, so a stale vocab
  yields a full-width vector and a weight applied to a permanent zero, with nothing
  raised). `epoch_divergent_features` measures per-epoch presence rates. +8 unit tests.
- **Selection never touched the test set.** Winner is the highest 5-fold CV PR-AUC
  *inside train* (`xgboost`, 0.9829 ± 0.0061).
- **`vt_detection` cannot become a feature.** `dataset.assert_no_label_leak` unchanged.
- **Calibration.** 122 calib positives clears the isotonic floor, so **isotonic** over
  Platt, chosen by cross-validated Brier *within* calib. Test Brier 0.1863 → 0.1139;
  **ECE 0.2239 → 0.0368** (−83.6%). T2.4's bucket check **passes and is informative**:
  79.6% of the 49 test samples in the 0.75–0.85 band were malware against an expected
  80% — the closest that check has come to its nominal rate.
- **Shipped `model_version`: `xgboost-428f-1.2.0`**, vocabulary 428 features, operating
  threshold 0.046556 (max-F1 on calib, n=207). `models/*` is gitignored.
- **The novelty escalator got WORSE and is stated in the generated doc, not buried.**
  Its lift is now **NEGATIVE**: malware escalation 0.3560 against benign 0.3983, so it
  fires slightly *more* on clean apps than on malware. No novelty-detection claim may be
  made from this run, and §6d prices its 84 benign LOW→HIGH promotions in rows.
- **Still rising, barely.** §6b learning curve: 106 → 849 training rows moved time-split
  PR-AUC 0.8285 → 0.9093, but the last two points (637→849 rows) moved it +0.0004. The
  curve has essentially flattened on this corpus, so more extraction of the same kind
  would buy little — a change from the previous run's reading, and the argument for
  widening the corpus rather than deepening it.

### GenAI RE pipeline — measured (RAG ratio, budgets, timing, injection posture)

`scripts/measure_rag_and_timing.py` writes `docs/figures/rag_and_timing.json`.

- **Budgets hold:** 2 LLM calls of 25 allowed; largest single prompt **2,161 tokens of
  12,000**. Caveat: these samples do not stress the cap, so this shows the accounting is
  wired up, not that the limit binds under load.
- **Fast path: 2.95 s of local compute** (median of 3 runs × 3 samples), 94% of it M2
  static. Everything else — ingest, 428-dim extraction, prompt assembly, the whole scorer
  — is under 80 ms combined. That runs against the **mock** provider. Against the 17 real
  logged LLM calls (median **15.5 s**, range 6.8–58.7 s, free-tier endpoint) the live
  fast path is **~18.5 s**, a sum of two measurements and labelled as such.
- **The paper's 6.3 s walk is NOT traceable** to any record in this repo (not docs/, not
  STATUS.md, not v1-reference/), and its 340-dim vector matches no shipped vocabulary.
  Flagged in `main.tex` rather than guessed; must be re-run on the extractor VM.
- **THE RAG SELECTION RATIO CANNOT BE MEASURED ON THIS LAPTOP.** Corpus APKs may not be
  copied here, and the only local samples are inert by construction because the same
  rules forbid writing real payloads. The decoy declares the full trojan permission set
  and component structure but **M2 recovers ZERO call paths from it** — its one matched
  sink, `Method;->invoke`, is reached only from Kotlin stdlib internals and from no
  lifecycle entrypoint. The backward walk is not failing; it has nothing to walk. On the
  canary, which has one real reachable chain, the mechanism measures end to end: **1
  method selected of 6,790**, rendering a **1,282-token workspace** against a 5,000-token
  retrieval budget. That demonstrates the mechanism; it is **not** the pitch number.
  **→ To get the pitch number, run this script on the extractor VM.**
- **Anti-injection posture verified on the decoy.** System prompt 2,279 chars with
  **zero** sample-derived tokens (no permission, component name or package leaked into
  it). All sample content arrives in the USER turn inside balanced `<untrusted_artifact>`
  blocks, HTML-escaped: zero raw `<`, zero unescaped `&`. A forged
  `</untrusted_artifact>` in a string constant is escaped to `&lt;/untrusted_artifact&gt;`
  and cannot terminate the block.
- **Victim profile is PARTIALLY populated** on the decoy (mock provider):
  `impersonated_target='e-Challan (traffic penalty)'` is deterministic and cited to an
  evidence node — good, the demo's key sentence survives without the LLM. But
  `language`, `script`, `tactic` and `segment` are all **None**; the verifier dropped the
  model's tactic/segment reading because it cited no resolvable node. Needs a re-check
  against the **live** provider. Separately, the lookalike detector does find
  `com.sbi.lotusintouch`, `com.phonepe.app` and `net.one97.paytm` in the decoy's
  financial roster, so an "impersonating SBI"-style line has real backing.
- **Behaviour keys are 16 and load-bearing** (`BEHAVIOUR_WEIGHTS` is the whole of `B`).
  Mapping to the consumer projection's 8: `reads_sms_content`→`reads_sms`,
  `exfiltrates_over_network`→`exfiltrates_data`, `abuses_accessibility_service`→
  `abuses_accessibility`, `hides_or_disables_its_own_icon`→`hides_icon`,
  `loads_dex_at_runtime`→`loads_code_at_runtime`; `overlays_other_apps`,
  `monitors_clipboard`, `encrypts_data_before_sending` match exactly. **Eight have no
  consumer sentence**, including `impersonates_a_known_brand`, which is the one most
  relevant to the impersonation line.

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

### Known blocker — the paper does not compile

`REPORT/main.tex` **produces no PDF**, and it did not before this session's edits either
— confirmed by compiling the committed baseline. Partially fixed, honestly recorded
rather than left to be discovered at submission.

| | Before | Now |
|---|---|---|
| `Option clash for package xcolor` | fatal, no output | **fixed** — `\PassOptionsToPackage` before `\documentclass`, because `SelfArx.cls:40` already loads xcolor bare |
| `Undefined control sequence` ×2 (`\@Keywords`, `\keywordname`) | present | **fixed** — `\Keywords{}` was commented out while the class references it unconditionally |
| `There's no line here to end` | present | **still present** |

The remaining error is inside the class's `\maketitle` abstract/keyword box. Replacing
the `\\` breaks with `\par` in `selfArx.cls` did not clear it, so that experiment was
reverted rather than left as unexplained churn. Someone with a clean hour should bisect
`\maketitle`; the content is correct and only the title block is at fault.

---

### The novelty escalator was blocking benign apps — 2026-08-26

Found by measuring the shipped model rather than by reading the code, and it reached
the consumer screen.

`anomaly_escalate` promoted a LOW band straight to **HIGH**. `contracts/verdict.py` maps
HIGH into `_BLOCK_BANDS`, which the consumer surface renders as **DO NOT INSTALL**. So a
signal intended to mean "a human should look at this" was issuing an accusation.

Measured on the shipped run: **93 LOW rows promoted without `S` moving a single point,
and 84 of them BENIGN.** On the same run the detector's own lift was **negative** —
anomaly 0.3560 for malware against **0.3983 for benign** — so it was ranking clean apps
as the more unusual ones and then blocking them. That is precisely the "do you just flag
everything?" failure, live in the demo path.

Fixed: the escalator now promotes **LOW → MEDIUM**, which maps to `REVIEW`. The paper's
stated intent is preserved — a zero-day still cannot land quietly in LOW, and
`requires_human_review` is what actually carries that intent. Two tests pin it: the
escalator can never reach a band in `_BLOCK_BANDS`, and it can never demote a verdict
that earned HIGH on real evidence.

The detector itself is **not** vindicated by this fix. Its lift is negative on this
corpus and it remains a candidate for removal; escalating to REVIEW bounds the damage,
it does not make the signal good.

### Model bundle — GCS was serving the leaky model — 2026-08-26

`gs://cybershield-505518-models/` held **`random_forest-504f-1.1.0`**: trained on the
two-epoch corpus, on the retired feature schema, and no longer the model the paper cites.
`models/` is gitignored, so shared storage was the only copy and it was the wrong one.

Replaced with **`xgboost-428f-1.2.0`** (schema 1.2.0, single-epoch corpus). The previous
bundle is archived at `gs://cybershield-505518-models/archive-random_forest-504f-1.1.0/`
rather than deleted — a superseded model is provenance, not garbage.

---

### Measured negative results — 2026-08-26

Recorded prominently because a negative result nobody can find is a claim waiting to be
made again by accident.

**The novelty escalator's lift is now NEGATIVE, and it costs 84 benign HIGH promotions.**
Measured on the time-split test set (n=481, 250 malware) at `20a76cf`.

| | Result |
|---|---|
| malware escalation rate | **0.3560** |
| benign escalation rate | **0.3983** |
| lift | **−0.0423** — it fires slightly MORE on clean apps |
| LOW→HIGH promotions | **93**, of which **84 benign** and 9 malware |
| Measurement | `docs/figures/ml_metrics.json` (`anomaly`, `composite.escalation`) |

The previous run read +0.0144, which was already "not carrying weight"; on the
single-epoch corpus it is on the wrong side of zero. It is still shipped because it is an
**escalator that never moves `S`** — but it is not evidence, and the 84 benign rows it
pushes into HIGH are a real analyst cost that is now priced in rows rather than rates. It
was invisible until `S` and the emitted band were counted separately (`ML_RESULTS.md`
§6d): the band histogram and the `S` histogram legitimately disagree, and reporting only
one of them hides either the escalator's cost or the scorer's ceiling.

**"The certificate features work" is NOT a supportable claim.** With the two-epoch leak
gone the group is finally evaluable, and the measured answer is +0.0085 time-split PR-AUC
(paired 95% [0.0033, 0.0139]) — real, but small, and entirely attributable to
`cert:validity_days`. `cert:brand_mismatch` and `cert:known_bad_reuse` are **constant
across all 849 training rows** and cannot carry signal at all. Measurement:
`ML_RESULTS.md` §6c.

**The benign-lookalike discriminator does NOT discriminate. It is not a scoring signal.**
Measured on **n=75** real corpus APKs (35 family-tagged banking trojans — Cerberus, Octo,
TeaBot, Coper, Hydra, Ermac, Hook, Alien, BankBot, Joker, SpyNote — against 40 benign).

| | Result |
|---|---|
| mean `trojan_score` | malware **0.050** (max 0.312) vs benign **0.009** (max 0.125) |
| rank-AUC | **0.621** |
| `TROJAN_SHAPE` verdicts | **0 of 35 malware, 0 of 40 benign** |
| Measurement | `data/measurements/lookalike_validation_n75.json` |

Structural cause, not a bad threshold: four of the eight signals need call-graph
reachability and carry 0.85 of the 1.60 total weight, so the ceiling from strings alone
is 0.4688 — below the 0.50 threshold *by construction*. Those four barely fire because
2024-25 trojans ship **packed**: androguard recovered a median of **12** decompiled
methods per sample. Firing rates: `overlay_after_package_enumeration` 17% malware / 5%
benign, `financial_app_roster` 3% / 0%, `sms_and_network_share_entrypoint` 0% / 0%.

It never fed `S` or the ML feature vector, so nothing was cut from scoring — but the
**claim** was corrected in `docs/DEMO_AND_MOAT.md`. The idea is sound and demonstrable on
unpacked code (`tests/unit/test_lookalike.py` shows two apps with identical permissions
and opposite verdicts); what it demonstrates on real samples is **the ceiling on static
intent analysis**, which is the argument for detonating instead. Do not retune to
manufacture separation on that set.

One thing it did fix: certificate `not_before` parsed on **75/75**, and
`freshly_minted_certificate` — which previously fired on 100% of samples including every
benign one — now fires on **0%** of both.

**The morph-then-wake capture was attempted and REFUTED by its own control.** BankBot
`8166dfba` looked like a clean wake (pass 1 failed with 0 observations, pass 2 morphed
completed with 4). A 3-run unmorphed control showed the sample completes with the same 4
observations *without* any morph, so the pass-1 failure was a Frida cold-start spawn
flake, not evasion. Not claimed. The 5 Frida morph scripts the applicator referenced did
not previously exist and were written; the infrastructure is proven and one command from
a real capture, but the banking trojans available mostly detonate passively, so no sample
with a genuine checkable environment gate has been found yet.

---

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
- **DETONATION CORPUS GREW TO 115 live runs (2026-08-26).** A 62-sample batch of
  MalwareBazaar family-tagged **banking trojans** (Coper, SpyNote, Hydra, Ermac,
  Cerberus, BankBot, Alien, Hook, Octo, TeaBot, Joker) was staged and detonated on the
  sealed VM, every one `simulated:false`, per-sample containment re-verified. **50
  completed with observations, 2018 total observations, 45 with ≥3 events.** Family
  highlights: Joker 245 obs, Octo 39–51, BankBot up to 58, Ermac 26–31, Coper 19–29,
  TeaBot/Hook 18–22. 63 failed (26 `install_unsupported` = ARM-only ABI, the known x86
  tooling limit; 35 `internal_error` = sample self-exited/crashed under Frida; 2
  `install_failed`). Containment gate is now also a standalone demo: `make
  demo-containment` (`0422fb9`) accepts a sealed net and rejects the v1 `nc -z` probe.
- **RAG selection ratio MEASURED on real banking trojans** (`2c681de`,
  `data/measurements/rag_selection_ratio.json`). The REPORT §4.2.2 headline — "we never
  send the whole app" — measured on 11 MalwareBazaar-tagged trojans on the extractor VM
  (the only place a corpus APK legally lives; the inert decoy has zero reachable sinks).
  The backward walk selects **4–9 methods regardless of app size** (117 to 48,449 internal
  methods), holding the workspace to **689–4832 tokens against the 12,000 prompt budget**.
  Largest sample (Hydra, 48,449 methods) → 8 methods, 0.017%, 4758 tokens. Far stronger
  than the canary's 1/6790. The ≤12k prompt budget holds with ≥60% headroom on every
  sample; the ≤25-call budget was not re-measured here (the VM checkout predates the
  controller `apk_path` signature) but is unchanged in code.
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

- **The lookalike discriminator's real-sample performance — MEASURED 2026-08-26, and it
  does NOT discriminate at the operating threshold.** Validation over **75 real corpus
  APKs** (35 malware / 40 benign; run at `e9f3d9e`, measurement
  `data/measurements/lookalike_validation_n75.json`, malware = MalwareBazaar family-tagged
  banking trojans — Cerberus, Octo, TeaBot, Coper, Hydra, Ermac, Hook, Alien, BankBot,
  Joker, SpyNote):
    - mean `trojan_score`: **malware 0.050** (min 0, max 0.312) vs **benign 0.009** (min 0,
      max 0.125). rank-AUC **0.621** — weak ordering, well short of usable.
    - **TROJAN_SHAPE verdicts: 0 benign AND 0 malware.** Zero false positives (the
      product-killer we feared) — but also zero true positives. `TROJAN_SHAPE_THRESHOLD`
      is 0.50 and the top malware score observed was 0.312.
    - **Structural root cause:** the four call-graph-reachability signals carry 0.85 of
      the 1.60 total weight, so the max score reachable *without* any of them is
      0.75/1.60 = **0.4688 < 0.50 — the threshold is unreachable from strings alone.**
      Those reachability signals almost never fire because these recent trojans are
      **packed**: androguard recovered a *median of 12 decompiled methods* per sample.
      The behaviour the discriminator keys on is not present in the static image; it is
      exactly what M3 detonation exists to observe.
    - The `e9f3d9e` fix worked as intended: certificate `not_before` parsed on **75/75**,
      and `freshly_minted_certificate` now fires on **0%** of both classes (it was the
      false universal-firing signal before). `package_strings` non-empty on 70/75.
    - **Recommendation: do NOT ship as a scoring signal.** Per the evaluation rules I did
      not tune the threshold or weights to manufacture a gap. It may survive as an
      explanatory/UI overlay only. Owner decision required.
- **Generative C2 emulation** remains designed, not built, and is bounded by CLAUDE.md's
  hard boundary — a PoC is only legitimate if the synthesised response is provably inert.
- **Environment morph → re-detonation (the D3 "sandbox-aware sample" demo)**: the morph
  *proposals* and the applicator are built and unit-tested. The **Frida morph scripts
  themselves** (`build_props`, `sim_locale`, `install_packages`, `clock_skew`,
  `files_present`) were missing entirely — they landed 2026-08-26; `detonator_run.sh
  morph` and `compose_hooks` were wired to a directory that did not exist. The scripts
  landed and were deployed to the detonator, and the before/after harness works end to
  end. Content-provider kinds (sms_history/contacts/accounts) are deliberately unshipped —
  an absent script is refused, which is honest; a stub would claim a morph it did not
  apply.
  **A clean morph-then-wake was ATTEMPTED but NOT captured (2026-08-26), and the negative
  is instructive.** Five real stall candidates were morphed (build_props+sim_locale+
  files_present [+install_packages]). Four AndroZoo quiet samples did not wake: two query
  their OWN package (a repackaging/integrity check no environment morph addresses), two
  crash at Frida instrumentation regardless. One banking trojan (BankBot `8166dfba`,
  x86 ABI) *looked* like the money shot — pass-1 `failed`/0 obs → pass-2 morphed
  `completed`/4 obs (T1417 overlay, T1418 package discovery). **A three-run UNMORPHED
  control refuted it: the sample completes with the same 4 observations unmorphed**, so
  the pass-1 failure was a Frida cold-start spawn flake (the documented issue, runbook
  §0.0), not sandbox evasion the morph unlocked. Claiming it would have been dishonest;
  the control is exactly why it is not claimed. Infrastructure is proven and one command
  from a real capture; what is missing is a corpus sample with a genuine, checkable
  environment gate — the banking trojans available mostly detonate passively already.
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

- [x] T4.1 Emulator control                        DONE  2026-08-26  8f0dfdf · 115 live detonations on the sealed m3-detonator
- [x] T4.2 Frida runner                            DONE  2026-08-26  8f0dfdf · 12 hook classes; 2,019 observations captured
- [~] T4.3 Crash recovery & self-repair            WIP   2026-08-26 · snapshot restore works; the LLM self-repair-from-tombstone loop is NOT built
- [ ] T4.4 TLS interception & network capture      DEFERRED — deliberate, see Decisions. mitmproxy is in the image but never runs;
      `tls_intercepted` is never set true. `Cipher.doFinal` yields plaintext BEFORE encryption, which is
      strictly stronger and also defeats custom crypto (T1521). State it as a choice, not a gap.
- [x] T4.5 Evasion observation detection           DONE  2026-08-26 · drishti/m3_dynamic/evasion.py, 161 lines
- [x] T4.6 Trace normalisation                     DONE  2026-08-26 · 1,925 raw events → 40 groups; `b_dynamic` provably unchanged
- [x] T4.7 TRIPWIRE @ H40                          PASSED — live detonation achieved, so the fallback was never needed
- [x] T4.8 Sandbox plan builder                    DONE  2026-08-26 · SandboxPlan built and consumed by both sandbox passes
- [x] T4.9 Live detonation wired into the pipeline DONE  2026-08-26 · `LiveSandboxSource` implemented; see below

### T4.9 — the execution path is wired, not just the analysis path — 2026-08-26

The paper (§13.2 Table 12, §15.3, §17 Table 18) records M3 as *partially* built: the
analysis layer — trace normalisation, rule-11 aggregation, evasion detection, the
containment probe — was built and tested, while the **execution path was not reachable
from the pipeline**. That was accurate. `LiveSandboxSource.available()` returned a
hardcoded `False` with the comment "P0: the lab is not built", and `.run()` raised
"not implemented until P4". The 115 detonations that did happen were driven by hand,
one `detonator_run.sh` invocation at a time, and their output reached the product only
if somebody remembered to run `scripts/observation_to_trace.py` afterwards.

So the dynamic layer could never fire for a sample a user actually uploaded. What was
built:

- **`drishti/m3_dynamic/ingest.py`** — `artifact_to_trace()`, the single
  `ObservationArtifact` → `DynamicTrace` conversion. It previously existed only inside
  `scripts/observation_to_trace.py`, so the offline fixture path and any future live
  path would have been two implementations of one conversion. The script is now a CLI
  over the module and `tests/contract/test_observation_ingest_parity.py` holds them
  together — the M3 analogue of `test_feature_parity.py`.
- **`drishti/m3_dynamic/detonator.py`** — `RemoteDetonatorClient`, the runbook's
  stage → detonate → collect sequence over IAP, with the retry loop the runbook asks
  for. No local branch exists: CLAUDE.md's rule is enforced by the structure rather
  than by a comment.
- **`LiveSandboxSource`** — real health probe (VM `RUNNING`, never *started* as a side
  effect of a job) and a real run path. Two gates abort rather than warn: containment
  not verified, and `safe_for_ingestion` false.
- **Evasion observations now survive conversion.** The old converter dropped them, so
  every captured fixture replayed as a sample that never probed its environment and the
  frontier could not fire on real data. 10 of 51 captured runs carry a probe→stall
  pattern; those now reach `_frontier`.

**A protocol bug was caught before it cost a VM start.** The first client was written
to send `detonate --sha256 X --serial Y --duration N --morphs <json>`. The script takes
`detonate <sha> [duration]` positionally and puts pass 2 behind a *separate* `morph
<sha> <kinds> [duration]` subcommand writing `<sha>.morph.json`. `MorphKind` also
enumerates nine kinds while only five have Frida scripts; the VM answers rc 5 for the
rest. `tests/unit/test_detonator_client.py` now asserts the command surface against
`infra/gcp/detonator_run.sh` itself.

**Fixture backfill.** 117 captured artifacts existed; 51 carry observations; only 25
had ever been converted. All 51 are now committed as replayable `TraceFixture`s, so
replay covers the real corpus instead of a quarter of it.

**Structured evidence is no longer dropped in conversion.** `ObservationEvent` is flat
— technique, mitre, hook, one redacted `detail` string — so the dropped-dex path, the C2
URL and the pre-encryption plaintext all arrive as prose. The old converter kept none of
it, which is why the Sandbox tab reported `0 network flows · 0 dex loads · 0 decrypted
blobs` for samples that had genuinely produced them. Measured over the 51 captured runs:

| Lifted | Count | Note |
|---|---|---|
| `dex_loads` | 11 | all from runtime-written paths (`/data/user/…/cache`, `app_DynamicOptDex`) |
| `network_flows` | 17 | across 13 distinct hosts |
| `decrypted_blobs` | 18 | `Cipher.doFinal` plaintext, captured before encryption |

Parsing is anchored on the hook's own marker and refuses to guess: a detail with no
`path=` yields no `DexLoadEvent` at all, rather than one with an invented verdict.
`in_original_apk` is **derived from the path** rather than defaulted, because it is the
strongest single input to `D` and the default (`False`) is the accusatory value — a
split APK loading its own `base.apk!/classes.dex` must not be called a dropper.

**This partially un-deadens `D`.** 11 of the 51 captured samples load dex from a
runtime-written path, so `D` is now reachable for real traces instead of being
structurally zero. It remains zero for static-only jobs, and `StaticReport.used_not_declared`
is still never populated by M2 — that half of `D` is untouched and still a real gap.

**Still not done, explicitly:** no live detonation has been run through this path. The
`m3-detonator` VM is `TERMINATED` and `DRISHTI_GCP_PROJECT` is unset in `.env`, so
`auto` resolves to replay. The code is exercised against a fake detonator, not a real
one — `tests/lab/` is where a live-marked test belongs and none has been written yet.
Until that runs, T4.9 is "wired and unit-tested", not "proven live".

## P5 — FRONTIER (H44→H58)

- [x] T5.1 Morph applicator                        DONE  2026-08-26 · 5 Frida morph scripts: build_props, sim_locale,
      install_packages, clock_skew, files_present
- [x] T5.2 Morph validation                        DONE  2026-08-26 · `validate_morph()` runs before adb or JS; params are
      injected as JSON literals, never string-concatenated
- [x] T5.3 Adversarial Elicitor agent              DONE  2026-08-26 · 238 lines; structured input only, so no raw sample string
      reaches the prompt
- [x] T5.4 Generative C2 emulation                 DONE  2026-08-26 · 717 lines, with a provable inertness gate
- [x] T5.5 Frontier orchestration loop             DONE  2026-08-26  8f0dfdf · **the loop now closes.** Wiring the call site alone
      was not enough: nothing wrote EVASION_CHECK nodes, so every proposed morph was
      silently dropped as ungrounded. Verified — a morph's `derived_from` resolves to a
      real evasion_check node.
- [x] T5.6 Replay-mode frontier                    DONE  2026-08-26 · 117 replayable fixtures, all `simulated=False`
- [x] T5.7 Frontier UI panel                       DONE  2026-08-26 · ui/src/tabs/FrontierTab.tsx, 227 lines

## P6 — REPORT / UI / DEMO (H50→H72)

- [x] T6.1 YARA generation                         DONE  2026-08-26 · `drishti/m7_report/yara.py`. Keys on repack-resistant
      artefacts; the hash is metadata, never a condition. Emits itself DISABLED with the reason below three
      distinctive strings. `test_yara_rule_does_not_key_on_the_hash` pins it.
- [x] T6.2 STIX 2.1 export                         DONE  2026-08-26 · UUIDv5 over stable keys, so two exports of a job are
      byte-identical and the scorer's determinism is not undone one layer up. Publishes only VERIFIED claims and
      OBSERVED flows — never `synthesised` ones, which came from our own Generative C2.
- [x] T6.3 HTML report                             DONE  2026-08-26 · self-contained, no external assets. Limitations are
      DERIVED from provenance flags; a sample that produced no runtime behaviour renders INCONCLUSIVE, never benign.
- [x] T6.10 Reporting dossier (A12)                DONE  2026-08-26 · `submission_is_manual` is always true — NCRP has no
      public submission API and nothing here files anything. `reportable` is gated on band.
- [x] T6.11 Case-file archive (A20)                DONE  2026-08-27 · `GET /api/jobs/{id}/artifacts/bundle.zip` +
      `drishti/m7_report/case_file.py`. One download holding report.html, the complaint package, YARA, STIX,
      the ledger export and the verdict, assembled **server-side from the same bytes the single-file routes
      serve** — the browser does not re-zip five fetches, so what is kept is what was analysed.
      `MANIFEST.json` carries a SHA-256 and size per entry, the chain verification as read at build time, and
      an `omitted` map naming any export that raised together with its reason: a short archive and a complete
      one are otherwise indistinguishable. Entry mtimes are pinned to the zip epoch, so identical inputs give
      identical bytes. **The sample is never in the archive** — `test_bundle_never_carries_the_sample` is the
      guard. Route added to the frozen surface in `docs/PHASE_0_FOUNDATIONS.md` T0.6 and
      `tests/contract/test_api_surface.py` before the implementation. 9 new tests in
      `tests/unit/test_case_file.py`; measured on this commit (rebased onto `origin/main` at `4036a34`):
      suite **1,664 contract+unit** (1,655 before), `pytest tests/contract tests/unit -q` → exit 0;
      `npm run build` and `npm test` (34) green. Two lint failures are **pre-existing on `origin/main`**
      and touch no file changed here: `ruff check` reports N806 in
      `tests/unit/test_behavioural_risk_context.py:98`, and `ruff format --check` wants
      `canary/decoy-challan/tools/make_launcher_icon.py`, `scripts/validate_lookalike.py`,
      `tests/unit/test_llm_retry_after.py`, `tests/unit/test_score_engine.py` and
      `tests/unit/test_score_fusion_logodds.py` reformatted. `make lint` is therefore red on `main`
      independently of this change.
- [~] T6.4 Dashboard completion                    WIP   2026-08-26  dea2ee9 · seven views render live; the shared Verdict and the honesty affordances landed
      Every panel is wired to a real endpoint and renders only what the API sent.
      **The three "renders its 501" caveats above this line were stale** — report.html,
      YARA and STIX all return 200 and are rendered and downloadable, and the A12
      complaint package is now on screen too. What remains is the dev-only **tamper
      demo**, which is deliberately unbuilt — see Deviations.

      Landed 2026-08-26 (`1203ee0`, `dea2ee9`):
      * `GET /api/jobs/{job_id}/verdict` — the A15 projection, one call to
        `build_verdict()`. Documented as A16 (contract **1.7.0**) and frozen in
        `tests/contract/test_api_surface.py`.
      * The dashboard's `Verdict` TypeScript is **generated** from the pydantic model
        by `ui/scripts/gen_verdict_types.py`; a contract test fails when it drifts.
      * Provenance badge reads `verdict.provenance` only — STATIC_ONLY draws as red
        NO TRACE. Confidence sits beside the score. Ungrounded score terms are
        labelled "ungrounded — not measured" instead of a bare zero (paper §20.1);
        on a static-only run that is R and G.
      * Fixed: `artefact()` parsed text/html and text/plain as JSON, so the report
        and the YARA rule rendered as empty and as the word "null".
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

### Demo rehearsal, re-measured 2026-08-26 at `67a197a`

Rehearsed cold, end to end, eight times. Numbers below supersede the two rows above
that they overlap; the rest of the table still stands.

| Measurement | Value |
|---|---|
| `demo_up.sh` cold to ready (AVD exists, quick-boot snapshot, nothing running) | **31.5 s** |
| `demo_up.sh` warm (emulator already up) | 9–12 s |
| **File landing → verdict, cleared app** | **4411 / 4724 / 5320 / 5682 / 5696 ms** |
| **File landing → verdict, blocked app** | **4368 / 4813 / 4878 / 5156 / 5519 ms** |
| Full `demo_run.sh --fast`, both beats | 30.9 / 37.3 / 40.4 / 40.4 s |
| Tests | 880 contract+unit passing at `67a197a` |

**Four silent failures found and fixed.** Each announced success and did something
else, which is the only failure mode that matters on stage:

1. **The Layer 3 veto had stopped working and setup still said "HELD".** `adb install
   -r` drops the *active admin* record while the *device owner* record survives, so
   `dpm list-owners` kept reporting DeviceOwner while every `addUserRestriction` threw
   `SecurityException: Admin … does not exist or is not owned by uid`. Measured:
   `block=true veto=false`, `Device policy restrictions: none`. Fixed by
   `dpm set-active-admin` each run plus a **self-test that engages the veto, reads the
   restriction back from `UserManager`, and releases it** before the demo is handed
   over. Setup now dies if the veto cannot be proved.
2. **`adb logcat -d -t N` returns ZERO Shield lines on a cold boot** — the boot flood
   pushes them past the tail window. Measured: 0 lines via `-t 400`, all of them via
   `-s DrishtiShield:I`. This is how verdict *latency* is read, so a cold emulator
   would have reported "no verdict line" while the demo worked perfectly.
3. **`am start --ez` silently drops the extra** to a stale top-most instance after
   `install -r`, and to a task "brought to the front" after a force-stop. The demo
   reset had been doing nothing. Fixed with `-f 0x10008000` (`NEW_TASK|CLEAR_TASK`).
4. **Beat 1b passed without proving anything** — it inferred "Android shows its
   install prompt" from the absence of an admin dialog, but `InstallStart` finishes
   silently on a `file://` URI when there is nothing to block.

**Correction to the veto note below:** `adb install` succeeding is *expected* and is
**not** evidence against the veto — shell uid is a privileged installer and exempt.
The user-facing package-installer path is the only honest test. Do not let anyone
demo the veto with `adb install`.

**The good-app/bad-app pair works back to back** and is the headline beat.
`canary/benign-sanchay/` declares the identical five dual-use permissions as the decoy
and is cleared (`block=false basis=CLEAR`), installs untouched, and Layer 4 does not
quarantine it; the decoy is blocked by the OS's own
`ActionDisabledByAdminDialog`. `scripts/demo_run.sh` runs both in the only order that
works — cleared first, because the veto is device-wide.

**The decoy now ships a raster launcher icon** (`res/mipmap-xxxhdpi/ic_launcher.png`,
generated by `canary/decoy-challan/tools/make_launcher_icon.py`), because
`m4_genai/vision.py` needs a PNG and a vector drawable compiles to XML — extraction
returned `None` before, a 192×192 image now. **`assess_icon()` still has no caller in
the pipeline**, so icon impersonation is not part of the scripted demo. The VLM scored
the shipped icon 0.55–0.92 on identical pixels across five calls (threshold 0.80), so
no fixed confidence may be quoted.

### Deviations

- **`shield/**` and `ui/**` handed off mid-task.** The demo workstream was split and
  dedicated consumer-UI and analyst-portal agents took those trees. The Layer 3 veto
  repair and self-test (`PolicyEngine.releaseAllQuarantines`,
  `MainActivity.handleVetoSelfTest`) were committed at `bd3ea8a` before handing over;
  everything else uncommitted under those paths belongs to the new owners.
- **`demo_up.sh` no longer dies on a dashboard build failure.** It serves the previous
  `ui/dist` with a loud warning instead. Reason: a TypeScript error in another
  workstream's in-flight edit took the entire stage down, and the phone, the four
  layers and the veto do not depend on the dashboard compiling.
- **Two agents shared one emulator during rehearsal**, which caused one failed run
  (Shield reinstalled mid-scan) and a decoy that reinstalls itself seconds after the
  reset clears it. Before a real take, confirm nobody else is driving `emulator-5554`.

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

---

### Deviations — 2026-08-26 (repo-invariant + clean-clone test suite)

- **`models/*.pkl` is now an explicit exception in `test_no_forbidden_artifacts_tracked`,
  not an invariant violation.** `fa04cdf` committed the trained classifier, calibrator
  and anomaly bundles (`.gitignore` already allowlists them by name); the invariant
  still failed because its allowlist was `canary/` only. Reason: a trained model is
  neither a sample nor key material — it executes nothing and leaks no secret — and
  the H7 concern it was written for (v1 shipping a *synthetic* model as real) is a
  provenance question answered by `models/model_card.json` and the metrics in this
  file, not by whether the bytes are in git. `gs://<proj>-models/`
  (`DRISHTI_GCS_MODELS_BUCKET`) stays the runtime source of truth; the committed
  copies exist so a paper reviewer can reproduce inference without GCP credentials.
  The exception is scoped to `.pkl`/`.joblib` **under `models/`** — an `.apk`, `.dex`,
  `.pem`, `.p12` or `.jks` dropped there is still an offender, and
  `test_the_models_exception_is_narrow` proves it.
- **`test_derive_hints_finds_the_decoys_dead_beacons` skips on a clean clone instead of
  failing.** It reads `canary/decoy-challan/dist/RTO_Challan.apk`, a deliberately
  gitignored build artifact (only `canary/dist/` is committed). Building it needs the
  JDK/Android SDK/Gradle toolchain that `canary/decoy-challan/build.sh` downloads —
  not hermetic enough for a fixture — so the test now `pytest.skip`s with the build
  command named. It skips visibly; it never silently passes.

### The Groq free tier is the binding constraint on M4 — measured 2026-08-26

The code interpreter reported `0 methods interpreted · 0 retrieval tool calls` on every
run, and the dashboard rendered that as though the model had *chosen* not to use its
tools. It had not. Four separate defects were stacked on top of one real quota limit.

**The limit, in the provider's own words** (captured by running the real pipeline over a
corpus sample, not inferred):

    round 0   "Rate limit reached ... on tokens per minute (TPM): Limit 8000,
               Used 4932, Requested 5584. Please try again in 18.87s."
    round 1   "Request too large ... Limit 8000, Requested 8528, please reduce your
               message size and try again."

**8,000 TPM, and the reserved `max_tokens` counts toward it.** The behaviour checklist
costs ~4,900 and the interpreter's round 0 ~5,300, so the two stages cannot both run
inside one minute. A 5,300-token prompt reserving 3,000 output is an 8,300-token request
and is refused outright — which is why round 1, *the round that carries the tool results
back and produces the interpretations*, never completed.

What was wrong in our code, each fixed with a test:

1. **413 was not retryable.** `_exchange_with_retry` re-raised on the first attempt, the
   tool loop returned None, `_guarded` swallowed it. One quota blip cost the job its
   whole RE stage.
2. **The two 413s need opposite handling and the status cannot tell them apart.** A
   rolling-window limit says "try again in Ns" and is worth waiting for; an oversized
   request says "reduce your message size" and can never succeed. Retrying the second
   burned 38s per job to reach the identical failure; it now fails in **171ms**.
3. **Our backoff was 1s+2s against a requested 18.87s.** Retrying sooner than the
   provider asked is arithmetically the same as not retrying. `retry_delay_from()` now
   honours the stated delay, capped at 30s so a hostile value cannot hang a demo.
4. **The provider's explanation was discarded.** `raise_for_status()` yields "Client
   error '413 Payload Too Large'" and throws away the body — which is where Groq says
   *why*. This cost about an hour of misdiagnosis; `_explain()` now includes it.

Sizing, now derived rather than guessed. `Settings.llm_max_request_tokens` (default 8,000)
records the provider ceiling; the interpreter reserves output from it, `MAX_TOOL_RESULT_CHARS`
went 8,000 -> 2,000, and the retrieval workspace went 5,000 -> 1,800 tokens.

**Measured result:** 0 tool calls -> **8 tool calls** (`read_method`, `get_method_strings`,
`find_xrefs`), 1 LLM call -> 4, 0 claims -> 2, and the tool loop now completes rounds at
3,715 / 3,936 / 4,160 tokens instead of being rejected.

**Still not landed, and it is a quota ceiling rather than a defect:** `interpretations`
remains 0. The model spends its whole round budget on tools and is then rate-limited
before it can emit the final validated JSON. The honest options are a tier upgrade (Groq's
own error suggests Dev Tier) or fewer stages per minute. The workspace reduction to 1,800
tokens is a real cost to the RE layer — fewer method bodies reach the model — and is
recorded here as a deviation rather than presented as a tuning improvement. Raising
`llm_max_request_tokens` after an upgrade restores it automatically.


### `0 methods interpreted` on every app was a signature-dialect join failure in the stored verdict — fixed 2026-08-26

The dashboard rendered `0 methods interpreted` and "No validated model interpretation
exists for this method in this run" for **every** sample, while the backend logs on the
analysis VM showed `code_interpreter_done interpretations=4` (and 1/2/3/6 on other jobs)
with the LLM round completing in one call. The model had done the work; the UI could not
find it.

**Root cause, verified against the live API on the VM** (`job_3f29046f7b68`, the same job
the dashboard screenshot came from): `interpret_methods` resolves the model's spelling of
a signature back to a catalogue method (`resolve_signature`, added for exactly this
dialect problem) — but then stored the **model's own spelling** in
`CodeInterpretation.method_signature`:

    verdict stored   Lcom/b/a/c/a;->a(Landroid/content/Context;Ljava/lang/String;)V
    catalogue key    Lcom/b/a/c/a;->a

Both dashboard views join by exact string — `CodeGraphTab` against call-graph node ids,
`ReverseEngineeringTab` against `decompiled_methods[].signature` — so every join missed
and the flagship RE layer read as empty. The earlier fix moved the join failure from the
backend lookup into every consumer instead of removing it.

**Fix:** store the resolved catalogue signature (`slice_.signature` / `method.signature`)
instead of the model's spelling. One line plus a regression test
(`test_stored_interpretation_carries_the_catalogue_spelling`) that fakes the observed
live answer and asserts the stored key equals the catalogue key. `make test` green:
1649 passed, 1 skipped.

**Separately, and not a defect:** `0 retrieval tool calls` is accurate and expected under
the current design — the method bodies ship in the first user turn and tools exist only
for drill-down, so a run where the model had no ambiguity to resolve legitimately makes
zero tool calls. The tile reads as an indictment but is the honest number.
