# DRISHTI — STATUS

**This file is the current state of the world.** Read it first, every session.
Update it after **every** task: task → DONE, hour, commit sha, test count.
Protocol: `docs/00_GUIDING_MAP.md` §13.

- **Started:** 2026-08-13 · **Last reconciled:** 2026-08-24
- **Integration branch:** `main` @ `2d30c6c` · 63 commits · **v1 record:** branch `v1` + tag `v1-final`
- **Phase:** P0/P1/P2 substantially done · P3 **built except the code-reading half** ·
  P4 **analysis half built, execution half unbuilt** · P5 stubs only · P6 UI only
- **Tests:** **474 passing** (measured 2026-08-24 at `2d30c6c`: 257 contract + 200 unit
  + 15 e2e + 2 lab, `uv run pytest` in 97.7 s)
- **Build design:** `docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md`
- **Evidence pack:** `docs/PROTOTYPE_REPORT_EVIDENCE.md` — every number in the paper, with its source
- **Next-work roadmap:** `docs/ROADMAP_GENAI_RE.md` · **Detonation:** `docs/M3_DETONATOR_RUNBOOK.md`
- **Narrative log:** see `PROGRESS.md`

> **Reconciliation note (2026-08-24).** The 2026-08-17 version of this file listed all
> of P3, P4 and P5 as TODO. That was already wrong when written: PRs #19, #20, #25, #27,
> #28 and #29 landed the LLM client, injection defence, controller, technique mapper,
> code interpreter, trained model, dashboard, trace normalisation, evasion detection and
> the containment probe **after** the last reconciliation. Every line below was
> re-checked against the source on 2026-08-24, not against the roadmap. Where a task is
> marked DONE the implementing symbol is named so the claim can be checked in one grep.

---

## Verified environment facts

Re-established by inspection on **2026-08-24**. Every row was checked with a command.

| Item | State |
|---|---|
| GCP (v1, legacy `drishti-m3-08130038`) | **GONE.** Absent from `gcloud projects list`. The four `v1-rescue-*` boot-disk snapshots went with it |
| GCP (v2 `drishti-v2-260814`) | **GONE.** The corpus bucket, artifacts bucket, `samples.csv`, the 14 rescued v1 observation artifacts and the 3 attestations are **unrecoverable** |
| Trial billing account | `01996C-C72085-6358D2` — **`open: false`** (closed) |
| Usable billing account | `017B2F-A06E63-B76B98`, INR, `open: true` |
| GCP (v3) | **`cybershield-505518`**, billing linked. 3 buckets in `us-east1` (versioned, PAP enforced, uniform access). **0 VMs** — confirmed 2026-08-24 |
| Budget guard | Project budget on `cybershield-505518` = **₹4,200 (≈$50)**, alerts at 60/90/100%. **Does not cover `internship-505513`** — see Open risks |
| **Extractor VM** | `instance-20260817-080247`, project `internship-505513`, `us-east1-c`, `n2-standard-8`, public IP, nested virt OFF. **STILL RUNNING as of 2026-08-24** — 7 days idle since the extraction batch. **~$0.39/hr. Stop it.** Usable for static extraction; **disqualified as a detonator** |
| Second VM | `instance-20260814-133700`, `internship-505513`, `us-central1-a`, `e2-micro`, RUNNING. Small, but unaccounted for — confirm it is wanted |
| Detonator VM | **Does not exist.** Neither does the `drishti-runtime` VPC nor the `drishti-m3-tools-*` image |
| LLM provider | **OpenRouter live and healthy** — `tests/lab/test_openrouter_live.py` green on 2026-08-24. Two transient failures observed on one run, green on retry: these tests are network-dependent and are excluded from `make test` for that reason |
| Secrets | `.env` (gitignored). `ANDROZOO_API_KEY` + OpenRouter key set — **both exposed in a chat transcript, rotate post-demo** |
| Region drift | `.env` says `DRISHTI_GCP_ZONE=asia-south1-a`; the buckets are **us-east1**. Building the lab as configured means cross-continent egress on every corpus read. Fix `.env` before `packer build` — see runbook §0.2 |
| CI | **GitHub Actions has never run** — 0 workflows registered, 0 runs ever, despite valid YAML on the default branch and `enabled: true`. `total_count: 0` from the API, so not a token-scope problem. PRs are merged on local verification |
| Trained model | `models/classifier_v1.pkl`, `calibrator_v1.pkl`, `vocab_v1.json` (340 features), `metrics.json` — all present, produced 2026-08-17 |

---

## P0 — FOUNDATIONS (H00→H06)

- [x] T0.1  Repo skeleton + tooling                DONE  H00  lint+mypy clean
- [x] T0.2  Config                                 DONE  H03
- [x] T0.3  All contracts, verbatim                DONE  H01  37 models
- [x] T0.4  Evidence Ledger                        DONE  H02  SQL-trigger append-only, SHA-256 chain, Ed25519, CLI verify
- [x] T0.5  Job runner + pipeline skeleton          DONE  H03  `drishti/pipeline.py`, 11 stages
- [x] T0.6  API surface                            DONE  H04  19 routes frozen, undeclared-route test
- [x] T0.7  TraceSource abstraction + fixture      DONE  H05  pre/post-morph arc
- [x] T0.8  UI shell                               DONE  2026-08-17  `ui/` Vite+React+TS+Tailwind, 7 tabs
- [~] T0.9  Sandbox VM groundwork                  WIP   canary compiled (SHA-256 `9854900c…`); **sealed image/VM still pending**
- [x] T0.10 Ingest module M1, for real             DONE  H07  guards + split reassembly + graded threat intel
- [x] P0.11 Ledger concurrency hardening           DONE  2026-08-17  `615a803`

## P1 — STATIC ENGINE (H04→H16)

- [x] T1.1 Manifest & permission analysis          DONE  **14** combo rules in `m2_static/rules.py`, DoD enforced by test
- [~] T1.2 Certificate analysis                    WIP   `engine._certificate()` extracts sha256/subject/issuer/`self_signed`/`debug_cert`.
      **The three signals the paper credits are hardcoded, not computed:** `not_before`/
      `not_after` = `"unknown"`, `age_days` = 0, `brand_mismatch` = `False`,
      `brand_claimed` = `None`. Certificate reuse across known-bad, certificate age and
      brand-identity mismatch are **unbuilt**. Do not claim them.
- [~] T1.3 Strings, constants, packing signals     WIP   URLs/packages/crypto strings, `_archive_signals()` entropy + native-lib detection, `_defang()`, `_string_kind()`
- [x] T1.4 Call-graph + backward sink walk         DONE  **29**-sink taxonomy in `m2_static/sinks.py` (DoD ≥18, test-enforced), bounded BFS with entrypoint attribution. Signature-format defect fixed in #22
- [ ] T1.5 Over-privilege & drift                  **TODO — and it is load-bearing.**
      `StaticReport.used_not_declared` is declared, consumed by `m6_score/engine.py:136`
      (the whole `D` term) and by two features in `m5_ml/features.py:221`, and is
      **never populated by M2**. The scorer's static-drift path is unit-tested
      (`test_static_drift_contributes_without_dynamic_data`) but **unreachable in a real
      run** — `D` is structurally 0.000 on every sample. This is why figure 12 shows
      `D raw 0.000`; the stated reason there ("nothing detonated") is only half of it.
- [x] T1.6 Hypothesis derivation                   DONE  `m2_static/hypotheses.py`, six kinds, evidence-cited static→dynamic bridge
- [ ] T1.7 MobSF enrichment (optional)             TODO  — cut candidate, not on the critical path

## P2 — ML & SCORING (H10→H24)

- [x] T2.1 Feature extractor                       DONE  12/12 families, **340** features, one `extract()` for train and inference, parity test + pinned vocab
- [~] T2.2 Dataset assembly                        WIP   Real list built **and extraction ran on the VM** (#21, #23).
      27.6M AndroZoo index rows scanned, seed 20260817, 70.6% dropped for implausible
      `dex_date` → **10,599 rows selected (193.9 GB)**. MalwareBazaar backfill added
      **571** recent samples. **Features extracted for 397** (205 train / 144 test /
      48 calibration) — the rest of the list is downloaded-but-unextracted or
      unfetched. 2024–2026 malware yielded only 99 of a 1,500 target: recent Android
      malware, not compute, is the binding constraint.
- [x] T2.3 Train the classifier                    DONE  `models/classifier_v1.pkl`; PR-AUC **0.9925** random / **0.9541** time split, gap **0.0384**. **n = 205/144/48 — a pilot. Never quote PR-AUC without the n.**
- [x] T2.4 Calibration                             DONE  `calibrator_v1.pkl`, Platt/sigmoid (isotonic gated on ≥25 per class, which 48 samples does not meet). Brier **0.3686 → 0.1302**, −64.7%
- [ ] T2.5 Anomaly detector                        **TODO — dead branch today.**
      `MLPrediction.anomaly_escalate` exists and `m6_score/engine.py:98` escalates a LOW
      band to HIGH on it, but `m5_ml/infer.predict()` never sets it. The escalator is
      unit-tested (`test_anomaly_escalates_band_without_changing_score`) and
      **unreachable in a real run**. The paper's "zero-days cannot land quietly in LOW"
      claim is not currently true in code.
- [ ] T2.6 SHAP explanations                       TODO  — referenced in `api/routes/ledger.py` docstring, not implemented
- [x] T2.7 The scorer                              DONE  `m6_score/engine.py`, 207 lines. Noisy-OR fusion, known-bad override, γ-confidence, bands. Pure: no I/O, no clock, no randomness
- [x] T2.8 Bands and proposed actions              DONE  `_band()` + `_actions()`; four bands, human-confirmation gate
- [x] T2.9 Scorer test suite                       DONE  7 tests: 100× determinism, source-level purity, noisy-OR, override, reputation floor, anomaly escalation, static drift.
      **Two of those seven test code paths that production cannot reach** — see T1.5 and T2.5

## P3 — GENAI CORE (H16→H36)

- [x] T3.1 LLM client                              DONE  `m4_genai/client.py`, 274 lines. Provider-agnostic, OpenRouter (NVIDIA Nemotron) live, budgets asserted, response cache, schema validation
- [x] T3.2 Prompt-injection defence                DONE  `safety.wrap_untrusted()` — `<untrusted_artifact>`, XML-escaped, user turn only. `tests/unit/test_prompt_injection.py`
- [x] T3.3 Controller                              DONE  `m4_genai/controller.py`, 307 lines. Evidence catalogue → user turn → checklist → verifier
- [~] T3.4 Code Interpreter agent                  WIP   **Built, but it has never seen a line of the sample's code.**
      `agents/code_interpreter.explain_paths()` sends sink signatures, depth and
      entrypoint — call-graph metadata. **No method bodies. Nothing in the repo
      decompiles.** The paper's "reconstructs the malware's logic — tracing decrypted
      strings" is not supported by this implementation. Fixed by roadmap task **A1**,
      which blocks everything else in Track A.
- [x] T3.5 RAG grounding                           DONE-by-cut  Inlined MITRE cheat-sheet over 21 techniques. Vector store pre-agreed as cut in `00_GUIDING_MAP.md` §10 item 7 — machinery without a purpose is a demo liability
- [x] T3.6 Behavioural risk B, bounded             DONE  **16** behaviours in `safety.behavioural_risk()`; model emits booleans, Python computes `B` from the weight table
- [x] T3.7 Technique Mapper                        DONE  `agents/technique_mapper.py`, deterministic, **no LLM in the path** — so it cannot hallucinate a technique ID. 21 techniques in `data/kb/`, 18 covered by ≥1 detection layer
- [ ] T3.8 Social Engineering Analyst              TODO  `VictimProfile` contract frozen, **always `None`**. Roadmap A4
- [ ] T3.9 Vision impersonation                    TODO  `VisionMatch` contract frozen, unfilled. No VLM path exists
- [x] T3.10 Verifier integration + summariser      DONE  `Verifier.check_claim()` splits passed/rejected; rejected count is a headline UI number, not a footnote. ≤3-sentence summary enforced in the prompt
- [ ] T3.11 Disagreement meta-check                TODO  `disagreement_flag` frozen in the contract, consumed by `m6_score/engine.py:90` (×0.6 on confidence), **never set** — a third dead branch. Roadmap A5
- [x] T3.12 Structured output contract             DONE  `parse_and_validate()`, strict schema, fence-stripping

## P4 — DYNAMIC SANDBOX (H24→H48)

**The analysis half is built and tested. The execution half does not exist.**
Nothing in this project has ever executed an APK.

- [ ] T4.1 Emulator control                        TODO  `infra/gcp/emulator_control.sh` exists as shell; `emulator.py` unbuilt
- [ ] T4.2 Frida runner                            TODO  `frida_runner.py` / `dynamic_analyze.py` **unbuilt**. `m3_dynamic/scripts/hooks.js` exists (13 emit sites, 11 hooked methods incl. `Cipher.doFinal`), is statically audited in CI by `tests/contract/test_hooks_are_observational.py`, and **has never been executed**
- [ ] T4.3 Crash recovery & self-repair            TODO
- [ ] T4.4 TLS interception & network capture      TODO  **Deliberately deferred.** The `Cipher.doFinal` hook yields plaintext *before* encryption, which is the stronger result and also defeats T1521. Do not block M3 on a system CA. ← v1 gap H4
- [x] T4.5 Evasion observation detection           DONE  `m3_dynamic/evasion.py`, 161 lines. Distinguishes stalled from clean; a sample with no observations is `inconclusive`, **never benign**. Verified over three trace shapes (figure 10)
- [x] T4.6 Trace normalisation                     DONE  `m3_dynamic/normaliser.py`. Rule 11 aggregation, `MAX_OBSERVATION_GROUPS = 40`. **1 event and 1,925 events yield identical `b_dynamic`** (figure 16) — aggregation provably cannot move a score
- [ ] T4.7 TRIPWIRE @ H40                          TODO  ← mandatory decision point, not yet reached
- [ ] T4.8 Sandbox plan builder                    TODO  `SandboxPlan` is constructed inline in `pipeline.py` with duration + pass number + morphs. There is no builder
- [x] P4.x Containment verification                DONE  `m3_dynamic/containment.py`, 180 lines.
      `assert_probe_trustworthy()` runs a negative control (`127.0.0.1:1`, must read
      unreachable) and a positive control (a listener we started, must read reachable)
      before any verdict is trusted; `TimeoutExpired` → rc 124 → *blocked*. The
      inherited v1 probe is **rejected** by this gate (toybox `nc` has no `-z`, so it
      exited 1 for every host and every containment check passed regardless of the real
      network state). Fails closed; a containment failure aborts a batch, never warns

## P5 — FRONTIER (H44→H58)

Every component here is a declared stub. The **control flow** around them is real and
exercised, which is deliberate: a conditional that never takes its branch has not been
tested, and this is the branch the demo narrative hangs on.

- [ ] T5.1 Morph applicator                        TODO
- [ ] T5.2 Morph validation                        TODO  `validate_morph()` is specified in `contracts/frontier.py`'s docstring and **not written**. Rule 7 has no enforcement point yet — nothing may touch adb or JS until it does
- [ ] T5.3 Adversarial Elicitor agent              TODO  `pipeline._stub_frontier()` derives morphs from real evasion observations (never invents a plan) and labels itself `m5_frontier:stub`. Roadmap A6
- [ ] T5.4 Generative C2 emulation                 TODO  Roadmap A7 — **highest risk, first cut.** Needs an airtight inertness proof before any line is written
- [~] T5.5 Frontier orchestration loop             WIP   The gate is built and real: FRONTIER runs **only** when pass 1 did not detonate **and** there is an observed evasion check to respond to (`pipeline.py:589`). Morphing without an observation would be a guess. Every callee behind the gate is a stub
- [~] T5.6 Replay-mode frontier                    WIP   `ReplayTraceSource` + the pre/post-morph fixture built; `DynamicTrace.synthetic` derived from fixture provenance, never from JSON
- [x] T5.7 Frontier UI panel                       DONE  `ui/src/tabs/FrontierTab.tsx` reconstructs passes from `API_TRACE` ledger nodes rather than a UI cache, and labels a stub plan as stub

## P6 — REPORT / UI / DEMO (H50→H72)

- [ ] T6.1 YARA generation                         TODO  `/api/.../artifacts/yara` returns **501** naming T6.1. The paper's "campaign multiplier" business argument is unbacked by code
- [ ] T6.2 STIX 2.1 export                         TODO  501 naming T6.2
- [ ] T6.3 HTML report                             TODO  **`drishti/m7_report/` is empty (0 lines).** `pipeline._stub_report()` appends one `REPORT_GENERATED` ledger node and nothing else.
      Note for the paper: the auto-generated **Limitations** text that the evidence pack
      credits to M7 is real, but it lives in `m6_score/engine.py:102` and is generated
      from live flags (`dynamic is None`, `ml is None`, `genai is None`). Credit it to
      M6, and do not claim a rendered report exists
- [~] T6.4 Dashboard completion                    WIP   Seven tabs render live against real endpoints. What remains is depth behind unbuilt modules (T6.1/T6.2/T6.3 render their 501s) plus the dev-only tamper demo, deliberately unbuilt — see Deviations
- [ ] T6.5 Code freeze @ H68                       TODO
- [ ] T6.6 Demo script                             TODO  ← **now the highest-value unstarted task.** See Grand-finale priorities
- [ ] T6.7 Backup plan                             TODO
- [ ] T6.8 Q&A preparation                         TODO
- [ ] T6.9 Final hour                              TODO

## Salvage from v1 (see `docs/SALVAGE.md`)

- [x] known_bad_hashes.txt LIFT -> data/kb/                 DONE  H07
- [x] Lab infra LIFT (`infra/m3/**` → `infra/gcp/`)        DONE  H08  + auto_delete and snapshot-policy fixes
- [x] Containment verification LIFT                        DONE  See P4.x — lifted **and** the lifted probe was rejected by its own trustworthiness gate
- [~] M3 harness + hook catalogue LIFT                     WIP   `hooks.js` lifted and CI-audited. `verify_containment.py` (CLI) and `frida_runner.py` **not written** — these two are what block `packer build`
- [x] canary/ source written to §4 spec                    DONE  H09  compile-only builder + `dist/canary.apk`
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

## Gaps against the documented Definition of Done

| Requirement | Source | Required | Actual |
|---|---|---|---|
| Permission-combo rules | `PHASE_1` DoD | ≥ 14 | **14** — enforced by test |
| Sink taxonomy | `PHASE_1` DoD | ≥ 18 | **29** in `m2_static/sinks.py` — enforced by test |
| Feature vector width | `PHASE_2` T2.1 | 12 families | **12/12 families, 340 features** |
| Scorer determinism test | `00_GUIDING_MAP` §9.3 | 100× identity | **done** — plus a source-level purity assertion |
| Feature parity test | `PHASE_2` T2.1 (R3) | golden-file element-wise | **done** — `tests/contract/test_feature_parity.py` |
| Vocabulary pinning | `PHASE_2` T2.1 | frozen vocab, width asserted both paths | **done** |
| LLM calls per job | `00_GUIDING_MAP` §9 | ≤ 25 | **asserted in `client.py`** |
| Prompt tokens in | `00_GUIDING_MAP` §9 | ≤ 12,000 | **asserted** |
| Observation groups | Rule 11 | ≤ 40 | **`MAX_OBSERVATION_GROUPS = 40`**, aggregation-invariance tested |

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
| 2026-08-13 | ML features: **full v2 schema, re-extract corpus first** | v1's 35-feature vector is a strict subset; PHASE_2's feature families and the paper's Drebin-style claim need the full set |
| 2026-08-13 | Lab: **fresh GCP project for v2**, legacy project read-only until v2 detonates the canary | Clean IAM/VPC to the CLAUDE.md spec; legacy kept as the data source until rescue is proven |
| 2026-08-13 | Branches: `v1` = immutable v1 record, `main` = v2 integration | origin had only `v1`; `main` was free |
| 2026-08-13 | Corpus APKs **retained in GCS** after extraction | v1 deleted every APK post-extraction, which is exactly why a schema change now costs a full re-download |
| 2026-08-17 | Lab rebuilt in **`cybershield-505518`**, region **`us-east1`** | Co-located with the pre-existing extractor VM. Moving 120GB cross-region would cost ~$12. **Deviates from `CLAUDE.md`'s `asia-south1`** |
| 2026-08-17 | Extractor = the existing `internship-505513` VM; **detonator built separately and sealed** | Static parsing never executes a sample, so a shared project is tolerable there. Detonation is not: that VM has nested virt off, a public IP, and shares a VPC with an unrelated running VM |
| 2026-08-17 | Corpus target **12,000 rows**, 50/50, 4 time bands, download order stratified | Makes any *prefix* of the download a balanced, time-spanning corpus, so a metered transfer can be stopped at any point and still yield a valid time split |
| 2026-08-17 | Budget ceiling **$50**; every billable GCP resource confirmed before creation | The trial account is closed — there is no safety net |
| 2026-08-17 | Platt over isotonic for calibration | 48 calibration samples; `PHASE_2` T2.4 says fall back to sigmoid when the split is small, and isotonic on a handful of one class overfits. Gate is ≥25 per class |
| 2026-08-18 | **Build the M3 analysis layer before the detonator** | A detonation you cannot trust is worse than no detonation. The containment probe must provably distinguish an open port from a closed one, aggregation must provably not move a score, and a silent sample must resolve to `inconclusive` — all three gates exist and are measured before any sample runs |
| 2026-08-18 | **Decompilation (A1) precedes every other GenAI task** | Without method bodies the Code Interpreter narrates a call graph. It is laptop-safe (androguard's DAD parses, it does not execute) and it is the difference between a demo and the claim |

## Deviations from roadmap

- Repo layout: v1's implementation is preserved at `v1-reference/` (read-only, nothing
  imports it) rather than deleted, so ADAPT work can see the original. Additive only.
- `v1-reference/README.md` landed in PR #1 (restructure) rather than PR #2, so the
  directory is not unexplained at review time.
- **T0.1 dependency extras.** Split into core + `[lab]` (frida<17, frida-tools,
  mitmproxy) + `[rag]` + `[yara]`. Reason: a laptop never instruments or proxies a
  sample, so installing frida/mitmproxy there contradicts the safety posture; and
  sentence-transformers pulls ~2GB of torch for a feature that is cut-listed
  (`00_GUIDING_MAP.md` §10 item 7). `make install` stays core+dev; `make install-lab` is
  for the detonator.
- **T0.1 LLM provider.** `PHASE_0` T0.2 specifies `anthropic_api_key` and
  `claude-sonnet-4-5`. The client is provider-agnostic and selected at runtime
  (`DRISHTI_LLM_PROVIDER`); **the live default is OpenRouter (NVIDIA Nemotron)**, which
  is the credited key. Gemini and Anthropic paths raise `NotImplementedError` (roadmap
  A8). `mock` remains available for tests. This matters commercially as much as
  technically: an institution that cannot send sample-derived strings to a third party
  can point the same code at a self-hosted open-weight model without touching the
  pipeline.
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
  `FILE_META` + `THREAT_INTEL` a run is **12** nodes, and **13** for a split bundle. A full
  real run on the canary is **29**; on a 50.5 MB real sample, **26**.
- **T0.6 froze 19 routes and added 3 beyond the doc's list.** A contract test asserts no
  *undeclared* `/api` route exists, so the surface cannot drift silently.
- **T0.6 uses two distinct "unavailable" statuses.** 404 + `{"stage": ...}` for
  not-yet-produced artefacts; **501** with the owning task for frozen-but-unbuilt features
  (report T6.3, YARA T6.1, STIX T6.2), because polling a 404 is reasonable and polling
  something that will never exist is not.
- **`DynamicTrace.synthetic` added (T0.7).** `source == REPLAY` cannot distinguish
  replaying a real captured trace from replaying a hand-authored one, and the report's
  Limitations section is generated from flags like this. The loader derives it from the
  fixture's `provenance.kind` and overwrites whatever the JSON claims. Addendum A7.
- **`EvidenceType.REPORT_GENERATED` added.** The REPORT stage was mis-typed as
  `ANALYST_ACTION`, which means "a human confirmed something" — it made a rendering step
  indistinguishable from a human decision in the ledger. Addendum A6.
- **`DynamicTrace.outcome` added** because `detonated: bool` cannot express
  *inconclusive*, and a sample that emitted nothing must never read as benign.
- **T6.4's "tamper demo" button is not built, on purpose.** The ledger is append-only in
  SQL via triggers, so no API call can corrupt a node — and simulating the red banner in
  the browser would prove nothing about the mechanism it claims to demonstrate. Building
  it honestly needs a dev-mode endpoint that writes to the SQLite file directly. The
  Ledger tab states this on screen. **The tamper demonstration is done at the CLI
  instead** (`drishti ledger verify` → edit one byte → `first_bad_seq=7`), which is the
  real mechanism and is what figure 14 captures.
- **The UI is a separate origin, not served by FastAPI.** `ui/` proxies `/api` to :8080 in
  both `dev` and `preview`. Mounting the built assets on the app would put a non-`/api`
  route into the file whose whole point (T0.6) is that its routes do not move.
- **Canary artifact path is `canary/dist/`,** not Gradle's `canary/app/build/outputs/…`.
  git cannot re-include a file whose parent directory is excluded, so a `!` allowlist
  inside an ignored `build/` directory can never fire. `tests/contract/test_repo_invariants.py`
  guards both directions.
- **RAG is an inlined cheat-sheet, not a vector store.** Pre-agreed cut,
  `00_GUIDING_MAP.md` §10 item 7. Revisit only if the KB grows past a few hundred entries.

## Open risks

Ordered by what costs most if ignored.

- **💸 The extractor VM has been running idle for 7 days.** `instance-20260817-080247`,
  n2-standard-8, ~$0.39/hr, in `internship-505513` — a project the ₹4,200 budget guard on
  `cybershield-505518` **does not cover**. Roughly $65 spent on nothing.
  `gcloud compute instances stop instance-20260817-080247 --zone=us-east1-c --project=internship-505513`
- **Nothing has ever been detonated.** No APK executed, no emulator run, no Frida hook
  fired, no probe against a real network. Every dynamic number in the paper comes from
  committed fixtures or constructed traces through the real analysis code. `docs/PROTOTYPE_REPORT_EVIDENCE.md`
  §9 is the authoritative list of what must not be claimed — read it before any slide.
- **`packer build` fails today.** `detonator.pkr.hcl` provisions four v1 `backend/scripts/`
  paths; two of those files do not exist in any form (`verify_containment.py` CLI,
  `frida_runner.py`). Cheap failure — it aborts at the file provisioner before spending VM
  time — but it is the gate on all of Track C. Runbook §0.3.
- **The GenAI layer has never read the sample's code** (T3.4). The paper's
  reverse-engineering claim is currently narration over a call graph. Roadmap A1.
- **Three dead branches** — see the table above. Two of four score terms are structurally
  zero.
- **`.env` region contradicts the buckets** (`asia-south1-a` vs `us-east1`). Fix before
  building anything, or pay cross-continent egress on every corpus read.
- **GitHub Actions has never run on this repo** — 0 workflows registered, 0 runs ever.
  PRs are being merged on local verification, which is weaker than the CI gate the docs
  assume. The contract tests exist and pass; nothing enforces that they pass before merge.
- **Both API keys were pasted into a chat transcript.** Rotate after the demo.
- **Model metrics are a pilot: n = 205 train / 144 test / 48 calibration.** Never quote
  PR-AUC without the n. The 0.0384 time-split gap is the honest headline, not the 0.9925.
- **R1 (emulator/frida) is fully open.** v1's proof that the image boots with frida
  16.7.19 rested on a project that no longer exists. The knowledge survives in
  `docs/CARRIED_FINDINGS.md`; the running system does not.
- **v1 H1 — no benign controls were ever detonated**, so the dynamic false-positive rate
  is unmeasured. Any claim that observed techniques *distinguish* malware from ordinary
  apps is unsupported. P4 must detonate benign controls.
- **v1 H2** — 9 samples executed, 7 with data. A pilot, not an evaluation. **Never quote 12.**
- **v1 H4** — no HTTPS interception, so Generative C2 over HTTPS is not available;
  `Cipher.doFinal` plaintext capture is a different (and defensible) claim.
- **Corpus recency** — 99 samples from 2024–2026 against a 1,500 target, backfilled with
  571 from MalwareBazaar labelled by a *different* pipeline than AndroZoo's
  `vt_detection`. Disclose the composition wherever it is reported.
- **GenAI output is not deterministic** — five identical runs over the same APK gave
  `B` = 0.925, **0.700**, 0.925, 0.925, 0.925. Bounded by the weight table and reported as
  a limitation (figure 15) rather than suppressed. This is the empirical argument for the
  enumerated-boolean architecture, so present it as a finding, not an apology.

---

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
