# DRISHTI — STATUS

**This file is the current state of the world.** Read it first, every session.
Update it after **every** task: task → DONE, hour, commit sha, test count.
Protocol: `docs/00_GUIDING_MAP.md` §13.

- **Started:** 2026-08-13 · **Last reconciled:** 2026-08-25
- **Integration branch:** `main` · **v1 record:** branch `v1` + tag `v1-final`
- **Phase:** Presentation hardening · GUI/reverse-engineering depth landed; live lab and model evaluation remain blocked
- **Tests:** **493 contract+unit + 15 e2e, all passing** (measured 2026-08-25 at `7fce6f0`)
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
- [ ] T2.3 Train the classifier                    TODO
- [ ] T2.4 Calibration                             TODO
- [ ] T2.5 Anomaly detector                        TODO
- [ ] T2.6 SHAP explanations                       TODO
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
- [ ] T6.6 Demo script                             TODO
- [ ] T6.7 Backup plan                             TODO
- [ ] T6.8 Q&A preparation                         TODO
- [ ] T6.9 Final hour                              TODO

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
