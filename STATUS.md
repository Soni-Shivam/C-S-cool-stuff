# DRISHTI — STATUS

**This file is the current state of the world.** Read it first, every session.
Update it after **every** task: task → DONE, hour, commit sha, test count.
Protocol: `docs/00_GUIDING_MAP.md` §13.

- **Started:** 2026-08-13 · **Clock:** H00
- **Integration branch:** `main` · **v1 record:** branch `v1` + tag `v1-final`
- **Phase:** P0 FOUNDATIONS (not started)

---

## Verified environment facts

Established by inspection on 2026-08-13, not assumed.

| Item | State |
|---|---|
| GCP (v1, legacy) | `drishti-m3-08130038` / `asia-south1-a`; image `drishti-m3-tools-v1`; VMs `drishti-detonator`, `m3-control-builder`, `m3-extractor` were **running**; **0 buckets, 0 snapshots** → all lab output was on `auto_delete=true` disks |
| GCP (v2) | Not yet created. Target: fresh project, VPCs `drishti-build` (NAT) + `drishti-runtime` (no NAT, default-deny egress) |
| Secrets | `ANDROZOO_API_KEY`, `GEMINI_API_KEY` present in v1's `.env` but **were shared in plaintext → must be rotated**; `LEDGER_SIGNING_KEY` was empty |
| v1 corpus list | `v1-reference/backend/samples.csv`, 6,000 rows, 3000/3000 balanced — **but split contaminated**: 1,235 rows (20.6%) dated 1980/81 all in train, 23 rows dated 2039–2107 all in test; only 62 rows from 2024, 55 from 2025 |
| Test baseline | v1 claimed 124 tests passing. **Not independently verified by v2.** Do not quote it. |

---

## P0 — FOUNDATIONS (H00→H06)

- [x] T0.1  Repo skeleton + tooling                DONE  H00  tests: 26/26 · lint+mypy clean
- [ ] T0.2  Config                                 TODO
- [ ] T0.3  All contracts, verbatim                TODO
- [ ] T0.4  Evidence Ledger                        TODO  ← highest priority in P0
- [ ] T0.5  Job runner + pipeline skeleton          TODO
- [ ] T0.6  API surface                            TODO
- [ ] T0.7  TraceSource abstraction + fixture      TODO
- [ ] T0.8  UI shell                               TODO
- [ ] T0.9  Sandbox VM groundwork                  TODO  ← now GCP, see CLAUDE.md
- [ ] T0.10 Ingest module M1, for real             TODO

## P1 — STATIC ENGINE (H04→H16)

- [ ] T1.1 Manifest & permission analysis          TODO
- [ ] T1.2 Certificate analysis                    TODO
- [ ] T1.3 Strings, constants, packing signals     TODO
- [ ] T1.4 Call-graph + backward sink walk         TODO
- [ ] T1.5 Over-privilege & drift                  TODO
- [ ] T1.6 Hypothesis derivation                   TODO
- [ ] T1.7 MobSF enrichment (optional)             TODO

## P2 — ML & SCORING (H10→H24)

- [ ] T2.1 Feature extractor                       TODO
- [ ] T2.2 Dataset assembly                        TODO  ← corpus rebuild, see Decisions
- [ ] T2.3 Train the classifier                    TODO
- [ ] T2.4 Calibration                             TODO
- [ ] T2.5 Anomaly detector                        TODO
- [ ] T2.6 SHAP explanations                       TODO
- [ ] T2.7 The scorer                              TODO
- [ ] T2.8 Bands and proposed actions              TODO
- [ ] T2.9 Scorer test suite                       TODO

## P3 — GENAI CORE (H16→H36)

- [ ] T3.1 LLM client                              TODO
- [ ] T3.2 Prompt-injection defence                TODO
- [ ] T3.3 Controller                              TODO
- [ ] T3.4 Code Interpreter agent                  TODO
- [ ] T3.5 RAG grounding                           TODO
- [ ] T3.6 Behavioural risk B, bounded             TODO
- [ ] T3.7 Technique Mapper                        TODO
- [ ] T3.8 Social Engineering Analyst              TODO
- [ ] T3.9 Vision impersonation                    TODO
- [ ] T3.10 Verifier integration + summariser      TODO
- [ ] T3.11 Disagreement meta-check                TODO
- [ ] T3.12 Structured output contract             TODO

## P4 — DYNAMIC SANDBOX (H24→H48)

- [ ] T4.1 Emulator control                        TODO
- [ ] T4.2 Frida runner                            TODO
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
- [ ] T6.4 Dashboard completion                    TODO
- [ ] T6.5 Code freeze @ H68                       TODO
- [ ] T6.6 Demo script                             TODO
- [ ] T6.7 Backup plan                             TODO
- [ ] T6.8 Q&A preparation                         TODO
- [ ] T6.9 Final hour                              TODO

## Salvage from v1 (see `docs/SALVAGE.md`)

- [ ] Lab infra LIFT (`infra/m3/**` → `infra/gcp/`)        TODO
- [ ] Containment verification LIFT                        TODO
- [ ] M3 harness + hook catalogue LIFT                     TODO
- [ ] canary/ from `demo-apks/m3-inert-fixture`            TODO
- [~] Rescue v1 lab data off VM disks → GCS                WIP   ← urgent, pre-teardown
      - [x] Snapshot all 4 boot disks                      DONE  H00  4/4 READY
            `v1-rescue-{drishti-detonator,m3-extractor,m3-control-builder,m3-detonator-debug}-20260813`
            auto_delete cliff removed; disks recoverable even if instances are deleted
      - [ ] Copy 9 detonation artifacts + manifests → GCS   TODO  blocked: v2 project not created
      - [ ] Copy v1 feature CSV + samples.csv → GCS         TODO  blocked: v2 project not created
      - [ ] Stop the 3 running VMs (~$1/hr)                 TODO  after copy-off

---

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-13 | ML features: **full v2 ~1200-dim schema, re-extract corpus first** | v1's 35-feature vector is a strict subset; PHASE_2's feature families and the paper's Drebin-style claim need the full set |
| 2026-08-13 | Lab: **fresh GCP project for v2**, legacy project read-only until v2 detonates the canary | Clean IAM/VPC to the CLAUDE.md spec; legacy kept as the data source until rescue is proven |
| 2026-08-13 | Branches: `v1` = immutable v1 record, `main` = v2 integration | origin had only `v1`; `main` was free |
| 2026-08-13 | Corpus APKs **retained in GCS** after extraction | v1 deleted every APK post-extraction, which is exactly why a schema change now costs a full re-download |

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
- **Canary artifact path is `canary/dist/`,** not Gradle's `canary/app/build/outputs/…`.
  git cannot re-include a file whose parent directory is excluded, so a `!` allowlist
  inside an ignored `build/` directory can never fire. `tests/contract/test_repo_invariants.py`
  caught this and now guards both directions.

## Open risks

- **R1 (emulator/frida)** partially retired: v1 already proved the image boots with frida
  16.7.19 and a working clean snapshot. Risk is now re-standing it in a new project.
- **v1 H1 — no benign controls were ever detonated**, so the dynamic false-positive rate is
  unmeasured. Any claim that observed techniques *distinguish* malware from ordinary apps is
  currently unsupported. P4 must detonate benign controls.
- **v1 H2** — 9 samples executed, 7 with data. A pilot, not an evaluation. Never quote 12.
- **v1 H4** — no HTTPS interception, so Generative C2 over HTTPS is not available;
  `Cipher.doFinal` plaintext capture is a different (and defensible) claim.
- Corpus recency: only 117 samples from 2024–25 in v1's list, while the paper names 2024–25
  families as primary targets. Needs a fresh AndroZoo index and ideally MalwareBazaar labels.
- API keys were shared in plaintext and are not yet rotated.
- **No Java runtime on the dev laptop**, so the `canary/` APK cannot be built locally
  (T0.9 / T4.1 depend on it). Either install a JDK or build the canary on a GCE VM. The
  prebuilt artifact is committed at `canary/dist/` precisely so the demo does not depend
  on a local toolchain.
- ~~A formatter in the dev environment reformats `docs/*.md`~~ — **resolved.** It was
  `ruff` itself: it formats Python code blocks inside markdown, so a repo-wide
  `ruff format` rewrote the spec (~445 lines in `01_DATA_CONTRACTS.md` alone) and CI's
  `ruff format --check .` failed on it. Fixed properly by adding `*.md` to
  `[tool.ruff] extend-exclude`, so `make fmt` and CI can both run repo-wide safely.
