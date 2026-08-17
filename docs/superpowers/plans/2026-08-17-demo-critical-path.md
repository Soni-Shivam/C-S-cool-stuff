# 12-Hour Demo Critical Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a safe, honest DRISHTI demo that analyses the inert canary end-to-end, renders evidence-led findings, and runs Android only in a sealed GCP VM.

**Architecture:** Replace the P0 stubs in pipeline order: M2 performs Androguard reverse engineering, M5/M6 derive a single shared feature vector and deterministic score, M4 emits schema-validated grounded claims behind an injectable provider, M3 produces a provenance-carrying trace, and M5 Frontier applies only validated synthetic observations. The report/dashboard consume artefacts and the ledger. The Android runtime is a dedicated no-external-IP VM in `cybershield-505518`; it is used only after fail-closed containment verification.

**Tech Stack:** Python 3.11/FastAPI/Pydantic/Androguard/SQLite, React/Vite, GCE/IAP/iptables/Android emulator/Frida 16.7.19.

**Spec:** `docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md`; `docs/PHASE_1_STATIC_ENGINE.md`; `docs/PHASE_2_ML_AND_SCORING.md`; `docs/PHASE_4_DYNAMIC_SANDBOX.md`; `docs/PHASE_6_REPORT_UI_DEMO.md`.

## Global Constraints

- Never execute any APK on this workstation. Building the audited inert `canary/` APK is allowed; `adb install` and emulator execution happen only on the sealed GCP detonator.
- Use only `cybershield-505518` for new GCP resources; keep all new runtime resources in `us-east1`, matching the bucket region and recorded deviation.
- Runtime VM: no external IP, no Cloud NAT, no service account, IAP-only SSH, default-deny firewall and host iptables. Stop it after every run.
- Do not create another APK besides the existing `canary/`. Frontier package/sms/network morphs must be Frida-returned synthetic values; do not install a fake banking application.
- Do not claim a trained model, AUC, live trace, or containment verification without the recorded measured artefact.
- Verify local commands with `env -u PYTHONPATH` because the host ROS environment otherwise injects an incompatible pytest plugin.
- Every PR: full tests, ruff check/format check, mypy; merge only after these fresh commands pass locally because GitHub Actions remains unavailable.

---

### Task 1: Finish and validate the inert canary build

**Files:**
- Create: `canary/build.sh`
- Modify: `.gitignore`
- Modify: `STATUS.md`, `PROGRESS.md`
- Test: `tests/contract/test_repo_invariants.py`

**Interfaces:**
- Produces `canary/dist/canary-debug.apk` and prints its SHA-256.
- Never installs, launches, or parses an APK as part of build verification.

- [ ] **Step 1: Add a failing repository-invariant test**

Assert `canary/build.sh` is executable, uses a user-local tools directory, writes `local.properties`, builds `assembleDebug`, and contains no `adb install`, `adb shell`, `emulator`, or `monkey` command.

- [ ] **Step 2: Run the invariant test and confirm it fails because the script is absent from the branch.**

Run: `env -u PYTHONPATH uv run pytest tests/contract/test_repo_invariants.py -q`

- [ ] **Step 3: Add the audited build script and ignore `canary/local.properties`.**

Use JDK 17, Gradle 8.10.2, Android command-line tools, API 35 platform/build-tools under `$DRISHTI_TOOLS` (default `$HOME/drishti-tools`); copy only the built canary to `canary/dist/`.

- [ ] **Step 4: Build once, inspect only the artifact hash and APK file metadata, and run the invariant suite.**

Run: `env -u PYTHONPATH bash canary/build.sh`; do not run `adb`, `emulator`, or install the output locally.

- [ ] **Step 5: Commit and PR.**

### Task 2: Provision a sealed runtime in GCP and validate containment using no sample

**Files:**
- Create: `infra/gcp/provision_runtime.sh`
- Modify: `infra/gcp/lab.sh`, `infra/gcp/packer/detonator.pkr.hcl`, `infra/gcp/packer/builder_setup.sh`
- Create: `infra/gcp/harness/verify_containment.py`
- Test: `tests/unit/test_runtime_provision_contract.py`

**Interfaces:**
- `provision_runtime.sh build-image` creates the immutable emulator image from repository paths, without v1 `backend/` references.
- `provision_runtime.sh create-runtime` creates `drishti-detonator` with nested virtualization and no external IP.
- `verify_containment.py` exits non-zero unless both probe trust controls and runtime block probes succeed.

- [ ] **Step 1: Write static contract tests for no public IP, nested virtualization, IAP-only ingress, firewall egress deny, no metadata/VPC/internet runtime probes, and no stale `backend/` Packer paths.**

- [ ] **Step 2: Run the tests and confirm the stale Packer path/provisioning interface fails.**

- [ ] **Step 3: Implement idempotent shell provisioning and replace stale Packer file copies with current repo files.**

The build VPC is the only network allowed image-builder egress; the runtime VPC has no NAT. Use an ephemeral builder; delete it after the image is created. The `verify_containment` harness uses the documented `toybox nc -w N HOST PORT </dev/null` protocol with explicit return-code parsing and positive/negative controls.

- [ ] **Step 4: Run unit tests; then run the provisioner against GCP.**

The first runtime boot may validate emulator start and containment only. It must not receive an APK.

- [ ] **Step 5: Record measured VM/image/probe state in `STATUS.md`, stop the runtime VM, commit and PR.**

### Task 3: Implement the full P1 static reverse-engineering core

**Files:**
- Create: `drishti/m2_static/engine.py`, `drishti/m2_static/manifest.py`, `drishti/m2_static/certificate.py`, `drishti/m2_static/strings.py`, `drishti/m2_static/callgraph.py`, `drishti/m2_static/overprivilege.py`, `drishti/m2_static/rules/permission_combos.yaml`, `drishti/m2_static/hypotheses.py`
- Modify: `drishti/pipeline.py`
- Test: `tests/unit/test_m2_manifest.py`, `tests/unit/test_m2_permission_combos.py`, `tests/unit/test_m2_certificate.py`, `tests/unit/test_m2_strings.py`, `tests/unit/test_m2_callgraph.py`, `tests/unit/test_m2_overprivilege.py`, `tests/unit/test_m2_hypotheses.py`, `tests/e2e/test_pipeline_walk.py`

**Interfaces:**
- `analyse(apk_path: Path, ledger: LedgerStore) -> StaticReport` parses but never executes the APK.
- `effective_exported(explicit: bool | None, has_intent_filter: bool) -> bool` implements Android legacy semantics.
- `find_call_paths(dx: Analysis, components: tuple[Component, ...], ledger: LedgerStore) -> tuple[CallPath, ...]` performs bounded reverse BFS from the sink taxonomy, never a full decompile.
- `derive_hypotheses(report: StaticReport, ledger: LedgerStore) -> tuple[Hypothesis, ...]` caps results at eight and makes `TARGET_APP_PROBE` from observed package strings.

- [ ] **Step 1: Write fake-object tests for exported semantics, every permission rule predicate, cert brand mismatch/debug detection, URL/package/crypto extraction, packer entropy, bounded reverse-BFS, over-privilege, and a package-probe hypothesis.**

- [ ] **Step 2: Run them and confirm imports/functions are missing.**

- [ ] **Step 3: Implement manifest/component extraction, the rule engine, certificate facts, string/packing facts, call-graph sink paths, and declared-vs-exercised permission drift.**

Every matched combination writes a `PERMISSION_COMBO` evidence node parented by the relevant `MANIFEST_ENTRY` evidence nodes.

- [ ] **Step 4: Implement bounded hypothesis derivation from the observed reverse-engineering facts.**

Treat parser failures as a partial `StaticReport`, never as a successful clean result. No raw sample string becomes an LLM prompt.

- [ ] **Step 5: Replace `_stub_static` with `analyse`, update the pipeline e2e test, run all checks, commit and PR.**

### Task 4: Implement one shared feature extractor and transparent scoring

**Files:**
- Create: `drishti/m5_ml/features.py`, `drishti/m5_ml/prior.py`, `drishti/m6_score/engine.py`
- Modify: `drishti/pipeline.py`
- Test: `tests/contract/test_feature_parity.py`, `tests/unit/test_m5_features.py`, `tests/unit/test_m6_score.py`

**Interfaces:**
- `extract(static: StaticReport) -> FeatureVector` is the only feature path for both future training and live inference.
- `rule_based_prior(static: StaticReport) -> MLPrediction` returns `model_version="rule-based-prior-v1"`, `partial=True`, and a limitation explaining no trained model is loaded.
- `score(...) -> CompositeScore` is pure and does no I/O, clock access, LLM call, or randomness.

- [ ] **Step 1: Add a failing parity test with a hand-built `StaticReport`, plus scoring tests for the formula, band thresholds, and no-intel-not-benign behaviour.**
- [ ] **Step 2: Run tests and confirm the modules are missing.**
- [ ] **Step 3: Implement a pinned, deterministic feature vocabulary and the rule-based prior.**
- [ ] **Step 4: Implement the pure composite scorer and replace ML/score stubs.**
- [ ] **Step 5: Run all checks, update limitations in the pipeline output, commit and PR.**

### Task 5: Implement P3 GenAI core without allowing the model to score

**Files:**
- Create: `drishti/m4_genai/client.py`, `drishti/m4_genai/controller.py`, `drishti/m4_genai/behaviours.py`, `drishti/m4_genai/prompts/static.jinja`, `drishti/m4_genai/prompts/full.jinja`
- Modify: `drishti/pipeline.py`
- Test: `tests/unit/test_m4_prompt_safety.py`, `tests/unit/test_m4_controller.py`, `tests/unit/test_m4_behaviours.py`

**Interfaces:**
- `LLMClient.complete(prompt: str) -> str` is injected; `MockLLMClient` enables deterministic tests without a key.
- `render_untrusted_artifact(value: str) -> str` XML-escapes sample strings inside `<untrusted_artifact>` blocks.
- `behavioural_risk(verdict: GenAIVerdict) -> float` maps enumerated booleans to `B`; it never parses a score from model output.

- [ ] **Step 1: Write failing tests proving embedded prompt-injection strings are XML-escaped, output schema failures degrade to a partial verdict, ungrounded claims are rejected, and LLM text cannot affect `S` directly.**
- [ ] **Step 2: Run the tests and confirm modules are missing.**
- [ ] **Step 3: Implement provider selection, prompt isolation, Pydantic output parsing, verifier filtering, deterministic behaviour weights, and cache/budget accounting.**
- [ ] **Step 4: Replace the GenAI stubs.**

If `DRISHTI_GEMINI_API_KEY` is absent, use `MockLLMClient` and emit `provider="mock"`, `partial=True`, and the exact limitation. A mock claim is never rendered as a real analyst observation.

- [ ] **Step 5: Run all checks, commit and PR.**

### Task 6: Implement P4 dynamic trace handling and P5 validated frontier

**Files:**
- Create: `drishti/m3_dynamic/normaliser.py`, `drishti/m3_dynamic/live.py`, `drishti/m5_frontier/validate.py`, `drishti/m5_frontier/apply.py`, `drishti/m5_frontier/orchestrator.py`
- Create: `drishti/m3_dynamic/scripts/morph/packages.js`, `drishti/m3_dynamic/scripts/morph/sms.js`, `drishti/m3_dynamic/scripts/morph/c2.js`
- Modify: `drishti/m3_dynamic/trace_source.py`, `drishti/pipeline.py`
- Test: `tests/unit/test_trace_normaliser.py`, `tests/unit/test_morph_validation.py`, `tests/unit/test_frontier_orchestrator.py`, `tests/contract/test_trace_source_interface.py`

**Interfaces:**
- `normalise(raw: ObservationArtifact) -> DynamicTrace` caps grouped observations at 40 but preserves distinct technique severity.
- `validate_morph(morph: Morph) -> Morph` accepts only schema-allowed package identifiers, synthetic SMS metadata, and static local C2 responses.
- `Frontier.run(first: DynamicTrace, static: StaticReport) -> MorphPlan | None` derives every morph from an observed evasion signal.

- [ ] **Step 1: Write failing tests for aggregation, sensitive-data redaction, package-name validation, rejection of host/metadata/URL morph targets, and no morph without an evasion observation.**
- [ ] **Step 2: Run tests and confirm modules are missing.**
- [ ] **Step 3: Implement normalisation and a provenance-preserving `LiveSandboxSource` transport boundary; do not make it usable until the VM test succeeds.**
- [ ] **Step 4: Implement only inert Frida morph scripts that return synthetic values to API calls; never add a capability or a route to the sample.**
- [ ] **Step 5: Replace the frontier stub, retain replay fallback, run all checks, commit and PR.**

### Task 7: Implement a self-contained report, IOC exports, and demo API surface

**Files:**
- Create: `drishti/m7_report/html.py`, `drishti/m7_report/yara_gen.py`, `drishti/m7_report/stix_export.py`
- Modify: `drishti/api/routes/artifacts.py`, `drishti/pipeline.py`
- Test: `tests/unit/test_report.py`, `tests/unit/test_yara_gen.py`, `tests/unit/test_stix_export.py`

**Interfaces:**
- `render_html(...) -> str` produces a standalone report whose limitations derive from real `partial`, replay, synthetic, and rejected-claim flags.
- `generate_yara(static: StaticReport) -> str` emits only detection conditions from evidence-backed static invariants.
- `export_stix(...) -> dict[str, object]` produces a STIX 2.1 bundle without a TAXII server.

- [ ] **Step 1: Write failing tests for a disclosed rule-prior limitation, safe YARA identifiers, and a valid STIX bundle.**
- [ ] **Step 2: Run tests and confirm modules/routes are absent.**
- [ ] **Step 3: Implement pure render/export functions and append `REPORT_GENERATED` evidence.**
- [ ] **Step 4: Wire real report, YARA, and STIX artefacts into the frozen API routes.**
- [ ] **Step 5: Run all checks, commit and PR.**

### Task 8: Build the dashboard and rehearsal assets

**Files:**
- Create: `ui/` Vite/React application
- Create: `scripts/demo_reset.py`, `docs/DEMO_SCRIPT.md`, `docs/QA.md`
- Test: `tests/e2e/test_api_demo_path.py`

**Interfaces:**
- Dashboard polls the frozen API and renders explicit source/limitation badges.
- Evidence chips link to the ledger node they cite; Verify-chain renders the real `ok`, reason, and node count.

- [ ] **Step 1: Add an API e2e test that uploads an APK-shaped fixture, observes preliminary score, follows evidence IDs, downloads report/YARA/STIX, and verifies the ledger.**
- [ ] **Step 2: Run it and confirm report/UI artefacts are unavailable.**
- [ ] **Step 3: Scaffold a compact dark dashboard with Overview, Static, Sandbox, Frontier, Ledger, and Report tabs.**
- [ ] **Step 4: Implement `demo_reset.py`, a truthful six-minute narration, Q&A answers, and backup/runbook checklist.**
- [ ] **Step 5: Run API e2e plus all checks, commit and PR.**

### Task 9: Lab-only canary rehearsal and fallback decision

**Files:**
- Modify: `STATUS.md`, `PROGRESS.md`, `docs/DEMO_SCRIPT.md`
- Test: `tests/lab/test_canary_live.py`

**Interfaces:**
- The lab test uses IAP and the sealed runtime only; it installs the canary after containment verification and persists a signed observation artifact to the private artifacts bucket.
- If this fails or exceeds the timebox, the demo switches to existing replay mode with an on-screen synthetic/replay disclosure.

- [ ] **Step 1: Write the `@pytest.mark.gcp` test to require a containment manifest before upload/install and to fail if an external IP or unverified trace is observed.**
- [ ] **Step 2: Execute only after Task 2 succeeds; run the canary on the VM via IAP.**
- [ ] **Step 3: Store the trace/manifest privately, record image version/VM ID/timing in `STATUS.md`, and immediately run `make lab-down`.**
- [ ] **Step 4: Timebox at 90 minutes. If no verified live trace exists, set the demo source to replay with the exact limitation text; never fake live.**

## Planned order and timebox

1. Tasks 1–2 in the first 3 hours (canary toolchain and sealed runtime).
2. Tasks 3–4 in the next 3 hours (full static reverse engineering, shared features, transparent scoring).
3. Tasks 5–7 in the next 3 hours (GenAI boundaries, trace/frontier core, report/API).
4. Tasks 8–9 in the final 3 hours (dashboard, rehearsal, one live canary attempt, then replay fallback/freeze).

The real AndroZoo metadata download continues in parallel. Dataset extraction/training is admitted only if Task 3 has landed and the sample list has a non-empty `train`, `calib`, and `test` split; otherwise this demo explicitly uses `rule-based-prior-v1` and makes no trained-model claim.
