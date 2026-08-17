# M3 live detonation — design

**Date:** 2026-08-17 · **Phase:** P4 (T4.1–T4.6) · **Status:** approved, pre-implementation
**Depends on:** `92a6aea` (m3_dynamic normaliser/evasion/containment/hooks landed),
P0 T0.7 (`TraceSource`), the sealed-lab runbook (`M3_RUNBOOK` supplied by the operator).

---

## 0. Why this spec exists

A prior status note claimed *"M3 dynamic sandbox — 0% built. Nothing exists."* That was
true before commit `92a6aea` and is stale now. The accurate state:

**Already built (real, tested code on `main`):**

| Piece | Location |
|---|---|
| Detonator wire contract (`ObservationArtifact`, `ObservationEvent`, `HarnessMetadata`, `SnapshotLifecycle`, `FailureRecord`) | `drishti/contracts/dynamic_trace.py` |
| Containment verification (toybox-`nc` fix, fail-closed, probe-trustworthiness controls) | `drishti/m3_dynamic/containment.py` |
| Evasion detection (probe→miss→stall) | `drishti/m3_dynamic/evasion.py` |
| Trace normalisation + aggregation + `b_dynamic` | `drishti/m3_dynamic/normaliser.py` |
| Frida hook catalogue (`emit()` shape matches the v1 collector exactly) | `drishti/m3_dynamic/scripts/hooks.js` |
| Redaction (fail-closed egress) | `drishti/m3_dynamic/redaction.py` |
| Replay source + honesty enforcement | `drishti/m3_dynamic/trace_source.py` |
| GCP Packer image / Terraform runtime / lab scripts | `infra/gcp/**` |
| Pipeline wiring (resolves source from `sandbox_mode`, runs frontier loop, feeds `D`) | `drishti/pipeline.py` |

**Missing: the live runtime execution layer.** `LiveSandboxSource.run()` raises by
design; nothing yet boots an emulator, loads `hooks.js`, or produces a captured trace.
Every dynamic number today comes from two committed replay fixtures.

v1 left a production-grade 523-line `dynamic_analyze.py` (fails closed, handles
receiver-only SMS trojans, classifies install failures, asserts snapshot hygiene). It
is the thing to port, and the v2 wire contract was reconciled from its output, so the
port is largely an import swap.

**Non-negotiable constraint:** detonation runs *only* on the sealed GCE detonator VM
(CLAUDE.md). No sample is ever executed on the laptop or in CI. All laptop work is
tested against mocked `adb`/`frida`.

---

## 1. Scope

### In scope
1. Signed containment manifest (`sign_manifest` / `load_and_verify_manifest`) — the
   layer the ported harness imports and that `runtime_prepare.sh` already generates a
   keypair for.
2. `scripts/verify_containment.py` — CLI that verifies containment and writes the
   signed manifest. (Runbook §0.3 blocker.)
3. `drishti/m3_dynamic/harness.py` — the ported v1 harness, importable and unit-testable.
4. `scripts/dynamic_analyze.py` — thin CLI entrypoint over `harness.py`. (Runbook §0.3
   blocker.)
5. `drishti/m3_dynamic/trace_builder.py` — `ObservationArtifact → DynamicTrace`, incl.
   the deterministic `detonated` rule (T4.6).
6. `infra/gcp/fake_c2.py` — sinkhole addon (`runtime_prepare.sh` references it).
7. `detonator.pkr.hcl` path fixes (v1 `backend/*` → v2 paths); `.env` region → `us-east1-c`.
8. `LiveSandboxSource.run()` + `available()` made real (SSH-over-IAP → harness → pull
   artifact → convert).
9. Live GCP execution: image build → VPCs → VM → containment gate → canary detonation →
   one corpus-sample detonation → `lab-down`.
10. `emulator.py` extracted from the harness **after** the first live trace succeeds.

### Out of scope (recorded deviations, not silent omissions)
- **LLM crash-repair loop (T4.3):** the ported harness already restores snapshots on
  failure and falls back to network-only. The LLM repair adds an LLM dependency and
  risk for marginal gain. Deferred.
- **TLS system-CA interception (T4.4):** runbook defers it; `Cipher.doFinal` yields
  plaintext before encryption, which is the stronger result and also defeats T1521.
- **Generative C2 (P5):** `fake_c2.py` is a static sinkhole here; synthesised responses
  are P5.
- **Multi-pass morphing (P5).**

---

## 2. Architecture

### 2.1 Component boundaries

```
                          LAPTOP / APP SIDE                         SEALED VM
                          ----------------                         ---------
  pipeline._dynamic ──> LiveSandboxSource.run(apk, plan)
                              │  1. gsutil cp apk → corpus bucket
                              │  2. ssh --tunnel-through-iap ────────>  scripts/dynamic_analyze.py
                              │                                          │  verify signed manifest (fail closed)
                              │                                          │  snapshot restore (before)
                              │                                          │  start frida-server
                              │                                          │  install sample (classify failures)
                              │                                          │  collect_frida: spawn-gated, load hooks.js
                              │                                          │  run stimuli window
                              │                                          │  snapshot restore (after) + assert clean
                              │                                          ▼
                              │  3. gsutil cp ObservationArtifact <──── artifacts bucket
                              │  4. trace_builder(artifact) ──> DynamicTrace
                              ▼
                       pipeline consumes DynamicTrace (normaliser + evasion already wired)
```

The VM emits only `ObservationArtifact` — the redacted, `strict=True`,
`simulated=False`-pinned wire contract. `DynamicTrace` assembly (normalise, evasion,
`detonated` rule) runs app-side where it is fully unit-tested, keeping the VM harness
minimal.

### 2.2 New / changed units

| Unit | Responsibility | Depends on |
|---|---|---|
| `containment.ContainmentManifest` (new model) | instance_id, verified_at, report, signature | contracts base |
| `containment.sign_manifest(report, key) -> ContainmentManifest` | Ed25519 sign the verified report | `cryptography` |
| `containment.load_and_verify_manifest(path, pubkey) -> ContainmentManifest` | load, verify signature + freshness, fail closed | `cryptography` |
| `scripts/verify_containment.py` | CLI: `verify()` → sign → write manifest | containment |
| `m3_dynamic/harness.py` | `DynamicHarness`, `collect_frida`, `HarnessConfig` | contracts, containment, redaction |
| `scripts/dynamic_analyze.py` | CLI over harness; FD-safe, flock, arg parsing | harness |
| `m3_dynamic/trace_builder.py` | `artifact_to_trace(artifact, *, source, provenance) -> DynamicTrace` | normaliser, evasion |
| `infra/gcp/fake_c2.py` | mitmproxy sinkhole addon | (runs on VM) |
| `trace_source.LiveSandboxSource` | real `run()` + `available()` | harness invocation over IAP, trace_builder |
| `m3_dynamic/emulator.py` (post-first-trace) | thin `Emulator` class extracted from harness | subprocess/adb |

### 2.3 The `detonated` rule (T4.6) — written down once

`detonated` is deterministic, computed in `trace_builder` over the normalised
observation groups. It is `True` iff **any** of these fired, and `detonation_reason`
records the first:

| Rule | Fires when |
|---|---|
| `runtime_dex_load` | technique `T1407` observed (DexClassLoader / InMemoryDexClassLoader / PathClassLoader) |
| `sms_forwarded` | `SmsManager.sendTextMessage` hook observed (`T1582`) |
| `overlay_added` | `WindowManager.addView` observed (`T1417`/overlay) |
| `accessibility_automation` | accessibility automation technique observed (`T1417`) |
| `decrypted_payload` | a decrypted blob whose preview contains a URL or dex magic |
| `command_exec` | `Runtime.exec` / `ProcessBuilder` observed (`T1623`) |

If none fired: `detonated=False`. An empty observation set → `outcome="inconclusive"`,
never benign (CLAUDE.md honesty requirement; enforced already by `evasion.detect`).

### 2.4 Adapters

`ObservationEvent` (technique/mitre/detail/source_hook/occurred_at) →
`normaliser.aggregate` expects dicts keyed `technique`/`mitre`/`source_hook`/`detail`. A
one-function adapter maps events to those dicts. Structured `DexLoadEvent` /
`NetworkFlow` / `DecryptedBlob` collections may stay empty in this first pass — the
signal flows through `api_events`, `techniques`, `b_dynamic`, `evasion_observations`,
and the `detonated` rule keyed on techniques. This is honest and sufficient for a first
captured trace; structured extraction is a later enrichment.

---

## 3. Sequencing (dependency order)

**Stage 1 — Python harness (laptop, TDD, mocked adb/frida). No GCP spend.**
1. Signed manifest (`ContainmentManifest`, `sign_manifest`, `load_and_verify_manifest`) + tests.
2. `scripts/verify_containment.py` CLI + test.
3. Port `harness.py` (imports → v2), keep injectable seams + tests.
4. `scripts/dynamic_analyze.py` CLI + test.
5. `trace_builder.py` + `detonated` truth-table tests.
6. `infra/gcp/fake_c2.py` (ported) — light test / lint only (runs under mitmproxy).

**Stage 2 — Infra fixes.** Repoint `detonator.pkr.hcl`; add `fake_c2.py` to `infra/gcp/`;
set `.env` `DRISHTI_GCP_ZONE=us-east1-c`. Verify `builder_setup.sh` provisions resolve.

**Stage 3 — `LiveSandboxSource` real** (mocked SSH runner in tests) + `available()`.

`make test` green, ruff + mypy clean, before any GCP spend.

**Stage 4 — Live GCP (billable, real detonation). Checkpoint before starting.**
1. Stop extractor VM (`instance-20260817-080247`) — the larger bill.
2. `packer build` the detonator image (~$0.08, ~20 min).
3. Create `drishti-build` (NAT) + `drishti-runtime` (no NAT, deny-all) VPCs.
4. `terraform apply` the detonator VM; confirm `runtime_has_external_ip == false`.
5. `make lab-up`; `runtime_prepare.sh` over IAP.
6. **`make lab-verify` — containment gate. Aborts on failure, never warns.**
7. Detonate the **canary** (inert, `sample_kind=inert_fixture`): prove
   boot→install→hook→trace. Capture the result as a committed replay fixture
   (`data/fixtures/traces/{sha}.json`, `provenance.kind="captured"`).
8. Detonate **one corpus AndroZoo sample** (`sample_kind=vetted_malware`) under the
   `require_pilot_authorization` gate (human-review record).
9. `make lab-down`. Confirm no instance left running.

**Stage 5 — `emulator.py` extraction** from the now-proven harness; harness delegates to it.

---

## 4. Testing

`make test` runs contract+unit (CI gate; never touches GCP, never sees a sample).

| Test | Asserts |
|---|---|
| `test_containment_manifest` | sign→load round-trips; a tampered signature or body is rejected; stale `verified_at` fails closed |
| `test_verify_containment_cli` | writes a signed manifest on success; non-zero exit + no manifest on containment failure |
| `test_harness_happy_path` | injected collector → `ObservationArtifact`, `outcome="completed"`, snapshot before/after `passed` |
| `test_harness_install_classification` | `INSTALL_FAILED_NO_MATCHING_ABIS` → `install_unsupported`, never `install_failed` |
| `test_harness_receiver_only` | spawn `front-door activity` error → broadcast fallback path |
| `test_harness_fail_closed` | containment/snapshot failure → artifact with failure record, non-zero exit |
| `test_detonated_rule` | truth table over the §2.3 rules; empty set → `inconclusive` |
| `test_artifact_to_trace` | `ObservationArtifact` → schema-valid `DynamicTrace`; evasion populated; provenance fields set |
| `test_live_sandbox_source` | mocked SSH runner → pulls artifact → returns `DynamicTrace(source=LIVE)`; `available()` false when VM down |
| `@pytest.mark.gcp` lab tests | live containment + canary detonation; excluded from CI |

TDD: write the test first for every unit above (all are contract/harness/pure-logic —
the project's tests-first territory).

---

## 5. Honesty & safety properties preserved

- **Live-vs-replay is read from the trace**, never a config flag: `DynamicTrace`
  carries `emulator_image`, `vm_instance_id`, `harness_version`, `captured_at`,
  `containment_verified`. The UI badge derives from these.
- **A captured canary trace is `provenance.kind="captured"`**, so replaying it later is
  disclosed as replay, not presented as live.
- **`simulated` is unrepresentable** on the egress path (`Literal[False]`), and
  redaction is enforced twice (hook + `ObservationEvent` validator).
- **Containment is a gate, not a report:** `require_containment` raises; a failure
  aborts the batch. The signed manifest is what the artifact's provenance references.
- **A sample that emitted nothing is `inconclusive`**, never benign.
- **Real samples never touch the laptop:** GCS → VM scratch only.

---

## 6. Cost

Per the runbook: image build ~$0.08, detonator ~$0.19/hr while running, stopped ~$0.01/hr.
A full session (build + a handful of detonations + `lab-down`) is a few dollars, inside
the $50 project ceiling. `lab-down` is the last step of every session, not optional.

---

## 7. Open questions / risks

- **`hooks.js` has never executed.** It is statically audited in CI but the first live
  run is its first execution — expect to fix overload signatures and class-availability
  guards on the canary run (T4.3 territory, handled per-hook by the `safe()` wrapper
  already in the file).
- **ABI mismatch:** a corpus sample may be ARM-only vs the x86_64 image →
  `install_unsupported` (classified, not scored as evasion). Pick an x86-friendly
  sample for the first real detonation, or accept `inconclusive`.
- **IAP SSH invocation latency/robustness** inside `LiveSandboxSource` — wrap in a
  bounded retry; a single flaky `gcloud` call must not fail the job.
