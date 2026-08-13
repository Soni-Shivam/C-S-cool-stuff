# DRISHTI — Onboarding, Methodology, and Honest Status

For a contributor new to this repo. Written 2026-08-13. Verified against live GCP state and a
full test run at time of writing. Where something is not done, it says so.

---

## 1. What the system is, in one paragraph

A user is about to install an APK. DRISHTI analyses it *before* installation and returns a
0–100 threat score, a plain-English explanation, and a cryptographically signed evidence trail
where every claim points at a concrete artefact. It is decision support — Android still shows
its own installer and the user still decides. The novel part is that a GenAI layer acts as an
automated reverse engineer rather than a classifier, and a separate isolated lab actually
detonates malware to produce runtime evidence.

Two things are deliberately kept apart, and confusing them is the most common mistake:

| | Training pipeline | Inference pipeline |
|---|---|---|
| When | Offline, batch, in the lab | Real time, per upload |
| Input | 6,000 APKs → numeric features | One APK |
| Output | `model.joblib` | A report |
| Executes malware? | **No** — static parse only | **No** — never |
| Where | `m3-extractor` VM | FastAPI service |

The model does **not** learn per sample at request time. New samples go to a review queue for a
scheduled retrain. Detonation is a *third*, separate thing that happens only in the sealed lab
and never inside the API.

---

## 2. Repository map

```
backend/drishti/            the library — M1..M7
  ingestion/ingest.py       M1  hash, threat-intel fast pass  -> ApkBundle
  ingestion/reputation.py   M1  graded reputation feed (NEW)
  static/androguard_adapter.py  M2  parse_apk() — the only APK parser
  static/rules.py           M2  permission combos, MITRE map, severity
  static/yara_scan.py       M2  YARA
  static/analyzer.py        M2  orchestrates the above -> StaticResult
  ml/features.py            M5  FEATURE_NAMES (35) — shared by train AND infer
  ml/model.py, train.py     M5  HistGradientBoosting + Platt calibration
  ml/evaluate.py            M5  evaluate_time_split() — the paper's §9.1 numbers
  ml/classify.py            M5  classify() -> p_cal
  llm/provider.py           M4  LLMProvider interface
  llm/gemini.py, mock.py    M4  live Gemini, deterministic mock
  genai/reason.py           M4  VERDICT_SCHEMA, prompt, injection defence
  sandbox/simulate.py       M3  SIMULATED behaviour (never executes)
  sandbox/real.py           M3  ingests real detonator output (NEW: aggregation)
  sandbox/containment.py    M3  signed manifests + control-plane attestation
  sandbox/observation.py    M3  ObservationArtifact schema
  sandbox/redaction.py      M3  redact_text()
  sandbox/interrogation.py  M3  bounded closed loop
  sandbox/catalog.py        M3  allowlisted hooks/stimuli
  ledger/ledger.py          hash-chained append-only evidence ledger
  ledger/signing.py         Ed25519 sign/verify
  ledger/verifier.py        drops GenAI claims citing non-existent nodes
  scoring/engine.py         M6  S, confidence, severity bands
  scoring/anomaly.py        M6  zero-day escalator (NEW)
  reporting/report.py       M7  build_android_report()
  reporting/artifacts.py    M7  YARA + Frida + STIX generation (NEW)
  pipeline/pipeline.py      wires M1->M2->M5->M3->M4->M6
  api/app.py, worker.py     FastAPI upload/poll, isolated parser worker

backend/scripts/            operator tools, NOT imported by the API
  build_sample_list.py      AndroZoo index -> balanced time-split sample list
  androzoo_extract.py       download -> static features -> DELETE apk -> CSV
  train_real.py             features CSV -> model + metrics
  dynamic_analyze.py        THE HARNESS. only place a sample is executed
  frida_hooks.js            passive hook catalogue
  verify_containment.py     8 probes -> signed containment manifest
  attest_runtime_control_plane.py   operator-signed half of containment
  emulator_control.sh       start/health/snapshot-restore/stop
  accept_m3_fixture.py      validate + publish an artifact under its hash
  emit_artifacts.py         run pipeline -> write YARA/Frida/STIX (NEW)
  analyze_batch_observations.py  cross-family behaviour summary (NEW)
  malwarebazaar_fetch.py    family-labelled sample fetcher (NEW, unused - needs key)

infra/m3/                   lab infrastructure
  packer/builder_setup.sh   builds the immutable tools image
  packer/detonator.pkr.hcl  Packer template
  terraform/runtime/        sealed n2-standard-4 definition
  runtime_lockdown.sh       host iptables deny-all
  runtime_prepare.sh        boot: keys, proxy, emulator
  fake_c2.py                mitmproxy no-upstream responder

android-client/             Kotlin/Compose companion app
demo-apks/                  inert fixtures (m3-inert-fixture, shady-demo, bank-one/two)
M3_RUNBOOK.md               the safety procedure — read before touching the lab
docs/gcp-lab-runbook.md     GCP design rationale
docs/gcp-pipeline-stepbystep.md  phased plan
```

---

## 3. Data flow for one analysis (follow the code)

`pipeline.py:run_pipeline()` is the spine. In order:

1. **M1** `ingest()` → SHA-256, size, `intel_hit` against `drishti/data/known_bad_hashes.txt`,
   and a graded `reputation_r`. Appends `ingest` + `intel` ledger nodes.
2. **M2** `parse_apk()` once (Androguard), then `analyze_parsed()` → permissions, combos
   (`rules.py:PERMISSION_COMBOS`), IOCs, cert facts, YARA hits, `signature_severity` (`G`).
   Appends `manifest`, `api_sink`, `ioc`, `cert`, `mitre_tag` nodes.
3. **M5** `classify()` reuses the same parse → `p_cal` (calibrated probability).
   Appends `ml_signal`.
4. **M3** one of three, explicitly chosen by the caller — never inferred:
   - `absent` → `absent_result()`. What the public API uses.
   - `simulated` → `interrogate()`. Labelled `[SIMULATED]`, cannot raise the dynamic score.
   - `observed` → `ingest_real()`. Requires a SHA-matched artifact from the detonator.
     Appends `dynamic_obs` nodes prefixed `[OBSERVED]`.
5. **M4** `reason()` → Gemini with a strict JSON schema. Instructions and untrusted data are
   separated (prompt-injection defence). `ledger/verifier.py` then **drops any claim citing a
   node ID that does not exist** — this is the anti-hallucination gate.
6. **M6** `score_verdict()`:
   ```
   F_AI = p_cal + B - (p_cal * B)          # joint prob, not a sum
   S    = 100 * min(1, 0.25R + 0.50F_AI + 0.15G + 0.10D)
   C    = gamma * (1 - |p_cal - B|)        # confidence = detector agreement
   ```
   Then `anomaly.py:escalate()` may raise the band on novelty grounds. Appends
   `score_factor` nodes.
7. **M7** `build_android_report()` → citation-checked report; `artifacts.py:generate_all()` →
   YARA + Frida + STIX.
8. Ledger is Ed25519-signed (`sign_ledger`).

**Key invariant:** `D` (dynamic contribution) is non-zero *only* when
`dynamic.status == "observed"`. Simulated behaviour can never move the score. See
`pipeline.py` lines around the `d = max(0.0, dynamic.b_dynamic - g) if ... == "observed"`.

---

## 4. The lab: how detonation actually works

Only `scripts/dynamic_analyze.py` ever executes a sample, and only on the sealed runtime.

**Mandatory sequence per sample** (all in `DynamicHarness.run()`, every exit through `finally`):

```
hash APK
  -> load_and_verify_manifest()      signed, fresh, correct signer, else ABORT
  -> aapt badging -> package name
  -> restore snapshot "clean"        BEFORE
  -> adb root, push+start frida-server
  -> adb install -r -g               (now with retry + refusal classification)
  -> collect_frida(): spawn, load frida_hooks.js, monkey stimulus, collect
  -> stop frida, uninstall
  -> restore snapshot "clean"        AFTER
  -> prove package absent
  -> write 0600 SHA-bound artifact   (success OR failure — always)
```

Empty output is `inconclusive`, **never** benign. Snapshot failure makes the artifact
non-ingestible (`safe_for_ingestion == False`), so the pipeline refuses it.

**Two-party containment.** Neither half alone is trusted:

- `scripts/attest_runtime_control_plane.py` runs on an authenticated control machine and
  checks via the GCP API: no external IP, **no Cloud NAT on the network**, no service account,
  exact machine type, nested virt on, `detonator` tag, auto-delete disk. Signs an attestation
  with a reviewer key that never touches the runtime.
- `scripts/verify_containment.py` runs on the runtime, verifies that attestation, then probes
  8 things from the inside and signs a short-lived manifest (≤30 min).

`sandbox/containment.py` types all 8 checks as `Literal[True]`, so a single false value fails
Pydantic validation. Fail-closed by construction.

**Live GCP resources** (project `drishti-m3-08130038`, zone `asia-south1-a`):

| Resource | Role | Network |
|---|---|---|
| `drishti-m3-tools-v1` (image) | immutable tools + clean AVD snapshot | — |
| `drishti-detonator` | sealed runtime; executes malware | `drishti-m3-runtime`, **no NAT**, deny-all egress |
| `m3-extractor` (n2-standard-16) | downloads + static-parses corpus | `drishti-m3-builder`, egress 443 only |
| `m3-control-builder` | operator box (packer/terraform installed) | `drishti-m3-builder` |
| `m3-detonator-debug` | stopped; was used to build the image | — |

The runtime is on its own VPC **because** the attestation requires no Cloud NAT on the
network, while the extractor needs NAT to reach AndroZoo. Samples move
extractor → runtime over IAP, so bytes never transit a laptop.

---

## 5. Methodology

### 5.1 Labelling and the corpus
`build_sample_list.py` reads AndroZoo's `latest.csv` metadata index (hashes + VT counts +
dates; **no APK bytes**) and applies a deliberately conservative policy:

- malware := `vt_detection >= 10` (strong multi-engine consensus)
- benign := `vt_detection == 0` **and** distributed via `play.google.com`
- **discarded**: `1 <= vt < 10` — the adware/grey zone. Excluding it avoids training on label
  noise, and this must be stated in the paper.

### 5.2 Time-split evaluation
Train on `dex_date < cutoff`, test on `>= cutoff` (2021-01-01 in the current list). Testing on
strictly newer samples measures generalisation to unseen families; a random split would
flatter the model. `ml/evaluate.py:evaluate_time_split()` reports precision, recall, PR-AUC,
ROC-AUC, FPR and a calibration table.

### 5.3 Why calibration is mandatory
Platt/isotonic calibration means `p_cal = 0.8` genuinely implies ~80% of samples at that score
are malicious. Without it the joint fusion `F_AI` is not probabilistically meaningful. This is
the difference between DRISHTI and asking an LLM to "rate this 0–100".

### 5.4 Evidence grounding
Agents may only **append** to the ledger; they cannot modify each other's evidence. Every
GenAI sentence must cite ≥1 node ID, and `verifier.py` mechanically drops unsupported claims.
Re-running the same APK yields a structurally identical ledger.

### 5.5 Avoiding a circular benchmark — important
Our labels come from VT counts. Feeding those same counts into the score's `R` term leaks the
label. So `reputation.py` marks such a feed `label_derived=True` and **refuses it by default**;
only production lookups pass `allow_label_derived=True`. ML metrics are unaffected because
`evaluate.py` never sees `R`. If you report precision/recall over `S` with a VT-derived feed
enabled, the number is meaningless.

### 5.6 Safety model
- No malware on any personal device, ever. Static extraction happens on a cloud VM; the laptop
  only receives `features.csv` (numbers) and sanitized JSON.
- The extractor **never executes** an APK; it parses and deletes.
- The runtime has zero egress, so a sample cannot reach real C2.
- OTPs, message bodies, credentials, tokens, clipboard and device values are redacted before
  serialization (`sandbox/redaction.py` + `frida_hooks.js`).
- Detonation ladder: inert fixture → known-benign → one vetted sample, each with a per-sample
  `PilotAuthorization` naming its exact SHA-256.

---

## 6. What is actually achieved

Verified, not aspirational:

- **124 tests pass** (`cd backend && python -m pytest tests/ -q`).
- **M1–M7 run end to end with live Gemini** (`gemini-3.1-pro-preview`), twice demonstrated:
  - F-Droid: ML said malicious (`p_cal=0.836`); Gemini identified the legitimate app store and
    explained the false positive. Final 56/100 Medium, **confidence 0.25 Low** — low *because*
    signals disagreed.
  - Real trojan: Gemini named the lure ("Fake Update Lure" / "Mobile Banking Application"),
    fused static techniques with `T1407`/`T1426` from our own detonation, cited 5 nodes,
    **confidence 0.92 High** because ML and reasoning agreed.
- **Immutable image built**: `drishti-m3-tools-v1`, containing Android 30 `google_apis` x86_64
  AVD with a verified clean snapshot, frida 16.7.19 client+server, and the harness.
- **Sealed runtime launched and independently confirmed contained** — `curl` to the internet
  fails from inside; all 8 probes true; signed manifest issued.
- **Snapshot restore semantics proven**, not assumed: a dirty marker vanishes after restore.
- **9 real malware samples executed**, 7 with behavioural data (see §7 for the honest caveat).
- **Anatsa cluster signature found empirically**: 4/4 droppers → exactly `T1407 + T1426`.
- **`Cipher.doFinal` × 1,925 in 60 s** captured from an Alipay-impersonating sample whose only
  technique was `T1521` — it defeats network TLS inspection; the memory hook still got
  plaintext. This is the paper's anti-evasion claim, demonstrated.
- **M7 artifacts validated**: YARA compiles under real `yara-python`; campaign rule achieves
  **4/5 sibling recall with 0/6 false positives**, including `com.bankofamerica.mobile` and
  `com.icicibank.pockets` — a bank-trojan rule must never match a bank's own app.
- **Zero-day escalator**: a novel dropper that would score Low/31 escalates to **High/65** with
  a review flag and a user warning that says "unverified rather than safe" while explicitly
  **not** claiming a known-family match.

---

## 7. What is NOT achieved — the real holes

Ordered by how much damage each does to a submission.

### H1. No benign controls were detonated — **the biggest hole**
All 4 selected benign APKs 404'd on AndroZoo. Consequence: the **dynamic false-positive rate
is unmeasured**. We can say malware exhibits `T1407`/`T1426`; we **cannot** say those
techniques *distinguish* malware from ordinary apps. `analyze_batch_observations.py` prints
`"no benign controls detonated, so discriminative power cannot be measured"` — that line is
telling the truth. Any claim of behavioural discrimination is currently unsupported.

### H2. Nine executed samples is a pilot, not an evaluation
Honest disposition of the 14 submitted:

| Outcome | n |
|---|---|
| Executed, behaviour captured | 7 |
| Executed, emitted nothing (stalling) | 2 |
| Installed, never started (receiver-only, no launcher) | 1 |
| Never installed (API 30 refused the APK) | 4 |

A batch log line reading `detonated=12` only meant "an artifact file was written" — it
included install failures. Do not quote 12. **9 executed, 7 with data.**
No percentage (least of all ">80% Level-2 detection") can be defended from this.

### H3. The corpus does not match the paper's stated targets
`backend/samples.csv` (6,000 rows) is mostly 2011–2021 adware / SMS fraud / droppers:
20 samples from 2023, **4 from 2024, 3 from 2025**. The paper names OverlayPhantom, Klopatra,
TsarBot, ToxicPanda, Sturnus as *primary* detection targets. AndroZoo also has **no family
labels**, so campaign attribution has nothing to validate against.
`scripts/malwarebazaar_fetch.py` is written for exactly this and is **unused — it needs a free
abuse.ch API key**. Decision pending: get the key, or soften §9.2 and Table 9.

### H4. No HTTPS interception — the flagship novelty is not available
I dropped `-writable-system` because it wedges the emulator in `adb offline` state and caused
repeated boot hangs. Consequence: the mitmproxy CA is **not** in the guest system trust store,
so **Generative C2 emulation over HTTPS does not work**. `infra/m3/fake_c2.py` exists and
`mitmproxy` is installed, but a sample using HTTPS will not have its traffic decrypted.
`Cipher.doFinal` hooks cover plaintext-before-encryption, which is a genuine mitigation but a
*different* claim from "we synthesise C2 responses".

### H5. Frontier features are design, not code
JIT environment synthesis, dynamic sandbox morphing, and the vision-language impersonation
check (paper §6.2, §6.4, §4.4.4) **do not exist as code**. `sandbox/interrogation.py` +
`catalog.py` implement a bounded allowlisted loop, which is the scaffolding, not the feature.

### H6. Install yield
4/14 refused by API 30 with `INSTALL_PARSE_FAILED_NO_CERTIFICATES` — `sdkVersion:'3'` samples
with stripped `META-INF`. One of them installed fine on retry, so some failures are
**transient**. Now retried 3× and classified as `install_unsupported` (tooling limit) vs
`install_failed`, so a tooling gap is no longer scored as evasion. Ancient samples may need an
older AVD.

### H7. Real ML numbers do not exist yet
`models/` and `observations/` were **empty** at session start; the demo used a synthetic
baseline reporting `baseline-synthetic-v1`. Extraction is running now
(4,103 / 6,000 rows, balanced: test 825 benign / 830 malware). Until it finishes and
`train_real.py` runs, **every metric in Table 9 is a target, not a result.**

### H8. Housekeeping traps
- `latest.csv` in the repo root **and** `backend/` is a saved **404 HTML page**, not the
  AndroZoo index. Re-download before building any new sample list.
- `LEDGER_SIGNING_KEY` in `backend/.env` is empty (keys are auto-generated per run).
- `backend/e2e_genai.py` is my scratch driver, untracked — move it under `scripts/` or delete.
- API keys were shared in plaintext in chat; **rotate after submission**.

---

## 8. Defects found and fixed this session (11)

Five blocked the build; the rest were silently wrong, which is worse.

| # | File | Defect | Consequence |
|---|---|---|---|
| 1 | control VM `gcloud` config | active account had **no credentials** | Packer IAP tunnel `4033 not authorized` — **the original blocker** |
| 2 | `infra/m3/packer/builder_setup.sh` | missing `libxkbfile1` + X/GL/xkb libs | `qemu-system-x86_64` could not start at all |
| 3 | same | `frida>=17` needs Python 3.11; Ubuntu 22.04 has 3.10 | `import frida` failed → **`collect_frida()` broken**, not just a probe |
| 4 | same | server URL built from crashing `frida` CLI → empty → 404 | image would ship with **no frida-server** |
| 5 | `scripts/emulator_control.sh` | `-writable-system` | guest wedges `adb offline`; removed |
| 6 | `scripts/verify_containment.py` | **`toybox nc -z` — flag does not exist on Android** | all 3 emulator probes passed unconditionally; manifests attested untested containment |
| 7 | same | crashed on `subprocess.TimeoutExpired` | verification flaky by DNS-cache state |
| 8 | `drishti/sandbox/real.py` | `ingest_real` uncapped, one node per raw event | 1,925 near-identical ledger nodes → prompt blow-up; now aggregated to 1 |
| 9 | `scripts/build_sample_list.py` | no dex_date plausibility window | 1,235/6,000 rows (20.6%) at 1980/1981 or 2039–2107 → **time split invalid** |
| 10 | `scripts/androzoo_extract.py` | serial, and bucket-ordered | 21h runtime; first 1,553 rows had **zero** test samples |
| 11 | `scripts/dynamic_analyze.py` | install refusal == evasion; receiver-only unhandled | tooling limits mis-scored; SMS trojans unanalysable |

**Defect 6 deserves separate emphasis.** Android's toybox `nc` has no `-z` flag; it exits 1
with `nc: Unknown option 'z'`, so `blocked()` returned `True` no matter what the network did.
`emulator_internet_blocked`, `emulator_metadata_blocked` and `emulator_vpc_blocked` all passed
vacuously. **Any containment manifest signed before this fix is worthless and must not be
cited.** The probe now parses an explicit `DRISHTI_RC=$?` and `assert_probe_trustworthy()`
runs a negative control (`127.0.0.1:1`) and a positive control (its own listener) so a broken
probe fails closed instead of reading as perfect isolation.

**Scoring was also mis-calibrated.** `R` was `1.0 if intel_hit else 0.05` against a 6-entry
known-bad list, so 24 of 25 reputation points were dead and a 39/40-detection banking trojan
scored **64/100 "Medium"**. With `reputation.py` wired in it scores **88/100 "Critical"** — for
a fraud desk, the difference between monitor and block.

New files: `drishti/ingestion/reputation.py`, `drishti/scoring/anomaly.py`,
`drishti/reporting/artifacts.py`, `scripts/emit_artifacts.py`,
`scripts/analyze_batch_observations.py`, `scripts/malwarebazaar_fetch.py`,
`tests/test_anomaly_escalation.py`, `tests/test_artifacts.py`.
Diff: **735 insertions, 110 deletions across 11 tracked files.**

---

## 9. How to run things

```bash
# tests (do this first)
cd backend && python -m pytest tests/ -q          # expect 124 passed

# API locally
cp .env.example .env                              # set DEMO_API_TOKEN
docker compose up --build
curl http://localhost:8000/health

# end-to-end with live Gemini, no dynamics
cd backend && python e2e_genai.py samples/fdroid.apk absent

# with real detonator observations
python e2e_genai.py <apk> observed <observations.json>

# train on real features (once extraction finishes)
python scripts/train_real.py features.csv \
  --save drishti/data/models/androzoo.joblib --metrics-json metrics.json

# behavioural summary across a detonation batch
python scripts/analyze_batch_observations.py \
  --results-dir observations --sample-list batch_samples.txt

# M7 campaign artifacts
PYTHONPATH=. python scripts/emit_artifacts.py \
  --apk-dir /opt/drishti/quarantine --observations-dir /opt/drishti/observations \
  --out-dir /opt/drishti/artifacts
```

**Local network caveat:** this laptop's network intermittently mangles TLS to
`*.googleapis.com` (`SSL: WRONG_VERSION_NUMBER`, roughly 1 call in 5 succeeds). Wrap `gcloud`
in a retry loop for anything scripted.

---

## 10. Recommended order for the remaining four days

1. **Benign controls** — detonate 10–15 known-good apps, measure the dynamic FP rate. Closes
   H1, the cheapest fix with the largest credibility gain.
2. **Train on the full corpus** when extraction lands; report real time-split numbers instead
   of targets. Closes H7.
3. **Scale detonation to 50–60 samples** now that retry + receiver-stimulus handling are in.
   Reduces H2.
4. **Decide on MalwareBazaar** — get the key, or soften §9.2/Table 9 to the distribution we
   actually evaluated. H3 cannot be closed without a sample feed.
5. **Decide on Generative C2** — invest in the CA work, or reframe around `Cipher.doFinal`
   interception, which we can prove. H4.

**Bottom line:** the engineering is sound and the novel mechanism is demonstrated on real
malware with signed containment evidence. The risk is no longer "does it work" — it is "can we
defend the numbers". Every remaining gap is evaluation coverage, and all are addressable in
four days except H3, which depends on getting a family-labelled feed.
