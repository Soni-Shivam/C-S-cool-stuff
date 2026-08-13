# CARRIED FINDINGS — what v1 measured, and what it never managed to measure

v1's code is superseded. Its **findings are not.** This file exists so v2 does not
re-derive v1's bugs, re-quote v1's unsupportable numbers, or re-discover v1's holes at
hour 60.

Source: `v1-reference/docs/ONBOARDING_STATUS.md` §5–§8, written 2026-08-13 against live GCP
state. **Everything here is a v1 claim.** v2 has independently verified only what is marked
✅ VERIFIED-BY-V2.

The 14 real `ObservationArtifact` files were rescued off the detonator disk on 2026-08-14 and
are archived at `gs://drishti-v2-260814-artifacts/v1-provenance/observations/`, so the claims
below can be re-checked against the data rather than taken on trust. Two are committed as CI
fixtures.

---

## Part 1 — Bugs that were silently wrong. Do not reintroduce these.

Five blocked the build; six were *silently wrong*, which is worse. Each maps to the v2 task
that must not regress it.

| # | The bug | Consequence | v2 task | Guard |
|---|---|---|---|---|
| 1 | Control VM's `gcloud config` active account had **no credentials** (the SA did) | Packer IAP tunnel died `4033 not authorized` for **weeks**, misread as a missing IAM role | T0.9 | Before concluding "IAM", diff `gcloud auth list` against `gcloud config get account` on the VM |
| 2 | `builder_setup.sh` missing `libxkbfile1` + X/GL/xkb libs | `qemu-system-x86_64` could not start **at all**, even `-no-window` | T0.9 | Verify with `emulator -version`; `ldd` gives false "not found" (RPATH) |
| 3 | `frida>=17` imports `typing.NotRequired` (needs Py 3.11); Ubuntu 22.04 ships 3.10 | `import frida` raised → **the whole collector broke**, not just a version probe | T0.9 | Pin `frida<17`. Verified pair: 16.7.19 client + 16.7.19 android-x86_64 server |
| 4 | frida-server URL built from the crashing `frida` CLI → empty version → 404 | Image shipped with **no frida-server**; nobody noticed until detonation | T0.9 | Derive version from the *importable module*; `curl --location` |
| 5 | `-writable-system` | Guest wedges in `adb offline` indefinitely; `adb remount` lies about success | T4.1, T4.4 | Keep it off the critical path. Consequence is hole **H4** below |
| 6 | **`toybox nc -z` — the flag does not exist on Android** | `blocked()` returned `True` unconditionally. `emulator_internet_blocked`, `_metadata_blocked`, `_vpc_blocked` **all passed vacuously.** Signed manifests attested containment that was never tested | T0.9 | `toybox nc -w N HOST PORT </dev/null` + parse explicit `DRISHTI_RC=$?`; `assert_probe_trustworthy()` with negative (`127.0.0.1:1`) and positive (own listener) controls |
| 7 | Containment probe crashed on `subprocess.TimeoutExpired` | A blackhole `-j DROP` makes curl hang past `--max-time`; verification passed or aborted **depending on DNS cache state** | T0.9 | Map timeout → `TIMEOUT_RC=124` → read as *blocked* |
| 8 | `ingest_real` appended one ledger node **per raw event**, uncapped | A 1,925-event sample would put 1,925 near-identical nodes in the ledger and the prompt | T4.6 | `aggregate_observations`, `MAX_OBSERVATION_GROUPS=40`; `B` keys on *distinct* severities so it is unaffected |
| 9 | `build_sample_list.py` had no `dex_date` plausibility window | 1,235/6,000 rows (20.6%) at 1980/81 or 2039–2107 → **the time split was invalid** | T2.2 | `--min-date`/`--max-date`, and report how many rows were dropped |
| 10 | `androzoo_extract.py` ran serially over a bucket-ordered list | 21h runtime, and the first 1,553 rows contained **zero** test samples, so time-split eval could not run at all | T2.2 | Deterministic interleave by (split, label); parallelise |
| 11 | Install refusal was scored as **evasion**; receiver-only apps unhandled | Tooling limits mis-scored as sample behaviour; SMS trojans unanalysable | T4.1 | Retry 3×, classify `install_unsupported` (tooling) vs `install_failed`; handle apps with no launcher activity |

> **Bug 6 has a retroactive consequence.** Any containment manifest signed before that fix is
> worthless. **Do not cite v1 containment attestations.** v2 re-verifies from scratch.

Also mis-calibrated, and worth its own line: `R` was `1.0 if intel_hit else 0.05` against a
**6-entry** known-bad list, so 24 of the 25 reputation points were dead. A 39/40-detection
banking trojan scored **64/100 "Medium"**. With graded bands it scores **88/100 "Critical"** —
for a fraud desk, the difference between *monitor* and *block*. → T2.7.

---

## Part 2 — Holes. Claims v2 must not inherit.

Ordered by how much damage each does to a submission.

### H1 — No benign controls were ever detonated · **the biggest hole**
All 4 selected benign APKs 404'd on AndroZoo. So the **dynamic false-positive rate is
unmeasured.** v1 can say malware exhibits `T1407`/`T1426`; it **cannot** say those techniques
*distinguish* malware from ordinary apps. Any claim of behavioural discrimination is
unsupported.
→ **P4 must detonate benign controls.** `analyze_batch_observations.py` prints
*"no benign controls detonated, so discriminative power cannot be measured"* — keep that line
until it is false.

### H2 — Nine executed samples is a pilot, not an evaluation · ✅ VERIFIED-BY-V2
Honest disposition of 14 submitted: **7 executed with behaviour captured**, 2 executed and
emitted nothing (stalling), 1 installed but never started (receiver-only, no launcher), 4 never
installed (API 30 refused).

**v2 re-derived this from the 14 rescued artifacts themselves** (2026-08-14): outcomes are
7 `completed` / 2 `inconclusive` / 5 `failed`; exactly 7 carry observations and 2 executed
with zero. Failure codes: 4 × `install_failed`, 1 × `internal_error`. So **9 executed, 7 with
data** is confirmed, and v1's "1 receiver-only + 4 never installed" is the `internal_error`
plus the four `install_failed`.

A batch log line reading `detonated=12` only meant "an artifact file was written" — it counted
install failures. **Never quote 12. It is 9 executed, 7 with data.** No percentage — least of
all ">80% Level-2 detection" — can be defended from this. → T4.7, and the honesty gate in
`CLAUDE.md`.

### H3 — The corpus does not match the paper's stated targets
`samples.csv` is mostly 2011–2021 adware / SMS fraud / droppers: 20 samples from 2023,
**62 from 2024, 55 from 2025** (v2 re-counted ✅ VERIFIED-BY-V2). The paper names
OverlayPhantom, Klopatra, TsarBot, ToxicPanda and Sturnus as *primary* targets. AndroZoo also
has **no family labels**, so campaign attribution has nothing to validate against.
→ T2.2: fresh AndroZoo index + recency-weighted selection; a free abuse.ch key would give
family labels via the already-written `malwarebazaar_fetch.py`.

### H4 — No HTTPS interception · the flagship novelty was not available
`-writable-system` was dropped (bug 5), so the mitmproxy CA never reached the guest system
trust store, so **Generative C2 emulation over HTTPS did not work**. `fake_c2.py` exists and
mitmproxy was installed, but a sample using HTTPS was never decrypted.
`Cipher.doFinal` hooks give plaintext-before-encryption, which is a genuine and arguably
stronger mitigation — **but it is a different claim** from "we synthesise C2 responses".
→ T4.4, T5.4. Do not conflate the two on a slide.

### H5 — Frontier features are design, not code
JIT environment synthesis, dynamic sandbox morphing, and the vision-language impersonation
check **do not exist as code** in v1. `interrogation.py` + `catalog.py` are a bounded
allowlisted loop — scaffolding, not the feature. → **P5 is greenfield.** Budget accordingly.

### H6 — Install yield
4/14 refused by API 30 with `INSTALL_PARSE_FAILED_NO_CERTIFICATES` — `sdkVersion:'3'` samples
with stripped `META-INF`. **One installed fine on retry, so some failures are transient.**
Ancient samples may need an older AVD. → T4.1.

### H7 — Real ML numbers did not exist
`models/` and `observations/` were empty; the demo used `baseline-synthetic-v1`. Extraction was
at 4,103/6,000 when the status doc was written. **Every metric in the paper's Table 9 is a
target, not a result.** → T2.3, and the honesty gate: no number in UI or report without a
measurement in `STATUS.md`.

### H8 — Housekeeping traps
- `latest.csv` (root **and** `backend/`) is a saved **404 HTML page**, not the AndroZoo index.
  ✅ VERIFIED-BY-V2. Re-download before building any sample list.
- `LEDGER_SIGNING_KEY` was empty → keys regenerated per run, so chains were not comparable
  across runs. → T0.4 `load_or_create_key()`.
- API keys were shared in plaintext. **Rotate.** ✅ VERIFIED-BY-V2 (both still present in v1's
  `.env`, still unrotated).
- **Additional finding by v2 — the v2 wire contract could not read v1's real output.** All 14
  rescued artifacts failed `ObservationArtifact` validation, because the port dropped three
  fields the harness actually emits: `duration_s`, `diagnostics` (which carries the containment
  manifest reference) and `mitre_observed`. Nothing would have caught this until the first P4
  ingestion. Fixed, and two real artifacts are now committed as CI fixtures
  (`tests/contract/test_real_observation_artifacts.py`) so it cannot regress. Addendum A8.
  Notably, **every nested model matched exactly** — the port was faithful below the top level.
  ✅ VERIFIED-BY-V2
- **Additional finding by v2:** five of v1's most valuable files were **never committed** —
  they existed only in the working tree (`builder_setup.sh` 76→195 lines,
  `verify_containment.py` 91→191, `androzoo_extract.py` 101→220, `ingest.py` 65→107,
  `test_ingestion.py` 35→80; ~735 insertions total). One `git clean` would have destroyed the
  entire fix set. Captured in v2's restructure commit. ✅ VERIFIED-BY-V2

---

## Part 3 — Results worth preserving

These are real measurements. They are the empirical backbone of the write-up, and they came
from real samples on real hardware.

| Finding | Detail | Why it matters | v2 task |
|---|---|---|---|
| **Custom-crypto defeat** ✅ VERIFIED-BY-V2 | `com.eg.android.AlipayGphone` called `Cipher.doFinal` **1,925 times**, and `T1521` is its **only** technique (`mitre_observed == ('T1521',)`, and all 1,925 events carry that id). **Correction: the run lasted 103.2s, not 60s** — so the rate is **18.6 ops/s, not the "32 crypto ops/second" v1 claimed.** The count is right; the window was wrong. Use 1,925 events / 103.2s. | It defeats *all* network TLS inspection while the memory hook still yields plaintext. This is the anti-evasion claim, demonstrated | T4.2 |
| **Runtime unpacking + victim profiling** | `us.mobileandroidangryfix.mbankingfixflash` (VT 39) dropped a runtime-unpacked DEX (`cache/of87oaufaldjawdjkw.dex`, `T1407`) and read `getSimOperatorName` twice (`T1426`) | Regional victim profiling is the *empirical justification* for JIT environment synthesis — the frontier is a response to observed behaviour, not a guess | T5.1 |
| **Environment-aware stalling** | A sibling Alipay sample produced **zero** observations → `outcome=inconclusive` | Correctly treated as inconclusive, **never benign**. Stalling is indistinguishable from a clean app if you let it be | T4.6 |
| **Anatsa cluster signature** | 4/4 droppers → exactly `T1407 + T1426` | A reproducible behavioural fingerprint across a family | T6.1 |
| **YARA campaign rule quality** | Compiles under real `yara-python`; **4/5 sibling recall, 0/6 false positives** — including `com.bankofamerica.mobile` and `com.icicibank.pockets` | A bank-trojan rule must never match a bank's own app. Keys on package-name token sets, not one hash | T6.1 |
| **Zero-day escalator** | A novel dropper scoring Low/31 escalates to **High/65** with a review flag and a "unverified rather than safe" warning, while explicitly **not** claiming a known-family match | Zero-days cannot land quietly in LOW | T2.5 |
| **Signals-disagree case** | F-Droid: ML said malicious (`p_cal=0.836`); the GenAI layer identified the legitimate app store and explained the false positive → 56/100 Medium, **confidence 0.25 Low** | Disagreement lowers *confidence*, never the score. The design principle, executable | T2.7 |
| **Lab proven** ✅ VERIFIED-BY-V2 | Image `drishti-m3-tools-v1`; sealed runtime independently confirmed contained; **snapshot restore semantics proven**, not assumed. v2 confirmed from the artifacts: every `completed` run carries `containment_verified=true`, `sample_kind=vetted_malware`, `snapshot.before_restore=passed`, `snapshot.after_restore=passed`, `package_absent_after=true` — which is what rules out cross-sample contamination | T0.9's go/no-go is already answered once | T0.9 |

---

## Part 4 — Methodology decisions to carry forward

Inherit these; they were thought through and they are defensible.

- **Labelling policy.** malware := `vt_detection >= 10` (strong consensus); benign :=
  `vt_detection == 0` **and** distributed via `play.google.com`; **discard `1 <= vt < 10`** —
  the adware/grey zone. Excluding it avoids training on label noise. **This must be stated in
  the paper.** → T2.2
- **Time split, not random.** Train `dex_date < cutoff`, test `>=` (v1 used 2021-01-01).
  Report **both** random and time-split numbers; the gap *is* the concept drift that motivates
  the behavioural and GenAI layers. → T2.3
- **Circularity guard.** Labels come from VT counts, so a VT-derived feed in `R` leaks the
  label. `reputation.py` marks such a feed `label_derived=True` and **refuses it by default**.
  ML metrics are unaffected because `evaluate.py` never sees `R`. Precision/recall over `S`
  with a VT feed enabled is **meaningless**. → T2.7
- **Redaction happens in the guest, before serialization.** OTPs, message bodies, credentials,
  tokens, clipboard and device values are redacted inside `frida_hooks.js` *and* validated by
  the `ObservationEvent` model, which refuses to construct if unredacted text is present. →
  T4.2, T0.3
- **The detonation ladder.** inert fixture → known-benign → one vetted sample, each gated by a
  per-sample `PilotAuthorization` naming its exact SHA-256. **v2 keeps this**, and the first v2
  detonation is the canary. → T0.9, T4.1
- **Training and inference are different pipelines and confusing them is the most common
  mistake.** Training: offline, batch, 6,000 APKs → numeric features, on the extractor VM,
  **never executes** an APK. Inference: real time, one APK, **never executes** an APK.
  Detonation is a *third* thing, in the sealed lab only, never inside the API. The model does
  not learn per sample at request time. → `CLAUDE.md`, T0.5
