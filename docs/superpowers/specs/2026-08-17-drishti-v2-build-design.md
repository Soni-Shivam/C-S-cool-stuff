# DRISHTI v2 — Build Design (2026-08-17)

**Status:** approved · **Supersedes:** nothing · **Amends:** `STATUS.md`, not `docs/00_GUIDING_MAP.md`

This document is the *delta* between what `docs/` already specifies and what reality
requires. `00_GUIDING_MAP.md` remains the architecture. `01_DATA_CONTRACTS.md` remains
the interface spec. `PHASE_0`…`PHASE_6` remain the execution detail. Where this file and
a phase file disagree, **this file wins and the deviation is recorded in `STATUS.md`**.

---

## 1. Verified state, 2026-08-17

Established by inspection, not assumed. Every row was checked with a command.

| Item | State | How verified |
|---|---|---|
| Code on `main` | 33 commits, P0 T0.1–T0.7 + T0.10 landed | `git log` |
| Test baseline | **290 contract+unit pass**, 304 total, **1 e2e failure** | `uv run pytest` |
| Lint / types | `ruff` clean, `mypy` clean over 41 source files | `make lint`, `make types` |
| GCP project `drishti-v2-260814` | **DOES NOT EXIST** | `gcloud projects list` |
| GCP project `drishti-m3-08130038` (v1) | **DOES NOT EXIST** | `gcloud projects describe` |
| v1 rescued artifacts, corpus, snapshots | **UNRECOVERABLE** — lived only in the above | — |
| Trial billing account | `open: false` (closed) | `gcloud billing accounts describe` |
| Usable billing account | `017B2F-A06E63-B76B98`, INR, `open: true` | same |
| Project `cybershield-505518` | exists, billing linked, compute/storage/oslogin on, **IAP off** | `gcloud services list` |
| VMs / buckets in it | **0 / 0** | `gcloud compute instances list` |
| Quota | `CPUS_ALL_REGIONS: 32`, `asia-south1 CPUS: 100`, `DISKS_TOTAL_GB: 4096` — no increase needed | `gcloud compute project-info describe` |
| Existing VM | `instance-20260817-080247`, `internship-505513`, `us-east1-c`, `n2-standard-2`, 500 GB `pd-standard`, public IP, **nested virt OFF**, SA scope `devstorage.read_only` | `gcloud compute instances describe` |
| PR trail | **zero PRs on the remote**; `PROGRESS.md` cites #1–#11 | `gh pr list --state all` |
| Local toolchain | `uv` absent (installed), JDK **11** (need 17), 45 GB free | `which`, `df -h` |
| `.env` | absent (created); AndroZoo key set, **Gemini key still empty** | — |

### 1.1 What this means

The **code** is real and healthy. The **infrastructure and its provenance are gone**, and
`STATUS.md` currently asserts otherwise. The hard-won lab knowledge survives as *code* in
`infra/gcp/` and as *findings* in `docs/CARRIED_FINDINGS.md` — the frida `<17` pin, the
`libxkbfile` blocker, the corrected `nc` containment probe, the Packer template. Rebuilding
is re-running scripts, not re-learning.

---

## 2. Locked decisions

| Question | Decision |
|---|---|
| Deadline | Days out. Full phase order, no triage. |
| Lab scope | **Full** — detonator + real corpus + real training. |
| Budget ceiling | **$50.** Ask before *every* billable resource. |
| Team | Solo. Branch per task, PR per task. |
| PR flow | Open PR → CI green → I merge → user reviews after. Never force-push over history. |
| Sequencing | **Approach A** — long poles first, overlapped tracks. |
| Extractor host | Reuse `instance-20260817-080247`, resized `n2-standard-8`, GCS write scope. |
| Region | **`us-east1`** — deviation from `CLAUDE.md`'s `asia-south1`, co-located with the VM. |
| Detonator | Built separately in `cybershield-505518`. **Its own checkpoint.** Not the existing VM. |
| Laptop installs | Permitted (JDK 17, Android SDK cmdline-tools). |
| Interrupts | Report at phase boundaries; stop only for billable resources and hard boundaries. |

---

## 3. Reality reconciliation (PR 1)

### 3.1 `STATUS.md` / `PROGRESS.md` corrections

`00_GUIDING_MAP.md §13` makes `STATUS.md` the technical appendix of the pitch. A judge
reading it against a live `gcloud` shell must not find a contradiction. Corrections:

- GCP section → both projects gone, trial billing closed, artifacts unrecoverable.
- New verified-facts table for `cybershield-505518` and the existing VM.
- Test baseline → `290 contract+unit / 304 total, 1 e2e failing` (was: unqualified `304/304`).
- PR references → marked as *local branch history; no PRs exist on the remote*.
- v1 salvage items that depended on the dead project → `LOST`, not `TODO`.

### 3.2 Bug — `verify_chain()` passes vacuously on an empty chain

`ChainVerification(ok=True, node_count=0)` is returned for a job with no nodes. Demo beat
#7 (`00_GUIDING_MAP.md §2`) is *"show `verify_chain()` returning green"*. Green on a job
that did nothing is the same defect class as v1's `nc -z` bug, where `blocked()` returned
`True` unconditionally and a signed manifest attested containment that was never tested.

**Fix:** `ok=False`, `reason="empty chain: no nodes for job <id>"`. Callers audited.
**Test first:** `test_empty_chain_does_not_verify`.

### 3.3 Bug — dedupe writes zero ledger nodes

T0.10's dedupe short-circuits the pipeline, so a deduplicated job leaves **no evidence
trail at all** — contradicting the §7 invariant that every job traces to artefacts.

**Fix:** a deduped job still appends `FILE_META` plus a dedupe marker citing the prior
job's node. `tests/e2e/test_pipeline_walk.py::test_two_concurrent_jobs_keep_separate_chains`
switches to two **distinct** APKs — it was accidentally testing dedupe, not chain isolation.

---

## 4. GCP topology (as-built target)

Deviates from `CLAUDE.md §GCP layout` only in region and extractor placement. Recorded.

```
data project   cybershield-505518          # dedicated; buckets + detonator
compute (temp) internship-505513           # existing extractor VM only, static parsing
region         us-east1 (zone us-east1-c)  # co-located with the VM; free VM↔bucket transfer

buckets        gs://cybershield-505518-corpus/     private, versioned, PAP
               gs://cybershield-505518-artifacts/  + lifecycle: delete noncurrent @7d
               gs://cybershield-505518-models/

extractor      instance-20260817-080247   n2-standard-8 (resized), 500 GB pd-standard
                                          public IP retained — needs AndroZoo egress
                                          SA granted objectAdmin on the three buckets
                                          NEVER executes a sample: androguard parses only

detonator      TO BE BUILT in cybershield-505518, sealed VPC, nested virt,
               NO external IP, IAP only.   ← separate checkpoint, separate PR
```

### 4.1 Cost controls (all added at bootstrap)

- **Budget alerts at $30 and $45.** With the trial closed there is no safety net.
- **Bucket lifecycle rule: delete noncurrent versions after 7 days.** Versioning is
  mandated by `CLAUDE.md`; without this rule one accidental re-upload silently turns
  120 GB into 240 GB.
- **Extractor is stopped between batches.** Disks bill while a VM is stopped —
  `make lab-down` stops compute, not storage. 500 GB `pd-standard` ≈ $0.67/day regardless.

### 4.2 Projected spend

| Line | Estimate |
|---|---|
| Extractor compute (`n2-standard-8`, ~30h metered) | ~$12 |
| Detonator compute (`n2-standard-4`, nested virt, metered) | ~$3 |
| Builder VM (Packer, ~1h, deleted after) | ~$0.20 |
| Storage — all buckets + all disks + custom image, 10 days | ~$6 |
| **Total** | **~$21**, ceiling $50 |

Ingress is free, so pulling ~120 GB from AndroZoo costs nothing. Egress *out* of GCP
would run ~$0.12/GB ≈ $14 — one more reason the corpus never leaves the project and never
touches the laptop.

---

## 5. Stratified corpus lister — the one novel design piece

`CLAUDE.md` requires `build_sample_list.py` to enforce `--min-date`/`--max-date` and report
dropped rows, and to interleave deterministically by `(split, label)` **before extraction**.
This design pushes that stratification up into the **download order** as well.

### 5.0 Target

| Parameter | Value | Rationale |
|---|---|---|
| Row count | **12,000**, 50/50 malware/benign | Fits the $50 ceiling at ~120 GB; large enough for a defensible time split |
| `--min-date` | `2012-01-01` | Below this, `dex_date` is almost entirely ZIP-epoch fallback |
| `--max-date` | `2026-08-17` (run date) | Anything later is impossible and signals a corrupt timestamp |
| Time bands | 4 (`≤2017`, `2018–2020`, `2021–2023`, `2024–2026`) | The 2024–26 band is what makes the time split honest; v1 had only 117 such rows |
| Split | train / **calib** / test by time | Calibration on a held-out *third* split, never on test |
| Seed | fixed, recorded in `STATUS.md` | Re-runnable and auditable |

If the 2024–26 band cannot be filled to at least 1,500 rows from AndroZoo alone, backfill
from MalwareBazaar's recent Android tags rather than rebalancing the other bands — a thin
recent band is the specific weakness this corpus exists to fix.

### 5.1 Algorithm

1. Stream AndroZoo's index CSV; filter by the `dex_date` plausibility window. This kills
   the ZIP-epoch fallback (1980/81) and impossible futures (2039+) that contaminated v1's
   split — 1,235 rows, 20.6%, all landing on one side.
2. Assign each surviving row a cell `(time_band, label)`.
3. Round-robin across cells with a **fixed seed**, emitting the interleaved list.
4. **Sum the `apk_size` column of the selected rows and print exact total bytes before a
   single byte transfers.** The corpus size is measured, never estimated.

### 5.2 The property this buys

**The download is interruptible at any row count.** Every consecutive 1,000 rows is
independently balanced across label and time band, so stopping at 4k or 9k still yields a
balanced corpus spanning the full time range and a valid time split. Bucket order yields
6,000 malware samples and no test set.

Given an unknown transfer rate and a metered bill, this converts a hard dependency into a
soft one.

**Enforced, not hoped:** `tests/unit/test_sample_list_stratification.py::test_any_prefix_is_balanced`
asserts label balance and time-band coverage across many prefix lengths.

### 5.3 Streaming, not hoarding

Download a batch → run M2 → extract features → push the APK to GCS → delete locally. The
extractor never needs more than a ~200 GB working set. Corpus APKs are **retained in GCS**
per the existing decision (v1 deleted every APK post-extraction, which is precisely why a
schema change cost a full re-download).

### 5.4 Reputation stays non-circular

`reputation.py` refuses a label-derived feed by default. AndroZoo's labels *are*
`vt_detection` counts; feeding them into `R` would make composite-score metrics circular.
This is not relaxed to make a number look better.

---

## 6. Execution order

Numbering is PR order, not phase order. Phases still follow `docs/PHASE_*`.

| # | PR | Where | Notes |
|---|---|---|---|
| 1 | Reality reconciliation + 2 ledger bugs | laptop | tests first |
| 2 | GCP bootstrap: IAP, buckets, lifecycle, budget alerts, IAM | GCP | **billable checkpoint** |
| 3 | Stratified sample list + download kickoff | GCP | starts the 12–24h clock |
| 4 | Packer image build (parallel with 3) | GCP | **billable checkpoint** |
| 5 | T0.8 UI shell · T0.9 canary APK | laptop | needs JDK 17 |
| 6–12 | **P1 static engine** T1.1–T1.7 | laptop | runs during the download |
| 13 | Corpus extraction batch | GCP | needs 3 + P1 |
| 14–22 | **P2** features → train → calibrate → scorer | mixed | needs 13 |
| 23+ | P3 GenAI · P4 sandbox · P5 frontier · P6 report/UI | | detonator is its own checkpoint |

**Why overlapped:** the corpus download (12–24h, unattended) and the P1 static engine
(~12h, laptop) have no dependency on each other. Serial ordering burns 12+ hours with the
network idle, and defers discovery of any AndroZoo problem to the worst possible moment.

---

## 7. Verification stance

Per `CLAUDE.md §Session protocol` and `§Testing`:

- Tests **first** for: contracts, ledger, scorer, feature extractor, morph validation,
  evasion detection, containment probes. Not required for UI and prompt work.
- Every PR: `make test` green, `ruff` clean, `mypy` clean, CI green before merge.
- **Real numbers only.** Test counts, PR-AUC, timings come from a run recorded in
  `STATUS.md` — never from the ideation PDF, never from an estimate.
- **`PROGRESS.md` keeps its `Not verified` section on every entry.** Absence of a claim is
  deliberate. A skipped test is reported, never quietly skipped.
- Containment verification is a test whose output the attestation manifest signs. A
  containment failure aborts a batch and never downgrades to a warning.

---

## 8. Honesty requirements — how each stays true automatically

These are `CLAUDE.md §Honesty requirements` mapped to a mechanism, so they track reality
rather than someone remembering:

| Claim | Mechanism |
|---|---|
| Replay vs. live | Derived from trace metadata (image version, VM instance id, timestamp), never from config. `ReplayTraceSource` overrides a fixture that lies about `source` or `synthetic`. |
| No observations ≠ benign | `DynamicTrace.outcome` carries `inconclusive`; `detonated: bool` cannot express it. |
| Containment | Report reads the verified probe output embedded in the run manifest; if the probe did not run, the manifest and the report both say so. |
| Limitations section | Generated from real flags (`partial`, `source == replay`, `synthetic`, rejected-claim count). Never hardcoded. |
| Ungrounded AI claims | `ledger.append()` rejects an `AI_CLAIM` with empty or unresolvable `evidence_refs`. |
| Metrics in UI/report | Sourced from a measurement written to `STATUS.md`. |

---

## 9. Risks

| # | Risk | Mitigation | Trigger |
|---|---|---|---|
| N1 | AndroZoo transfer rate unknown; 120 GB could exceed the window | Stratified order makes any prefix usable (§5.2) | download start + 6h |
| N2 | Detonator needs a VPC and image built from scratch; v1's lab knowledge is code, not a running system | `infra/gcp/` is idempotent and re-runnable; `CARRIED_FINDINGS.md` carries the 9 verified lab facts | image build |
| N3 | Extractor lives in a shared project (`internship-505513`) alongside an unrelated VM | Static parsing only — androguard never executes. Detonation happens elsewhere, sealed. Recorded as a deviation. | — |
| N4 | AndroZoo key was exposed in a chat transcript | Rotate after the hackathon. Stored only in gitignored `.env`. | post-demo |
| N5 | Gemini key not yet provided | Nothing blocks until P3; `mock` provider covers tests | P3 start |
| N6 | v1's open risk H1 — no benign controls ever detonated, so dynamic FP rate is unmeasured | P4 must detonate benign controls before any claim that techniques *distinguish* malware | P4 |

---

## 10. Out of scope

Unchanged from `00_GUIDING_MAP.md §3` and `§10`. This design adds no scope. In particular
it does not revisit: GNN/transformer models (cut), bare-metal device farm (cut),
multi-channel ingest (cut), TAXII server (cut), MobSF as static core (optional enrichment).

The hard boundaries in `CLAUDE.md` are not modified by this document. No malware is
authored. `canary/` stays within its four behaviours. No sample is ever executed on a
developer machine.
