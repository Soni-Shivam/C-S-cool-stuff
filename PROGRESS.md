# PROGRESS

A running log of what was built, what it changed, and what was found. Newest first.

`STATUS.md` is the *current state* (task checklist, decisions, open risks). This file is
the *narrative* — what happened, in order, and why. If you want to know "what did you do
and what did it change", read this.

Conventions:
- **Found** entries are bugs or wrong claims discovered while building. They are the most
  useful part of this file.
- **Not verified** is stated explicitly on every entry. Absence of a claim is deliberate.
- **PR numbers below refer to local branch history.** `gh pr list --state all` on
  `Soni-Shivam/CyberShield` returns nothing — no pull request was ever opened against the
  remote. Verified 2026-08-17.

## 2026-08-17 · Stratified corpus sample list (T2.2, part 1)

**Branch:** `feat/stratified-sample-list` · **Phase:** P2 prep · Contract addendum **A9**

ADAPTed from v1's `build_sample_list.py`, which already had the `dex_date` plausibility
window. Four things it did not have, all required by the v2 spec:

1. **Three-way split** — `train`/`calib`/`test`. `PHASE_2` T2.4 calibrates on a held-out
   third split; calibrating on test is a leak a good judge will catch.
2. **Four time bands**, so the 2024-2026 band is visible as its own quantity rather than
   averaged away. v1's corpus had 117 rows from 2024-25 total.
3. **Stratified download order** — round-robin across `(time_band, label)` cells from a
   seeded shuffle, so **any prefix of the list is itself balanced**. This is what makes a
   metered, multi-hour transfer interruptible.
4. **Measured size** — `apk_size` is summed from the index and printed in bytes *before*
   anything downloads. The corpus size is never estimated.

### Verified

The prefix-balance test has teeth. Negative control over 400 rows, comparing our ordering
against the alternatives:

| Ordering | Worst label gap | Worst band gap | First bad prefix |
|---|---|---|---|
| **stratified (ours)** | **1** | **2** | never |
| bucket order | **200** | bands absent | n=8 |
| band-sorted | 1 | bands absent | n=8 |

End-to-end on a 60,000-row synthetic index: 19,859 implausible dates dropped, 6,645
VT grey-zone rows dropped, exactly 100 malware + 100 benign in each of the four bands.
The HTTP-404-page guard fires on a short file, which is the v1 failure that wasted a
debugging session (`SALVAGE.md`: *"Saved HTTP 404 HTML pages, not the AndroZoo index"*).

### Found

**1. A new contract model can silently escape the round-trip gate.** `test_roundtrip`
discovers models via `DrishtiModel.__subclasses__()`, which only sees modules that have
been **imported**. `drishti/contracts/corpus.py` was not exported from
`contracts/__init__.py`, so `CorpusSample` was invisible to the gate and the full suite
passed with it unguarded. Confirmed directly: discovered `False` before importing the
module, `True` after. Fixed by exporting it, which immediately made the gate fail as it
should, then adding the factory. Same import-order trap as the e2e ledger bug earlier
today — a test that cannot see the thing it guards passes for the wrong reason.

**2. An empty `calib` split fails silently.** The synthetic index put every recent row in
`test`, leaving `calib` at zero. Nothing downstream would have complained; isotonic
calibration and the reliability curve would simply not have happened, and that curve is
one of the few things separating this project from prompting an LLM for a number. The CLI
now warns explicitly on any empty split.

### Not verified

- **The real AndroZoo index has never been fetched or parsed.** Every number above is from
  a synthetic 60,000-row index. Real composition, real drop rates and the real corpus size
  are unknown until the index is downloaded.
- Nothing was downloaded and no APK exists anywhere. No GCP resource was touched.
- The 12,000-row target and the four band edges are design choices, not yet validated
  against what AndroZoo actually supplies — in particular the 2024-2026 band may be thin.

---

## 2026-08-17 · The real AndroZoo index, and what it actually contains

**Phase:** P2 (T2.2) · Sample list archived to
`gs://cybershield-505518-corpus/sample-lists/samples-seed20260817.csv`

The index downloaded (3,512,086,448 bytes, `gzip -t` clean) and was streamed end to end.
**27,606,781 rows scanned.** These are the first real corpus numbers this project has ever
had; everything before was synthetic.

### The date filter was not a nicety

| Outcome | Rows | Share |
|---|---|---|
| Scanned | 27,606,781 | 100% |
| **Dropped — implausible `dex_date`** | **19,479,745** | **70.6%** |
| Dropped — VT grey zone (1–9 detections) | 1,798,395 | 6.5% |
| Dropped — unlabelled or oversized | 1,154,354 | 4.2% |
| Selected | 10,599 | 0.04% |

**70.6% of AndroZoo carries an implausible `dex_date`.** v1 measured this at 20.6% on a
6,000-row sample and treated it as a correctable annoyance. On the full index it is the
dominant property of the data. Without the plausibility window the time split would not
have been slightly contaminated — it would have been mostly noise.

### The 2024–2026 malware cell is nearly empty

| Band | Malware | Benign |
|---|---|---|
| ≤2017 | 1500 | 1500 |
| 2018–2020 | 1500 | 1500 |
| 2021–2023 | 1500 | 1500 |
| **2024–2026** | **99** | 1500 |

Target was 1500. AndroZoo yielded **99**. This is the exact weakness the corpus was
supposed to fix, and it is now quantified rather than suspected: the paper names 2024–25
families as primary targets, and the corpus cannot currently support a claim about them.
**MalwareBazaar backfill is now a requirement, not an option.**

Splits: train 9000 / calib 599 / test 1000. The calib split is thin for the same reason —
it is drawn from 2024.

### The stratified ordering earned its keep, and its limit is measured

Any prefix stays balanced **until a cell exhausts**, which happens at row ~801 (99 malware
× 8 cells). Measured on the real list:

| Prefix | Size | malware/benign | 2024–2026 rows |
|---|---|---|---|
| 1,000 | 19.5 GB | 485 / 515 | 228 |
| 2,000 | 37.1 GB | 914 / 1086 | 370 |
| 4,000 | 73.5 GB | 1771 / 2229 | 656 |
| 8,000 | 147.1 GB | 3485 / 4515 | 1228 |

The degradation past ~2,000 rows is **supply, not algorithm** — there is no more recent
malware to interleave. Stated plainly because the distinction decides whether the fix is
code or more data. It is more data.

### Found

**The corpus is 193.9 GB, not the ~120 GB estimated.** Real APKs average ~18 MB, not the
~10 MB assumed. At the transfer rate observed for the index (~415 KB/s from AndroZoo) a
full download would take **on the order of 130 hours**, which is not viable. The stratified
ordering is what makes this survivable: **the first 1,000 rows are 19.5 GB and are already
balanced across label and all four bands.** A partial download is a usable corpus, which
was the entire point of stratifying the download order rather than only the extraction
order.

### Not verified

- **No APK has been downloaded.** This is index metadata only; nothing was fetched, and no
  GCP compute was started.
- The 193.9 GB figure is summed from AndroZoo's own `apk_size` column, not measured by
  transferring anything.
- The ~415 KB/s rate is from the index download on this network; AndroZoo's APK endpoint may
  differ and parallel connections were not tested.
- Labels are AndroZoo's `vt_detection` counts. They are **not** validated against any second
  source, and they never reach the scorer (contract A9).

---

## 2026-08-17 · GCP bootstrap — buckets, APIs, budget guard

**Branch:** `feat/gcp-bootstrap` · **Phase:** P0 (lab rebuild)

`infra/gcp/bootstrap.sh` — idempotent, creates **no compute**. Empty buckets and a budget
cost effectively nothing, so this runs safely ahead of any spending decision. VMs stay a
separate, explicit step.

Three buckets in **`us-east1`** (deviation from `CLAUDE.md`'s `asia-south1`, recorded in
Decisions — co-located with the extractor VM, since moving ~120GB cross-region would cost
about $12 in egress and buy nothing). All three: versioned, `public-access-prevention:
enforced`, uniform bucket-level access, noncurrent versions deleted after 7 days.

That lifecycle rule is not housekeeping. Versioning is mandated by `CLAUDE.md`, and
without the rule one accidental re-upload of the corpus silently turns 120GB into 240GB.

### Found

**`gcloud billing` bills the API call to the *quota* project, not `--project`.** The quota
project defaults to `gcloud config get project`, which on this machine is an unrelated
project (`internship-505513`). The budget call therefore failed with *"Cloud Billing Budget
API has not been used in project internship-505513"* — which reads exactly like a
permissions problem and is not one; the API was enabled on the right project the whole
time. `--billing-project="$PROJECT"` is the fix, and the script comments say why so the
next person does not re-diagnose it.

This is the same failure shape `CLAUDE.md` warns about for IAM: *"a configured account
with no credentials on it produces an authorisation error that reads exactly like a
missing role."*

### Verified

Read back from the API, not from the script's own output:

| Bucket | Location | Versioning | PAP | Uniform | Lifecycle |
|---|---|---|---|---|---|
| `-corpus` | US-EAST1 | True | enforced | True | Delete @7d noncurrent |
| `-artifacts` | US-EAST1 | True | enforced | True | Delete @7d noncurrent |
| `-models` | US-EAST1 | True | enforced | True | Delete @7d noncurrent |

Budget `drishti-cybershield-505518` = ₹4,200 (≈$50 at ~₹84/USD), thresholds 0.6/0.9/1.0.
It sits inside a pre-existing account-wide ₹10,000 alert. Re-running the script is a
clean no-op that re-asserts the declarative settings — proven by running it twice.

### Not verified

- **No compute was created or started.** `0 instance(s)` after the run.
- **The ≈$50 conversion is an assumption**, not a lookup — the budget is denominated in
  INR because the billing account is, and the rate was not queried.
- No VPC, firewall, Packer image, detonator, or corpus exists yet.
- Nothing was uploaded to any bucket; all three are empty.

---

## 2026-08-17 · Ledger concurrency hardening + reality reconciliation

**Branch:** `fix/p0-ledger-hardening` · **Phase:** P0
**Plan:** `docs/superpowers/plans/2026-08-17-ledger-hardening-and-reconciliation.md`

Establishing a real test baseline surfaced three defects. `tests/e2e` had never been run
alongside the rest of the suite, so none of them had been seen.

### Found

**1. The ledger signing key was created non-atomically.** `load_or_create_key` did
check-then-act, so two `LedgerStore` instances built concurrently — and `job_workers`
defaults to 2 — both generated a key and the second overwrote the first. The losing thread
signed every one of its nodes with a key that was not on disk. **On a fresh install the
first two concurrent uploads produced a permanently unverifiable ledger, and the evidence
is not re-signable.** Measured: 8 threads released through a barrier produced **8 distinct
keys**, not 1.

**2. A worker thread could die before publishing `_DONE`.** `JobRunner._run` constructed
`LedgerStore` *above* its `try`, so a failure there skipped both the handler that marks the
job `FAILED` and the `finally` that publishes the sentinel. Observed as a job stuck in
`QUEUED` with `error=None` while the SSE consumer blocked for its full timeout. The
docstring promised the worker never raises; the line above the `try` broke that promise.

**3. Schema initialisation could not survive lock contention.** SQLite returns
`SQLITE_BUSY` **without invoking the busy handler** when two connections each hold a shared
lock and both try to upgrade — the one case it cannot wait out without risking deadlock —
and `CREATE TABLE IF NOT EXISTS` is precisely a read plus an upgrade. Measured **2 failures
in 480 concurrent constructions**. A longer connect timeout does not fix it: probing showed
the busy handler *does* run and simply times out (failed at exactly 5.01s against a held
`EXCLUSIVE` lock), so the fix is a bounded retry with jittered backoff.

**4. `STATUS.md` asserted infrastructure that no longer exists.** Both GCP projects are
gone, taking the four rescue snapshots, the 14 rescued observation artifacts, the 3
attestations, `samples.csv` and the v1 feature CSV. The trial billing account is closed.
The PRs `PROGRESS.md` cites were never opened on the remote.

### A wrong diagnosis, corrected

The first explanation for the failing e2e test was that T0.10's dedupe short-circuited the
pipeline and left a job with no ledger nodes. **That was wrong** — M1's `ingest()` writes
`FILE_META` and `THREAT_INTEL` regardless of `dedupe_hit`; dedupe is only a flag on
`FileMeta`. The real cause was found by reproducing in isolation, where the failure was
`first_bad_seq=0, "signature is not valid for this node_hash"` — a signing problem, not an
ingest one. One root cause produced two different symptoms, which is why it read as flake.

### Verified

- 8 threads racing to create a key now yield exactly 1, and it is the key on disk.
- **1,440 concurrent `LedgerStore` constructions, zero failures** (was 2 in 480).
- `test_two_concurrent_jobs_keep_separate_chains` passes **6/6 in isolation**, having
  failed **3/3** before this branch.
- 314 tests pass (300 contract+unit, 14 e2e). ruff clean, mypy clean over 41 files.

### Changed

- `drishti/ledger/crypto.py` — atomic key creation via temp-file + `fsync` + `os.link`;
  new `LedgerKeyError`; a corrupt key raises rather than being silently replaced
- `drishti/ledger/store.py` — `initialise_schema()` with bounded retry; `verify_chain`
  rejects an empty chain
- `drishti/api/jobs.py` — ledger constructed inside the `try`
- `tests/unit/test_ledger_key_concurrency.py`, `tests/unit/test_job_runner_failure_paths.py`
  — new; `tests/contract/test_ledger_chain.py` — empty-chain expectation reversed

### Reversed a documented decision

`test_empty_chain_verifies` asserted *"a job with no evidence is vacuously valid, not an
error"*. True of chain integrity in the abstract, wrong for this result specifically:
`verify_chain`'s output is rendered to a human as a trust signal by the UI badge, the CLI
exit code and the report, and demo beat #7 is showing it green. "No violations found
because nothing was checked" must not look identical to "verified". Same shape as v1's
`nc -z` bug.

### Not verified

- **No GCP resource was created, started, or touched.** Laptop only.
- Nothing was detonated and no sample was analysed.
- The key fix is tested against **threads, not processes**. `os.link` is atomic across
  processes too, but there is no test for that case.
- The sqlite retry is proven by injection and by a 1,440-construction stress run, not by a
  deterministic reproduction of the upgrade-deadlock race itself — that race is inherently
  timing-dependent.

## 2026-08-14 · T0.10 — real M1 ingest (first non-stub module)

**Branch:** `feat/p0-ingest` · **Phase:** P0 · Follows `docs/PHASE_0_FOUNDATIONS.md` T0.10

The first module that actually does something. Everything before this was scaffolding.

- **`guards.py`** — size cap (300MB), zip magic on the first four bytes, and zip-bomb
  detection read from the **central directory** so nothing is extracted to find out. Every
  guard runs *before* androguard sees the file: androguard is a large parser on
  attacker-controlled input, so cheap structural checks come first.
- **`ingest.py`** — sha256, split-APK reassembly, androguard manifest facts, dedupe, then
  the ledger. Split bundles are detected **by content, not extension** (the same bundle
  arrives as `.apks`, `.xapk` or `.zip` depending on the tool), and the base APK is the
  member whose manifest has no `split` attribute rather than the one named `base.apk`.
- **`intel.py`** — ADAPTed from v1 per `docs/SALVAGE.md`. Graded `R` bands, because v1's
  binary version left 24 of 25 reputation points dead and scored a VT-39 banking trojan
  64/Medium instead of 88/Critical.

Two rules the tests pin down: **a clean intel result never lowers a score** (`R` is a
floor-raiser; unknown maps to a positive floor because a zero-day is unknown to every
engine), and **a label-derived feed is refused by default** with the refusal recorded, since
AndroZoo's labels *are* VT counts and using them would make composite metrics circular.

### Found

**1. The test fixtures were never valid zips.** They were `b"PK\x03\x04" + b"stub"*64` —
enough to pass a magic check, not a real archive. Real M1 rejected all of them as corrupt,
which is correct behaviour, and 24 tests failed. Replaced with `tests/apk_fixtures.py`
producing genuine minimal zips. The placeholder manifest inside means androguard still
refuses it, so every pipeline run now exercises the degradation path for free.

**2. Zip-slip was possible in bundle extraction** and is now closed — member names are
flattened, so a member called `../../../../tmp/evil.apk` cannot escape the temp directory.
There is a test that would have written to `/tmp` if it could.

**3. An earlier deviation was wrong, and T0.10 resolved it.** I had recorded that a run
produces 11 ledger nodes rather than the 13 `PHASE_0` T0.5 predicted. With real M1 writing
`FILE_META` + `THREAT_INTEL` it is **12**, and **13** for a split bundle. The doc's estimate
was fair; my stub was just thin.

### Verified

Against a real uvicorn server: a valid APK-shaped zip → 12 ledger nodes, chain verifies,
`GET /ingest` returns real `FileMeta` with `partial=true` and `manifest parse failed` as the
stated reason. A `%PDF` upload named `.apk` → job `failed` with
`not a zip archive (magic b'%PDF')`, no 500.

304 tests (+27), ruff clean, mypy clean over 41 files.

### Not verified

- **No genuinely parseable APK has been ingested.** Every fixture has a placeholder
  manifest, so the androguard *success* path — package, label, versionCode, min/target sdk —
  is exercised only by the code, never by a test. That needs `canary/` (T0.9), and it is the
  most significant gap in this task.
- MalwareBazaar lookup is a `Protocol` with no implementation; only the local
  `known_bad_hashes.txt` feed is wired (6 entries, LIFTed from v1).
- Dedupe takes a `seen_hashes` set from the caller; nothing persists it yet.

---

## 2026-08-14 · Legacy detonation artifacts rescued + contract reconciled

**Branch:** `feat/rescue-artifacts` · **Phase:** P0 (side track: v1 salvage)

> **SUPERSEDED 2026-08-17.** The rescue described below was real and succeeded, but the
> project holding the output has since been deleted. `gs://drishti-v2-260814-artifacts/`
> no longer exists and the 14 artifacts are unrecoverable. **What survives is the 2
> artifacts committed to `data/fixtures/observations/`** and the contract fix — both of
> which are in this repo and unaffected. Read the rest of this entry as history.

### What happened

The 14 real `ObservationArtifact` files from v1's detonation runs were still stranded on
the legacy detonator's disk. They are now archived and two are CI fixtures.

1. Started `drishti-detonator` (legacy project), reached it over **IAP** (no external IP).
2. **Enumerated before copying.** That disk holds **33 real malware APKs**; only inert JSON
   was staged, and the staging step asserts `apk/dex count == 0` before anything leaves.
3. Copied 14 observation artifacts + 3 attestations (containment manifest, control-plane
   attestation, pilot authorisation) + the batch sample list — 18 files, 768KB, all
   JSON/txt.
4. Uploaded to `gs://drishti-v2-260814-artifacts/v1-provenance/`.
5. Cleaned the staging dir on the VM and **stopped it again**. All four legacy VMs are
   `TERMINATED`; disks and snapshots remain `READY`.

### Found

**1. v2's wire contract could not read v1's real output.** All 14 artifacts failed
`ObservationArtifact` validation. `extra="forbid"` rejected three fields the harness
actually emits that the port had dropped: `duration_s`, `diagnostics` (which carries the
containment-manifest reference), and `mitre_observed`. Nothing would have caught this until
the first P4 ingestion — after a detonation run, the most expensive place to find out.
Fixed; addendum A8. Encouragingly, **every nested model matched field-for-field** — the
drift was entirely top-level.

**2. A published number was wrong.** v1 claims the Alipay sample called `Cipher.doFinal`
"**1,925 times in 60 s**" at "32 crypto ops/second". The artifact says `duration_s =
103.238`. The count is right; the window is not. The real rate is **18.6 ops/s**.
`CARRIED_FINDINGS.md` now carries the correction — this was headed for the paper.

**3. My own `.gitignore` silently excluded the new fixtures.** A blanket `observations/`
rule (added to keep detonation output out of the repo) also matched
`data/fixtures/observations/`, so CI would have run the new test against an empty fixture
list and passed vacuously. Root-anchored to `/observations/`. Detonation output lands on
the sealed VM, never here, so the blanket rule bought nothing.

### Confirmed against the real data

| v1 claim | Verdict |
|---|---|
| "9 executed, 7 with data" (never quote 12) | ✅ 7 `completed` + 2 `inconclusive` = 9 executed; exactly 7 carry observations |
| Failure breakdown | ✅ 4 × `install_failed`, 1 × `internal_error` — matches "4 never installed + 1 receiver-only" |
| Alipay `T1521` is its **only** technique | ✅ `mitre_observed == ('T1521',)`, all 1,925 events carry it |
| Snapshot restore semantics proven | ✅ every `completed` run: `containment_verified=true`, `before_restore=passed`, `after_restore=passed`, `package_absent_after=true` |
| Artifacts are real, not simulated | ✅ `simulated=False` on all 14; `sample_kind=vetted_malware` |
| In-guest redaction worked | ✅ all events validate against the redaction check that refuses to construct on unredacted text |

### Changed

- `drishti/contracts/dynamic_trace.py` — `+duration_s`, `+diagnostics`, `+mitre_observed`
- `data/fixtures/observations/` — 2 real artifacts (1 `completed` w/ data, 1 `failed`)
- `tests/contract/test_real_observation_artifacts.py` — 12 tests over real data
- `.gitignore` — `observations/` → `/observations/`
- `docs/CARRIED_FINDINGS.md`, `docs/01_DATA_CONTRACTS.md` (A8)

### Not verified

- Nothing was detonated. This was a file copy off a stopped VM.
- The 699KB Alipay artifact is **not** committed (GCS only) — a repo fixture that big earns
  nothing a 1KB one does not.
- The extractor's v1 feature CSV is **still on `m3-extractor`'s disk**, not yet rescued. It
  is provenance-only now (the corpus is being re-extracted under the v2 schema), so it was
  not prioritised.
- 277 tests pass; ruff and mypy clean over 38 files.

---

## 2026-08-14 · T0.7 — TraceSource + the pre/post-morph replay fixture

**PR:** #11 (merged) · **Phase:** P0

The Replay-Mode parachute. If live detonation is not working by the **H40 tripwire**, the
pipeline consumes traces from a fixture instead — and that switch only costs 20 minutes
because this exists now.

- `TraceSource` ABC, `LiveSandboxSource` (unavailable until P4, and it **raises** rather
  than degrading), `ReplayTraceSource`, `resolve_trace_source()` with `auto` → replay fallback.
- The committed fixture carries both halves. Pass 1: probes `com.sbi.yono` → MISS → stalls
  3200ms, `detonated=False`. Pass 2: dropped DEX not in the APK, encrypted exfil POST,
  `detonated=True`.
- The frontier stub derives its morph plan **from pass 1's actual observations** rather
  than inventing a package list.

**Three honesty properties enforced in the loader, not remembered:** a fixture saying
`"source": "live"` still returns `REPLAY`; a hand-authored fixture is forced to
`synthetic=True`/`partial=True` with a disclosure in `errors`; a fixture claiming
`"synthetic": false` is overridden. Added `DynamicTrace.synthetic` (A7) because
`source == REPLAY` could not distinguish replaying a real capture from replaying typed-up
values.

**Not verified:** nothing detonated; the fixture is hand-authored and says so in three
places; its values are *modelled on* real Anatsa-cluster behaviour but were not measured.

---

## 2026-08-14 · T0.6 — the frozen API surface

**PR:** #10 (merged) · **Phase:** P0

19 routes, split into routers. A contract test asserts both that every frozen route exists
**and that no undeclared `/api` route has appeared** — otherwise "frozen" means whatever the
last commit left behind.

Two distinct unavailability statuses: **404 + `{"stage"}`** for not-yet-produced ("pending",
keep polling) and **501 + `{"task"}`** for frozen-but-unbuilt ("never coming in this build").
Collapsing them would make a missing feature look like a slow one.

The human gate ships unstubbed: confirming an action writes an `ANALYST_ACTION` node naming
who confirmed, with `executed: false`, and executes nothing.

**Found:** the REPORT stage was appending an `ANALYST_ACTION` node — a type that means *a
human confirmed something*. It made an automated rendering step indistinguishable from a
human decision in the ledger, and the confirmation gate's audit trail has to be
unambiguous. Added `EvidenceType.REPORT_GENERATED` (A6).

---

## 2026-08-14 · T0.2 + T0.5 — config, job runner, 11-stage pipeline

**PR:** #9 (merged) · **Phase:** P0

The skeleton became load-bearing. Verified against a **real uvicorn server**: multipart
upload → 23 SSE events → job `DONE` with both verdicts → `{"ok":true,"node_count":11}`.

The conditional FRONTIER branch actually executes (stub pass 1 reports an evasion
observation, which is §7.1's condition) — a skeleton that never takes its conditional path
has not been tested. A stage crash produces exactly one `ERROR` node and the chain still
verifies.

**Deviations:** 11 ledger nodes per run, not the 13 T0.5's prose states (§7.1 defines 11
stages; the ">=5" exit criterion holds). 4 routes, leaving the rest to T0.6.

---

## 2026-08-13 · T0.4 — the evidence ledger

**PR:** #8 (merged) · **Phase:** P0

Three layers, each tested where the previous one fails: SQL append-only triggers → sha256
hash chain → Ed25519 signatures. The tamper tests **drop the triggers first**, because the
honest claim is not "the database cannot be edited" but "editing it is detectable".
Detection asserted on every hashed field at its exact seq.

CLI verified by hand: healthy chain → `CHAIN OK` rc=0; rewrite node 1 → `CHAIN BROKEN,
first bad seq 1` rc=1.

**Found:** the spec's own id convention is unsafe. `uuid7_hex[:12]` is *exactly* the 48-bit
millisecond timestamp, so 50 appends in a loop produced 50 identical ids. Widening the
random part does not fix it either (a 400-node job would carry ~1-in-200 collision odds).
`new_id()` recomposed as 8 hex of time + 4 hex of a per-process counter. Addendum A5.

---

## 2026-08-13 · T0.3 — all 37 contract models

**PR:** #7 (merged) · **Phase:** P0

Contract version 1.0.0 → 1.1.0. **The spec referenced eight models it never defined**
(`FileMeta`, `ThreatIntel`, `PermissionCombo`, `DecryptedBlob`, `DexLoadEvent`, `FileWrite`,
`VisionMatch`, `StageEvent`); per its own §0 rule they went into an addendum before the code.

Adopted v1's stricter detonator wire contract, which the spec did not cover at all:
`strict=True`, a validator that **refuses to construct** on unredacted text, and
`simulated: Literal[False]` making synthetic unrepresentable on that path.

The round-trip test requires a factory for **every** model and fails on orphans, so coverage
cannot decay as contracts grow.

**Found:** `strict=True` also refuses `list → tuple`, so `ObservationArtifact` could not
parse its own JSON. Collection fields now carry `Field(strict=False)`.

---

## 2026-08-13 · T0.1 — skeleton, pinned deps, CI, samples-never-in-git gate

**PR:** #5 (merged) · **Phase:** P0

Module boundaries per §7–8, `uv` + Python 3.11, CI running ruff + contract + unit tests on
every push, plus a second job that fails the build if any apk/dex/joblib/pem/`.env` is
tracked. `frida` pinned `<17` (the GCE image ships Python 3.10). Lab extras split out of the
core install so `make install` cannot equip a laptop to detonate.

**Found, by writing the test rather than trusting the config:**
1. `build/` and `dist/` also matched `canary/app/build/` and `canary/dist/`, so the `*.apk`
   allowlist §4 requires **could never fire** — git cannot re-include a file whose parent
   directory is excluded.
2. `models/` made its own `!models/.gitkeep` dead, so the directory would vanish from clones.
3. **The test itself was wrong in the dangerous direction:** `git check-ignore -q` exits 0
   for *any* matching pattern including a negation, so an allowlisted file read exactly like
   a blocked one.

---

## 2026-08-13 · Repo restructure + v1 salvage inventory

**PRs:** #1–#4 (merged) · **Phase:** pre-P0

v1 frozen at `v1-reference/` (read-only, nothing imports it), v2 roadmap → `docs/`,
`CLAUDE.md` to root, `STATUS.md` seeded with all 61 task IDs, `.gitignore` hardened.

`docs/SALVAGE.md` gives every v1 path one verdict (LIFT / ADAPT / REFERENCE / DROP) with a
target v2 path and task id. `docs/CARRIED_FINDINGS.md` records v1's 11 defects, 8 holes, and
the measurements worth keeping.

**Found:** five of v1's most valuable files were **never committed** — they existed only in
the working tree. `builder_setup.sh` 76→195 lines, `verify_containment.py` 91→191,
`androzoo_extract.py` 101→220, `ingest.py` 65→107, `test_ingestion.py` 35→80. That is the
entire hard-won fix set (the frida pin, the `libxkbfile` fix, the corrected `nc` probe). One
`git clean` and it was gone.

**Also:** kept v1's `.env` (live keys, still unrotated) and an unrelated 3.3MB personal PDF
out of the commit.

---

## 2026-08-13/14 · GCP

> **SUPERSEDED 2026-08-17.** Every resource named below has been deleted — both projects,
> all four snapshots, all three buckets and their contents. None of it is recoverable.
> See the 2026-08-17 entry and `STATUS.md`. History, not current state.

- **Legacy project `drishti-m3-08130038`:** all four boot disks snapshotted
  (`v1-rescue-*-20260813`) — they were on `auto_delete=true` with **zero buckets and zero
  snapshots**, one command from total loss. All four VMs now `TERMINATED` (~$1/hr stopped).
- **v2 project `drishti-v2-260814`:** billing linked, compute/IAP/storage/oslogin enabled,
  three buckets in `asia-south1` (private, versioned, public-access-prevention):
  `-corpus`, `-artifacts`, `-models`.
- **Archived:** `samples.csv` (6,000 real rows) → corpus bucket; 14 observation artifacts +
  3 attestations → artifacts bucket.
- **Not built yet:** VPCs, firewall rules, Packer image, detonator. That is the lab lift.
