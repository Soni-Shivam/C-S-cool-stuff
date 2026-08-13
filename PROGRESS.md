# PROGRESS

A running log of what was built, what it changed, and what was found. Newest first.

`STATUS.md` is the *current state* (task checklist, decisions, open risks). This file is
the *narrative* — what happened, in order, and why. If you want to know "what did you do
and what did it change", read this.

Conventions:
- **Found** entries are bugs or wrong claims discovered while building. They are the most
  useful part of this file.
- **Not verified** is stated explicitly on every entry. Absence of a claim is deliberate.

---

## 2026-08-14 · Legacy detonation artifacts rescued + contract reconciled

**Branch:** `feat/rescue-artifacts` · **Phase:** P0 (side track: v1 salvage)

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

- **Legacy project `drishti-m3-08130038`:** all four boot disks snapshotted
  (`v1-rescue-*-20260813`) — they were on `auto_delete=true` with **zero buckets and zero
  snapshots**, one command from total loss. All four VMs now `TERMINATED` (~$1/hr stopped).
- **v2 project `drishti-v2-260814`:** billing linked, compute/IAP/storage/oslogin enabled,
  three buckets in `asia-south1` (private, versioned, public-access-prevention):
  `-corpus`, `-artifacts`, `-models`.
- **Archived:** `samples.csv` (6,000 real rows) → corpus bucket; 14 observation artifacts +
  3 attestations → artifacts bucket.
- **Not built yet:** VPCs, firewall rules, Packer image, detonator. That is the lab lift.
