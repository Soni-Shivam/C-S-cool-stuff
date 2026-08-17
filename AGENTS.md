# AGENTS.md — Operating instructions for the coding agent

Copy this file to the repo root as `AGENTS.md`. Codex reads it automatically
at the start of every session.

---

## What this project is

DRISHTI is a **defensive** Android malware triage system built for a 72-hour
hackathon. It analyses suspicious APKs inside an isolated sandbox and produces a
calibrated threat score, a grounded investigation report, and a cryptographically
chained evidence ledger.

**The samples are real, the training corpus is real, and both live in GCP.** There
is no synthetic-malware mode and no "we'll wire the real thing up later" mode. The
ML classifier is trained on a real, time-split Android corpus, and dynamic analysis
detonates real APKs on a real Android emulator running on a GCE VM with nested
virtualisation. Anything that cannot be traced to a real sample or a real run is
labelled as such in the UI and the report (see *Honesty requirements*).

Full context is in `docs/`. Read `docs/00_GUIDING_MAP.md` and
`docs/01_DATA_CONTRACTS.md` at the start of every session, and the phase file for
whatever you're working on.

Where a phase file assumes a local analysis laptop (`PHASE_0 §T0.9`,
`PHASE_4 §Safety controls`), **this file wins**: the analysis host is a GCE VM. The
safety *properties* those sections require are unchanged — they are just enforced by
VPC firewall rules and an immutable image instead of by someone's spare ThinkPad.

## Hard boundaries — refuse if a task appears to ask for these

This project analyses malware. It does not create it. Do not write, and refuse
tasks that request:

- Malicious payloads, overlay-capture code, SMS-forwarding code, credential
  harvesters, packers, or obfuscators
- Anti-analysis or evasion techniques intended to be embedded in an application
- Any second-stage content served to a sample that is not provably inert
- Distribution, publication, or upload of real malware samples anywhere **outside
  the analysis project's own private GCS bucket** — never to a public bucket, never
  to a registry, never to an artifact store, never into a git object
- Any change that gives a sample a route to the internet, to the GCE metadata
  server, to the VPC, or to the host — including "just for one test"

The `canary/` app is the sole exception and its behaviour is strictly limited to:
querying `PackageManager`, reading an SMS count, one HTTP GET to a configured
local host, and `Log.i` output. If a task asks to extend `canary/` beyond that,
stop and ask.

Frida morph scripts under `m3_dynamic/scripts/morph/` deliberately return synthetic
values to the sample under analysis. That is in scope — it changes what the sample
*observes about the environment*, inside an isolated VM. It must never add
capability to the sample.

---

## Execution environment — where each thing runs

| Work | Runs on | Never runs on |
|---|---|---|
| Contracts, ledger, scorer, feature extractor, prompts, UI, all tests | laptop | — |
| M2 static analysis of real samples | GCE extractor VM (batch), laptop only for the canary | — |
| ML training / calibration / evaluation | GCE trainer VM (or the extractor VM), reading the corpus from GCS | laptop |
| **Detonation of any real APK (M3, Phase 5)** | **GCE detonator VM, sealed VPC, Android emulator under KVM** | **laptop, CI, any shared machine** |

**The rule, stated once:** a file under `data/samples/` or in the corpus bucket is
never opened by an installer, an emulator, or a `subprocess` on a developer machine.
Static parsing with androguard on the laptop is fine (it does not execute code);
`adb install` on the laptop is not. If a task would break that rule, stop and say so.

### GCP layout — the shape to build and keep

```
project        drishti-<lab-id>              # dedicated project, not a shared one
region/zone    asia-south1 / asia-south1-a   # keep everything co-located
buckets        gs://<proj>-corpus/           # real APKs, private, versioned, CMEK optional
               gs://<proj>-artifacts/        # traces, screenshots, dropped dex, ledgers
               gs://<proj>-models/           # vocab_v1.json, model, calibrator
images         drishti-emulator-v<N>         # immutable Packer image: SDK + AVD + frida
networks       drishti-build    (has Cloud NAT — for building images only)
               drishti-runtime  (NO Cloud NAT, egress denied by default)
VMs            m3-builder     n2-standard-4  on drishti-build
               m3-extractor   n2-standard-8  egress 443 only (static + training)
               m3-detonator   n2-standard-4  --enable-nested-virtualization, sealed
access         IAP TCP tunnel only. No external IPs. No SSH keys in the image.
```

Infrastructure lives in `infra/gcp/` — Packer template + `builder_setup.sh` for the
image, and idempotent `gcloud` scripts (not hand-typed commands) for VPC, firewall,
and VM lifecycle. Every script must be safe to re-run.

**Containment is a firewall property, not a policy document.** On
`drishti-runtime`: default-deny egress; explicit deny to `169.254.169.254/32`
(metadata), to RFC1918, and to the internet; allow only the analysis host's
mitmproxy port. The emulator's only route out is the proxy on `10.0.2.2`.

### Cost and lifecycle guardrails

- The detonator VM is **stopped when not detonating**. Add `make lab-up` /
  `make lab-down` and use them. A forgotten nested-virt VM is the single easiest way
  to burn the budget.
- Never move the emulator to a preemptible/Spot VM — a mid-detonation preemption
  loses the trace and leaves the AVD dirty.
- Bake tools into the image. If a step needs `apt`/`pip` at detonation time, it
  belongs in the Packer build, because the runtime network cannot reach a mirror.
- Wrap scripted `gcloud` in a retry loop. Calls to `*.googleapis.com` fail
  intermittently from some networks (`SSL: WRONG_VERSION_NUMBER`); one failed call
  must not abort a batch.

### Verified lab facts — read before debugging the emulator

These cost real hours to find. Treat them as given, and if you contradict one,
prove it with a command output before changing code.

1. **Nested virt works on `n2-standard-4`** with `--enable-nested-virtualization`;
   `/dev/kvm` is present. `emulator -accel-check` *fails for non-root* (it checks
   `kvm` group membership) while root is fine. Add operators to `kvm` anyway.
2. **`frida` must be pinned `<17`** on Ubuntu 22.04 (frida ≥17 imports
   `typing.NotRequired`, which needs Python 3.11; the distro ships 3.10, so
   `import frida` raises `ImportError` and the whole collector dies, not just a
   version probe). Verified pair: frida **16.7.19** client + frida-server
   **16.7.19 android-x86_64**, versions matched exactly.
3. **Derive the frida-server download version from the importable module**, not from
   `frida --version` on the CLI, and `curl --location` (GitHub release assets
   redirect). Getting this wrong ships an image with no frida-server and a 404 nobody
   notices until detonation.
4. **The emulator needs system libs the obvious apt list omits** — the blocker is
   `libxkbfile.so.1`; without it `qemu-system-x86_64` will not start even with
   `-no-window`, because `swiftshader_indirect` still pulls libGL/libEGL/libgbm.
5. **Verify the emulator with `emulator -version`, never `ldd`.** Its Qt and
   `android-emu` libraries resolve via RPATH out of `$SDK/emulator/lib64`, so `ldd`
   reports false "not found".
6. **Avoid `-writable-system` on the critical path.** With it, `adb remount` claims
   success while `/system` stays read-only, and `adb reboot` can wedge the guest in
   `offline` forever (requiring an AVD purge). Without it, boots are clean and fast.
   Snapshots *do* coexist with `-writable-system` — but if you ever install the
   mitmproxy system CA, cut the clean snapshot **after** the install, or restore
   reverts the trust store.
7. **HTTPS interception is therefore a deferred, optional step.** The
   `Cipher.doFinal` hook already yields plaintext before encryption, which is the
   stronger result anyway (it also defeats T1521 custom crypto). Do not block M3 on
   the system CA.
8. **Batch loops must read the sample list on FD 3** (`while read -u 3 …; done 3< list`).
   `dynamic_analyze.py` consumes stdin, so a naive loop silently stops after one
   sample and looks like a data problem.
9. **The runtime VPC has no NAT by design.** If a runtime tool needs `apt`, use
   HTTPS mirrors — port 80 is blocked — or better, bake it into the image (see above).

### Containment verification is a test, not a claim

`verify_containment.py` runs before every detonation batch and its output is what
the attestation manifest signs. Two rules, both learned the hard way:

- **Do not use `nc -z`.** Android's toybox `nc` has no `-z` flag; it exits 1 with
  `Unknown option 'z'`, which made `blocked()` return True unconditionally — every
  containment check passed regardless of the real network state, and the signed
  manifest attested containment that had never been tested. Correct probe:
  `toybox nc -w N HOST PORT </dev/null` followed by an explicit `echo DRISHTI_RC=$?`
  that you parse (0 = reachable, 1 = not).
- **Fail closed.** `assert_probe_trustworthy()` must run a negative control
  (`127.0.0.1:1`, must read unreachable) and a positive control (a listener you
  started, must read reachable) before any verdict is trusted. Map
  `subprocess.TimeoutExpired` to rc 124 and read it as *blocked* — a blackhole
  `-j DROP` makes `curl` hang past `--max-time`, and an unhandled timeout previously
  turned containment verification into a coin flip on DNS cache state.

A containment failure aborts the batch. It never downgrades to a warning.

---

## Real-malware corpus and ML training

The classifier is trained on real APKs pulled to `gs://<proj>-corpus/`, not on
feature dumps from 2014 alone and never on generated data.

- **Sources:** AndroZoo (needs the API key; it is the volume source), MalwareBazaar
  recent Android tags (the 2024–25 samples that make the time split honest), F-Droid
  / APKPure for the benign baseline. Record the exact source, date, and row count of
  every corpus build in `STATUS.md`.
- **One feature extractor, both paths.** `m5_ml/features.extract(StaticReport)` is
  called by training (over `StaticReport`s produced by running real M2 on the corpus)
  and by inference. There is no second code path, and
  `tests/contract/test_feature_parity.py` is what keeps it that way.
- **Time-split, with a plausibility window on `dex_date`.** A large fraction of
  AndroZoo rows carry a ZIP-epoch fallback (1980/1981) or impossible futures
  (2039+). Unfiltered, those all land on one side of the split and the
  generalisation claim silently stops holding. `build_sample_list.py` must enforce
  `--min-date`/`--max-date` and report how many rows it dropped.
- **Interleave the sample list deterministically by (split, label)** before
  extraction. A bucket-ordered list means the first N thousand rows are nearly all
  malware with zero test rows, and time-split evaluation cannot run at all.
- **Reputation inputs must not be label-derived.** AndroZoo's labels come from
  `vt_detection`, so feeding a VT-derived signal into `R` makes composite-score
  metrics circular. `reputation.py` refuses a label-derived feed by default
  (`allow_label_derived=False`). Do not flip that to make a number look better.
- **Report both random-split and time-split metrics.** The gap is a real finding and
  the argument for the behavioural and GenAI layers. Calibrate on a held-out third
  split, never on test.
- Corpus APKs stay in GCS and in the VM's ephemeral scratch. They are never
  committed, never copied to a laptop, and stored zipped with the `infected`
  convention at rest.

## Session protocol

**At session start:**
1. Read `STATUS.md`. It is the current state of the world.
2. Read the phase file for the current phase.
3. Confirm the task's `depends_on` items are `DONE` in `STATUS.md`. If not, say so
   and pick a different task rather than building on sand.
4. If the task touches M3, Phase 5, or training: check the lab state first
   (`make lab-status` — project, image version, VM state, corpus row count). Say
   plainly whether you are working against live GCP or against a committed fixture.

**Per task:**
1. State which task ID you're doing and its acceptance criteria.
2. Write the test first when the task has a testable acceptance criterion. For this
   project that means: contracts, ledger, scorer, feature extractor, morph
   validation, evasion detection, containment probes. For UI and prompt work,
   tests-first is not required.
3. Implement.
4. Run `make test`. Green before moving on.
5. Update `STATUS.md`: task → DONE, hour, commit sha, test count. Record any
   deviation from the roadmap under `### Deviations`.
6. Commit: `feat(m2): backward BFS from sinks with entrypoint attribution`.

**Per detonation run,** additionally: containment verified → snapshot restored →
sample sha256, image version, and VM instance id recorded in the run manifest →
`make lab-down` when the batch is finished.

**At session end:** summarise what changed, what's next, any new risk, and **whether
any GCP resource is still running**.

## Non-negotiable engineering rules

1. **Contracts first.** All cross-module types are pydantic models in
   `drishti/contracts/`. Never pass a raw dict across a module boundary. If a field
   is missing, add it to `docs/01_DATA_CONTRACTS.md` first, then to the model, then
   use it.
2. **Every module degrades.** Wrap all external calls (anthropic, adb, frida,
   mitmproxy, mobsf, gcloud, gcs, network) in `@degrades_gracefully`. Return partial
   results with `errors` populated. A failing sub-analyser must never fail the job.
3. **The scorer is pure.** `m6_score/engine.py` does no I/O, calls no LLM, uses no
   clock and no randomness. If you're tempted to add any of those, you're solving
   the wrong problem.
4. **The LLM never emits the score.** It emits enumerated behaviour booleans;
   Python computes `B` from a weight table. If you find yourself parsing a number
   out of model output for anything that reaches `S`, stop.
5. **No ungrounded claims.** `ledger.append()` rejects an `AI_CLAIM` with empty or
   unresolvable `evidence_refs`. Don't work around it — that rejection is the
   product.
6. **Untrusted content is structurally isolated.** Sample-derived strings and code
   go in `<untrusted_artifact>` blocks in the user turn, XML-escaped, never
   concatenated into a system prompt.
7. **LLM output that reaches a command surface is validated.** Morph params go
   through `validate_morph()` before touching adb or JS. Params are injected as
   JSON literals, never string-concatenated into expressions.
8. **Prompts live in `m4_genai/prompts/*.jinja`.** Never inline a prompt in Python.
9. **The ledger is append-only in SQL**, via triggers, not just in Python.
10. **Budgets are asserts, not hopes.** LLM calls ≤25/job. Static ≤90s. Prompt
    ≤12k tokens in. Enforce in code.
11. **Aggregate raw dynamic events before they reach the ledger or a prompt.** One
    real sample called `Cipher.doFinal` 1925 times in 60s; appending a node per
    event would have put 1925 near-identical nodes in the ledger and blown the
    prompt budget. Group by (technique, mitre, hook), keep an occurrence count, cap
    at `MAX_OBSERVATION_GROUPS = 40`. `b_dynamic` must be unchanged by aggregation.
12. **No credentials in the image or the repo.** The VMs use their service account
    via the metadata server; the emulator can't reach it. `.env` is gitignored and
    the analysis project holds no keys for anything outside itself.

## Style

- Python 3.11 for the app; note that the **GCE image ships Python 3.10** — anything
  that runs on the VM must import cleanly there (this is why frida is pinned)
- `ruff` formatted, type hints on all public functions
- `structlog`, structured JSON, one line per meaningful event; log lines in the
  M3/FRONTIER path are user-facing on the demo screen — write them for a human
- Docstrings on public functions: what, not how
- Shell in `infra/gcp/` is `set -euo pipefail`, idempotent, and comments every
  non-obvious line with why (`# FIX-2: frida<17 — 3.10 has no typing.NotRequired`)
- No cleverness in the demo path. Boring code that works at hour 71 beats elegant
  code that doesn't

## Testing

```
tests/contract/   schema round-trips, ledger chain, feature parity, purity,
                  containment-probe trustworthiness                    ← CI gate
tests/unit/       per-module logic
tests/e2e/        full pipeline on a fixture APK
tests/lab/        marked `@pytest.mark.gcp`, needs a live lab, excluded from CI
```
`make test` runs contract+unit. `make e2e` runs the slow ones. `make lab-test` runs
the GCP-marked ones against a live detonator. CI runs contract tests on every push —
those are the ones that prevent the integration disaster. **CI never touches GCP and
never sees a sample.**

## When you're blocked or the roadmap is wrong

The roadmap was written before the code existed and is expected to be wrong in
places. When reality disagrees with it:

1. Say so explicitly rather than silently improvising.
2. Propose the smallest deviation that unblocks the work.
3. Record it under `### Deviations` in `STATUS.md` with a one-line reason.
4. If the deviation changes a contract, update `docs/01_DATA_CONTRACTS.md` in the
   same commit.

Do not silently expand scope. Do not add dependencies not in `pyproject.toml`
without saying why. If a task looks like it will take more than 2× its budgeted
time, stop and flag it — the cut-list in `00_GUIDING_MAP.md §10` exists for exactly
that moment.

For GCP work specifically: **debug on the VM, from the VM's own logs, one variable
at a time.** The failure modes above all looked like something else at first
(an IAM problem that was an active-account problem, a missing library that looked
like a GPU problem, a 404 that looked like a network problem). Before concluding
"IAM", check `gcloud auth list` against `gcloud config get account` on the VM — a
configured account with no credentials on it produces an authorisation error that
reads exactly like a missing role.

## Honesty requirements in output

Several parts of this system make claims to a human reader. Those claims must track
reality automatically, not by anyone remembering:

- The report's **Limitations** section is generated from real flags (`partial`,
  `source == replay`, `composite`, `synthetic`, rejected-claim count). Never
  hardcode it.
- **Replay vs. live is read from the trace, not from a config.** A trace carries the
  image version, VM instance id, and run timestamp it was produced by; the UI badge
  is derived from those. Replaying a real captured trace is legitimate and must be
  disclosed on screen; presenting it as live is not.
- **A sample that produced no observations is `inconclusive`, never benign.**
  Environment-aware stalling looks identical to a clean app if you let it.
- **Containment claims come from the verified probe output** embedded in the run
  manifest. If the probe did not run, the manifest says so and the report does too.
- Metrics shown anywhere (PR-AUC, FP rate, triage time) come from a measurement
  written to `STATUS.md`, never from the ideation PDF and never from an estimate.

If you're about to write a number into the UI or report that you can't trace to a
measurement, don't.
