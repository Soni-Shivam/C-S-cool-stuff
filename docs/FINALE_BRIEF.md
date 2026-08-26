# Finale brief — three samples, measured 2026-08-27

Every number here was produced by this branch at `faf7d01` on a live pipeline run and
can be reproduced in front of a judge. Nothing is estimated.

## Bring it up

```bash
uv run uvicorn drishti.api.main:app --port 8090
DRISHTI_API_ORIGIN=http://127.0.0.1:8090 npm --prefix ui run dev
```

The dashboard deep-links, so each beat is a URL: `?job=<id>&view=<overview|static|sandbox|frontier|ledger|report>`.

## The three samples

All three are built from source in this repo. `verify_inert.sh` gates the two demo
apps, so neither can grow a real capability without the build failing.

| Sample | Built from | Score | Band | Action |
|---|---|---|---|---|
| `RTO_Challan.apk` | `canary/decoy-challan/` | **65** | HIGH | **BLOCK** |
| `Sanchay_Expenses.apk` | `canary/benign-sanchay/` | **60** | MEDIUM | REVIEW |
| `canary.apk` | `canary/` | **30** | LOW | REVIEW |

## The beat that lands: two apps, one permission set

This is the Truecaller problem made concrete, and it is the argument for the whole
system. Measured permission sets:

```
shared by both : INTERNET, QUERY_ALL_PACKAGES, READ_CONTACTS,
                 READ_SMS, RECEIVE_SMS, SYSTEM_ALERT_WINDOW
decoy only     : REQUEST_INSTALL_PACKAGES, FOREGROUND_SERVICE, RECEIVE_BOOT_COMPLETED
benign only    : POST_NOTIFICATIONS, VIBRATE
```

Six dangerous permissions are identical. A permission-list scanner cannot separate
these two apps at all. DRISHTI separates them, and the Overview says so in the
"Shared with apps you trust" panel: *"the permission set is not the finding."*

**What actually separates them** — the lookalike discriminator, on screen in view 04:

| | decoy | benign |
|---|---|---|
| `trojan_score` | **0.25** | **0.0625** |
| `financial_app_roster` | **FIRED** — references `com.phonepe.app`, `com.sbi.lotusintouch`, `net.one97.paytm` | not present |
| `freshly_minted_certificate` | **FIRED** — signing cert 9 days old, signer not a known publisher | not present |

A 4× separation on identical permissions. The decoy carries a roster of Indian banking
packages it has no legitimate reason to know about.

**Say this before a judge asks it:** on real, *packed* 2024-25 banking trojans this
discriminator does **not** separate at the operating threshold — measured rank-AUC
0.621 over 75 corpus APKs, recorded in `STATUS.md` under *Measured negative results*.
Androguard recovers a median of 12 methods from those samples; the behaviour it keys on
is not in the static image. That is precisely why detonation exists. Volunteering this
is stronger than being caught by it.

## If asked "why is your benign app flagged at 60?"

Because it genuinely holds READ_SMS, SYSTEM_ALERT_WINDOW and READ_CONTACTS — an
SMS-reading expense tracker is a real and legitimate app category in India. The model's
behaviour booleans are grounded in the manifest, not hallucinated. The verdict is
REVIEW, not BLOCK, and the consumer sentence is *"We could not confirm this app is
safe"* — not an accusation.

The honest framing: **static analysis reaches a ceiling here, and the score says
MEDIUM/REVIEW rather than pretending certainty.** We did not tune weights to
manufacture a gap; `CLAUDE.md` forbids it and the negative result above is published.

## What the system refuses to do — the strongest material

- **Nothing executed, and it says so.** All three runs show `NO TRACE — STATIC ONLY`,
  and Limitations reads *"No sandbox was available, so this sample was never executed.
  Nothing in this report was observed at runtime."*
- **A quiet sample is INCONCLUSIVE, never benign.** The report states it in those words:
  environment-aware malware stalls in a sandbox and is indistinguishable from a clean
  app when it does.
- **The frontier does not fire without an observation.** No probe observed → no morph
  planned → no second pass. Verified: 0 `morph_action` nodes in the ledger.
- **The ledger verifies.** `GET /api/jobs/{id}/ledger/verify` → `{"ok": true,
  "node_count": 30}` for the canary; 84+ evidence nodes on the decoy.
- **The LLM never emits the score.** It emits enumerated behaviour booleans; Python
  computes `B` from a weight table. The Behaviours panel says so on screen.

## Known gaps — state them plainly if asked

- **The Frontier view is empty for these samples** — no environment probe was observed,
  so the frontier correctly does not fire. The UI says that rather than showing a blank
  panel.
- **The inert second stage is built but not reachable end to end.** `SINKHOLE_URL` is
  guest loopback (`127.0.0.1:9`), so a fetch of it never traverses the emulated NIC.
  Deliberate: making it reachable means rewriting the inertness gate, which is the one
  function that makes "we never serve capability" true.
- **The redaction gate has no PAN/phone/UPI rules yet.** It catches OTP, credential,
  token and JWT patterns. Tracked, and it must land before real samples are put through
  HTTP capture.
- **Two `tests/e2e/test_pipeline_walk.py` tests fail** and predate this entire branch
  (verified at the base commit `a4f013e`). `STATUS.md`'s header claim of "15 e2e, all
  passing" is stale and should be corrected rather than refreshed.

## The Sandbox view has a real detonation behind it

`canary.apk` was detonated live on the sealed `m3-detonator` (VM instance
`7382052279419138339`, image `m3-detonator-manual-20260826`), containment manifest
signed minutes before the run, snapshot clean before and after, `simulated=false`. The
capture is committed at `data/fixtures/traces/9854900c….json` with
`provenance.kind=captured`, so the dashboard replays a **real** run and discloses that
it is a replay — the badge reads REPLAY, never LIVE.

**Detonation is what moves confidence, and now you can show it:**

| canary | static only | with the real trace |
|---|---|---|
| provenance | `STATIC_ONLY` | `REPLAY` |
| threat score | 30 | **47** |
| confidence | **0.24** | **0.86** |

The three observations are exactly what the canary is built to do — `T1418` package
probe, `T1412` SMS query, `T1437` network call. Nothing else.

## The overlay detector was firing on almost everything

Worth telling, because it is the strongest evidence that the honesty machinery works.

`T1417 Input capture via overlay` is *the* headline banking-trojan behaviour. The Frida
hook emitted it on every `WindowManagerImpl.addView` call without reading
`LayoutParams.type` — and every Activity attaches its content view that way. Measured
across the captured corpus: **47 of 52 artifacts claimed an overlay attack**, including
the canary, which this repo forbids from drawing one.

It was caught because our own control app confessed to an attack it is built to be
incapable of. An overlay needs a *system* window; the hook now emits only for the system
range (2000–2999). For the 116 artifacts already captured with the blind hook, the
overlay observation is dropped at ingest **and the drop is disclosed** in the report's
Limitations. The captured artifacts are not rewritten: they record what the hook emitted,
which is true. What changed is whether we draw a conclusion the instrument could not
support.

Four artifacts had *only* that observation. They now produce no fixture at all, because
a fixture with nothing in it replays as "the sample did nothing" — a different claim from
"we could not observe it", and the more dangerous one.

## The trust invariants — all three verified working 2026-08-27

Each runs in well under a minute and needs no network. These are the strongest
material in the deck, because they demonstrate a *refusal* rather than a capability.

```bash
make demo-reject      # an AI claim citing no resolvable evidence is REFUSED
make demo-tamper      # one edited byte is located at the exact node
make demo-containment # the containment gate accepts only a trustworthy probe
```

**`make demo-reject`** — two ungrounded claims are refused, and the surviving sequence
is contiguous: `chain ok=True nodes=2 seqs=[0, 1]`. Grounding is checked *inside* the
write transaction, so a rejected node never consumes a sequence number and never leaves
a hole an auditor would have to ask about. Closing line: *the model does not get to
decide what counts as evidence.*

**`make demo-tamper`** — after editing one field: `first_bad_seq: 3`, reason
`node_hash does not match the node's content (tampered)`, 5 nodes walked. The auditor
gets the precise node, not "the ledger is broken somewhere". Forging evidence undetected
means forging an Ed25519 signature for every node from 3 to the end.

**`make demo-containment`** — replays the v1 defect: toybox `nc` has no `-z` flag, so
every probe returned the flag error and `blocked()` was unconditionally true. The gate
now reads `probe_trustworthy = False` and refuses to make any containment claim, because
the positive control reported UNREACHABLE while a listener was running. A probe that
cannot see an open network is not evidence of a closed one.

## Two exports were lying, and now are not

Worth knowing because both are the kind of thing a judge inspects rather than watches.

**STIX exported any sub-HIGH sample as `benign`** while the dashboard beside it said
*"safety could not be confirmed either way"* and recommended REVIEW. That is the
never-benign rule broken in the one artefact a SOC actually ingests — a machine-readable
file asserting a sample is clean when the system's own screen refuses to. Now `unknown` /
`anomalous-activity`. Verified on a LOW sample: the word "benign" appears nowhere in the
bundle.

**The verdict card overstated its own evidence base 2.4×** — 44 `evidence_refs` of which
18 were distinct, so it drew duplicate chips and computed "+36 more" from the inflated
length. On the card whose entire purpose is *here is the evidence*. Verified after the
fix: 34 total, 34 distinct.

## Verification state at `d645481`

- **contract + unit: 1,812 tests, EXIT 0.**
- **e2e: 16 tests, EXIT 0.** `make e2e` was RED before this branch — all four failures
  came from the suite asserting a stage list and node count that only held while the
  pipeline fabricated an evasion observation. It is green now, and `STATUS.md`'s header
  has been corrected rather than refreshed.
- **`make lint`: clean.** `ruff format --check`: 199 files already formatted.
- **`make ui-build`** passes (tsc + vite); **`make ui-test`** 14/14.
