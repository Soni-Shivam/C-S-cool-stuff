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

- **The Sandbox and Frontier views are empty for these three samples.** No sandbox was
  reachable, and the UI says exactly that rather than showing a blank panel. A live
  detonation of the canary was in progress at the time of writing.
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
