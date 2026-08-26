# DEMO AND MOAT — what we show, and what actually defends it

Working reference for the pitch. Not slides. Every claim here is either traceable to
something in this repo or explicitly labelled as unbuilt.

**Rule for this document, and for anything built from it:** if a number is not traceable
to a measurement in `STATUS.md`, it does not appear on a slide. See
`CLAUDE.md` § *Honesty requirements in output*.

---

## 1. The problem statement, restated honestly

The brief asks for GenAI-powered automated APK analysis: reverse engineering, malware
pattern recognition, code interpretation, threat summarisation, static and dynamic
analysis, risk scoring, and investigation reports with actionable recommendations —
*for banks*.

The trap in that brief is that it reads like "build an antivirus". Google already built
the antivirus, it runs on three billion devices, and we will not beat it at detection.
The defensible reading is the second half of the sentence: **proactive cybersecurity and
fraud prevention measures for banks.** That is a product Google does not sell.

**Positioning line:**

> Play Protect answers *"should this install?"* for a billion phones. DRISHTI answers
> *"what exactly did this intend to do to my customer, how do I prove it, and who do I
> report it to?"* for one bank's fraud desk. Those are different products, and only one
> of them is buyable.

---

## 2. The interception window — the single most important idea

On stock, unrooted Android there is **no install-veto API** for third-party apps.
`PACKAGE_VERIFICATION_AGENT` is `signature|privileged`, which is precisely why Play
Protect has a monopoly on that hook. Pretending otherwise loses the room.

What is true, and better: **Play Protect engages at install time. We engage at file-landing
and at tap.** The gap between those two moments is the window in which the victim decides.

### The deployment ladder

Naming all three rungs honestly is stronger than claiming the top one, because the ladder
*is* the go-to-market story — each rung is a different sales motion.

| Mode | How it deploys | What it can do | Status |
|---|---|---|---|
| Consumer | Play Store install | Detect at file-landing and tap, quarantine, one-tap uninstall | Layers 1, 2, 4 |
| **Device Owner** | **Bank MDM, telecom-subsidised handset, enterprise fleet** | **Genuine install veto** via `DISALLOW_INSTALL_UNKNOWN_SOURCES`, `setPackagesSuspended`, `setUninstallBlocked` | **What we demo** |
| Privileged verifier | OEM partnership | Play-Protect-class `PACKAGE_NEEDS_VERIFICATION` hook | Named, not built |

Device Owner is a real, shipping, Google-supported deployment model — not a hack. It is
provisioned with one command on a fresh device:

```bash
adb shell dpm set-device-owner in.drishti.shield/.DrishtiAdminReceiver
```

### The four interception layers

1. **File-landing** — watch Downloads/WhatsApp for a new `.apk`, hash it, scan it. Fires
   *before the user taps anything*. This is the beat that carries the whole pitch.
2. **Tap-time** — intent filter on `application/vnd.android.package-archive`, so DRISHTI
   opens instead of the package installer.
3. **Install-veto** — Device Owner policy refuses the install outright.
4. **Post-install failsafe** — `PACKAGE_ADDED` → full-screen block + `REQUEST_DELETE_PACKAGES`.

---

## 3. Demos, ranked by impact per hour of build

### D1 — The 90-second interception *(hero)*
Split screen, emulator left, dashboard right. A mock WhatsApp message delivers
`RTO_Challan.apk`. Shield's notification fires **before the tap** — put a stopwatch on
screen. The dashboard's stage strip lights up live. The victim taps Install; the Device
Owner veto kills it. Verdict, evidence chips, every AI sentence clickable to a real
decompiled method. One tap produces the dossier.

### D2 — The hallucination test *(cheapest, highest impact)*
`make demo-reject`. **Built and working.** An AI claim citing nothing is refused; a
*fabricated* citation is refused by resolution; the same claim is accepted once cited.
The refusals leave **no gap in the sequence**, because grounding is checked inside the
write transaction.

> Every other GenAI security tool asks you to trust the model. We built one where the
> model's output is rejected by default and has to earn its way in.

### D3 — The sandbox-aware sample *(most novel, highest risk)*
Detonate an evasive sample: 60 seconds, nothing. Verdict **INCONCLUSIVE — not benign.**
Enable environment morphing — fake Jio SIM, installed banking apps, Indian locale — and
re-detonate. It wakes up. Trace diff side by side.

> Play Protect's sandbox looks like a sandbox. Ours looks like a Jio phone in Pune with
> HDFC installed. Malware written for Indian victims only shows itself to Indian victims.

**Depends on live detonation, which has never succeeded in this project.** Fallback is a
replay of a genuinely captured trace, which the UI discloses automatically.

### D4 — Two runs, one score
Same APK twice; `S` is bit-identical while the LLM's prose differs.

> The LLM never touches the score. It emits booleans; Python computes S from a fixed
> weight table. A regulator can reproduce our verdict. Nobody can reproduce a chatbot's.

### D5 — The tamper demo
`make demo-tamper`. **Built and working**, and it came out as *two* layers: the
append-only SQL triggers refuse the `UPDATE`; after an attacker drops the triggers and
rewrites the row, the hash chain still reports the break **at the exact seq**.

> This isn't a log. It's a chain. If anyone edits our evidence — including us — it shows.

### D6 — The polymorphic batch
Five repacked variants: different hashes, different certs, renamed packages. A blocklist
sees five unknowns; DRISHTI clusters them by sink graph and generates a YARA rule live.
The generator refuses to key on the hash, precisely so this works.

### D7 — The bank fraud desk
Reframe the dashboard as a triage queue: customer-reported APKs, auto-scored, analyst
confirms or overrides, every override written to the ledger as `ANALYST_ACTION`. Turns
"antivirus" into "fraud-ops infrastructure", which is what the brief actually asks for.

---

## 4. Illustrations

The first is worth more than the rest combined.

1. **The interception window.** Time axis, t=0 at file landing. DRISHTI verdict at t≈8s.
   Play Protect's earliest hook at install-tap. Shade the gap: *"the window where the
   victim decides."*
2. **The four-layer stack**, each rung badged with the Android API and the deployment
   tier it needs — shows the honest degradation story in one image.
3. **Score waterfall** — S decomposed into its factors, each bar clickable to evidence.
4. **The chain, drawn as a chain** — with one node greyed and struck through:
   *"rejected — no evidence_ref."* The rejection rendered as a feature.
5. **Sink-graph flow** — `READ_SMS` → `getMessagesFromIntent` → `getOutputStream`,
   entrypoint `BootReceiver`.
6. **Morph trace diff** — 3 events flat vs 47 events spiky. Same APK.
7. **Time-split vs random-split PR curves** — the *gap* is the finding.
8. **MITRE ATT&CK Mobile heatmap**, static vs dynamic layers distinguished.
9. **India fraud kill-chain** — WhatsApp forward → APK → permission grant → overlay →
   OTP intercept → UPI debit. Mark where DRISHTI cuts it: step 2.

---

## 5. The moat, sorted by how hard it is to copy

### Tier 1 — architectural. This is the real defensibility.

1. **Grounding by construction.** `ledger.append()` rejects an `AI_CLAIM` whose
   `evidence_refs` are empty or unresolvable. Not a prompt trick — a data-structure
   decision that forces every upstream component to emit citable artefacts. A competitor
   built on "the LLM writes the report" cannot retrofit this without a rewrite.
2. **The LLM is outside the scoring path.** Booleans → fixed weight table → deterministic
   `S`. Reproducible, auditable, immune to model drift. You can change model providers
   without re-validating your risk model — a genuine operational moat for a regulated buyer.
3. **Evidence is legally shaped from day one.** Append-only in SQL *via triggers*,
   hash-chained, Ed25519-signed, analyst actions recorded. The difference between "our
   tool flagged it" and "here is an exhibit". Once a bank's legal team accepts your
   evidence format, switching cost is enormous. **Commercially the strongest asset.**
4. **Honesty as a machine property.** Limitations derived from provenance flags; no
   observations ⇒ `inconclusive`, never benign; replay-vs-live read from the trace, not a
   config. Every other demo in the room quietly overstates. Saying this out loud is
   disarming *and* true.

### Tier 2 — expensive to copy

5. **Environment morphing.** Needs the sealed lab, the Frida hook catalogue, and
   validation that a morph adds no capability to the sample.
6. **The deployment ladder** in §2 — three rungs, three go-to-market motions.
7. **India-specific typology.** Challan, KYC-update, PM-Kisan, electricity-disconnection,
   fake-bank families; Hindi and regional social-engineering text; UPI-overlay plus
   SMS-forwarder combinations. Google optimises for global scale.

### Tier 3 — compounding. Worth saying even before it is built.

8. **Bank-federated feed.** Each participating bank's customer reports improve the
   typology model; the improved model attracts the next bank. Google cannot replicate it
   because Google does not see bank fraud reports.
9. **Become the format.** If the STIX/dossier export is what Indian cyber cells expect to
   receive, we are infrastructure. Align to CERT-In/NCRP conventions deliberately.

---

## 6. Claims to refuse

Saying these loses the argument, and they are not true:

- ❌ *"Better detection than Play Protect."* Unprovable, and it is Google's home turf.
- ❌ *"Real-time protection for all Android users."* Not without Google.
- ❌ *"We auto-file complaints with the cyber cell."* **NCRP has no public submission
  API.** We generate the complaint package and deep-link a human. `submission_is_manual`
  is always `True` and the UI must say so.
- ❌ *"We auto-submit samples to threat-sharing platforms."* Forbidden by `CLAUDE.md`'s
  hard boundary on distributing samples outside the analysis project's private bucket.
- ❌ Any number not traceable to a measurement in `STATUS.md`.

---

## 7. What is actually built, as of 2026-08-26

Kept current so nobody pitches something that does not exist.

| Capability | State |
|---|---|
| Evidence ledger, hash-chained, append-only in SQL | **Built**, `make demo-tamper` |
| Ungrounded-claim rejection | **Built**, `make demo-reject` |
| Deterministic scorer, LLM outside the score | **Built**, purity asserted at source level |
| Static engine: 14 permission-combo rules, 29 sinks, bounded decompilation | **Built** |
| GenAI: grounded claims, MITRE mapping, bounded tool loop | **Built**, live provider verified |
| Investigation report, STIX 2.1, YARA, dossier | **Built** (T6.3/T6.2/T6.1 + A12) |
| Seven-view dashboard with RE workspace | **Built** |
| Corpus extraction over real AndroZoo samples | **Running** |
| Trained classifier with reportable metrics | **Not yet** — pilot only, PILOT-stamped |
| Live detonation of a real sample | **Never achieved.** Replay fallback available |
| Android Shield app + Device Owner veto | **In progress** |
| Environment morphing (D3) | **Not built** |
