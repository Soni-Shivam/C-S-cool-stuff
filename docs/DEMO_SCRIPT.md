# DEMO_SCRIPT — the live interception demo

**What the audience sees:** a phone receives a WhatsApp-style forward of
`RTO_Challan.apk`. Before anyone touches it, a full-screen verdict appears on the
phone naming the evidence. The install is then attempted and the *operating system*
refuses it. The dashboard fills in on its own, with nobody touching the browser.

**Before that**, a second app — holding the *identical* permission set — arrives and is
**cleared**. That pair is §2.1b, it is the beat judges probe hardest, and it should
never be cut.

**Total runtime:** 4 minutes. Setup from cold: **31.5 s measured**. Verdict on screen:
**4.4–5.7 s measured** (8 runs, both apps). The scripted pair end to end: **31–41 s**.

**The one command that runs the whole thing:** `scripts/demo_run.sh`.

> **These numbers move.** Other agents are landing the ML model, the LLM provider and
> the report exports while this is being written. Every figure below carries the date
> it was measured; re-measure with §7 before you go on stage and correct anything that
> has drifted. Do not read a stale number aloud.

Every number in this file was measured on the demo laptop on 2026-08-26 and is
reproducible with the commands shown. Nothing here is an estimate.

---

## 0. Roles and the one rule

| Role | Does |
|---|---|
| **Driver** | Hands on keyboard. Says nothing. Runs exactly the commands in §2. |
| **Narrator** | Says the words. Never touches the machine. |

The one rule: **the driver does not improvise.** If something goes wrong, the driver
runs the fallback in §5 and the narrator keeps talking.

## 1. Setup — T-minus 5 minutes

```bash
cd <repo>
scripts/demo_up.sh --fresh          # 35 s measured, cold, including a wiped AVD
```

`--fresh` wipes the AVD. Use it: device owner can only be provisioned on a device
with no accounts and no existing owner, and a wiped AVD guarantees both. If you are
re-running within a few minutes and the last run ended clean, plain
`scripts/demo_up.sh` is fine.

**The script fails hard if the veto cannot be armed.** It does not warn and carry on,
because Layer 3 is the beat the demo turns on. Confirm the banner reads:

```
  Layer 1      watcher service running
  Layer 3      device owner HELD, veto self-test PASSED
```

**Read the second half of that Layer 3 line, not the first.** "HELD" alone is a claim
and it has lied: `adb install -r` drops the *active admin* record while the *device
owner* record survives, so from the second run of the day onwards `dpm list-owners`
kept reporting DeviceOwner while every `addUserRestriction` threw a `SecurityException`
and the demo blocked nothing. Measured, before the fix: `block=true veto=false` on the
decoy and `Device policy restrictions: none` in dumpsys, with setup reporting success
throughout.

So `demo_up.sh` §7b now **engages the real veto, reads the restriction back out of
`UserManager`, and releases it** before it hands you a stage-ready demo. That is what
"veto self-test PASSED" means. If it fails, the script dies rather than letting you
find out on stage.

If provisioning fails the script exits non-zero and tells you what to do. To run
deliberately without the veto — Layers 1, 2 and 4 still work and the verdict screen
still names its evidence — pass `--allow-no-owner` and skip §2.4.

**If the dashboard build fails**, setup no longer dies: it serves the previous build
from `ui/dist`, prints the compiler error and warns that the screen may not match the
source. The phone, the four layers and the veto are unaffected. Read the warning — do
not narrate a dashboard feature you cannot see working.

**Windows to arrange before the audience arrives:**

- Emulator window, **left half**, as large as it will go.
- Browser at `http://127.0.0.1:4173/`, **right half**.
- A terminal, small, bottom-right. The driver types in this.

**Warm the LLM cache before the audience arrives.** The GenAI provider is a free
OpenRouter endpoint that 502s under load; a throwaway delivery makes the real run a
cache hit:

```bash
scripts/demo_deliver.sh --instant --no-notify     # throwaway, warms the cache
adb shell rm -f /sdcard/Download/RTO_Challan.apk   # reset for the real beat
adb logcat -c
```

Open the Shield app on the emulator (it should already be foreground) so the four
layer cards are visible while the narrator does the intro.

## 2. The beats

### 2.1 — The setup · 30 s · narrator only

> "This is an ordinary Android phone. The app on screen is DRISHTI Shield. It is not
> an antivirus — it does not have a signature database. It watches the Download
> folder, and when something arrives it asks our analysis backend what it is.
>
> Four layers, and the screen tells you honestly which ones are actually armed right
> now. Layer 3 is the one that matters: this app is the device owner, which means it
> can tell the operating system to refuse an install."

Point at the four cards. They report real state read from the system, not badges.

### 2.1b — The control · 45 s · **the beat judges probe hardest**

**Run this before the block, every time.** The first question any room asks a malware
detector is *"does it just flag everything?"*, and a demo that only shows a block
cannot answer it. This beat answers it with the strongest evidence available: an app
that is **cleared while holding the identical permission set the fraud APK holds.**

**Driver:**
```bash
scripts/demo_deliver.sh --benign
```

A notification from *"Priya (Family)"* — no urgency, no threat — then
`Sanchay_Expenses.apk` lands in the same watched folder, is scanned by the same
watcher, through the same backend.

> "Before I show you anything being blocked, I want to show you something *not* being
> blocked — because that is the harder problem.
>
> Sanchay Expenses is an SMS-driven expense tracker. It declares `READ_SMS`,
> `RECEIVE_SMS`, `READ_CONTACTS`, `SYSTEM_ALERT_WINDOW` and `QUERY_ALL_PACKAGES`.
> That is **the same five dual-use permissions** the fraud APK declares — and, not
> incidentally, close to what Truecaller ships with. If our tool worked by counting
> scary permissions, this app would be dead.
>
> DRISHTI clears it. Same watcher, same backend, same rules."

**Measured 2026-08-26:** `block=false basis=CLEAR veto=false`, **4411 ms** from file
landing to verdict.

The install then proceeds untouched, and the script proves it from the same dial it
will use to prove the block:

```
Device policy restrictions:
  none
```

> "No restriction. We did not stand in the way. And Layer 4 — the post-install
> failsafe — watched it install and left it alone, which is the false positive you
> would have seen before I did."

**The one-command version of the whole pair,** which is what to use on stage:

```bash
scripts/demo_run.sh                 # cleared app, then blocked app, with pauses
scripts/demo_run.sh --fast          # no pauses (rehearsal)
```

It ends by printing the two verdicts side by side. That table is the answer to the
question, and it is worth reading aloud verbatim:

| | Sanchay Expenses | RTO Challan |
|---|---|---|
| shared dual-use permissions | 5 | 5 (identical set) |
| permission-combo rules matched | 1 high | 1 critical + 4 high |
| Shield decision | CLEAR — installed | BLOCKED — OS refused |

> "Same permissions. Different verdicts. The difference is not the permission list —
> it is which *combinations* co-occur, and what the code does with them. That is the
> whole argument."

**Order matters and is not negotiable.** The Layer 3 veto is a device-wide
`DISALLOW_INSTALL_UNKNOWN_SOURCES` restriction: once the block beat engages it,
*nothing* installs from unknown sources, the benign app included. Running the cleared
beat second would show it being refused by the previous verdict — confusing, and as a
claim about the benign app, false. `demo_run.sh` enforces the order.

### 2.2 — The forward · 20 s

**Driver:**
```bash
scripts/demo_deliver.sh
```

A real system notification appears — *"Traffic Police (+91 98XXX XXXXX) — Your
vehicle has a pending e-challan of Rs 1,500…"* — then three seconds later the file
lands in `/sdcard/Download`.

> "That is the most common malware delivery route in India right now. Not an app
> store — a forwarded file and a deadline. Watch the phone. **Nobody is going to
> touch it.**"

### 2.3 — The interception · 5–9 s · THE MOMENT

The verdict screen appears **by itself**. A millisecond counter runs live, then
freezes when the verdict lands.

> "No one tapped anything. The file landed, and DRISHTI had already hashed it,
> uploaded it, run static analysis, and come back — in about five seconds, before the
> user had a chance to make a decision.
>
> And look at what it says. It does not say 'threat detected'. It names the evidence:
> one critical and four high-severity permission combinations, each mapped to a MITRE
> technique. An accessibility service. SMS receive plus SMS read — that is an OTP
> interceptor. Overlay plus network. Install-packages — a dropper stage."

Scroll down slowly. Land on two things:

1. **The embedded endpoints**, defanged to `hxxp://` by the backend.
2. **`LAYER 3 VETO ENGAGED`.**

> "And the basis card is the part I want you to read. It says the decision was taken
> on M2 static evidence. Not on a score — on named rules, with MITRE identifiers."

**The composite score arrives a few seconds later** and fills in below. Measured
2026-08-26: **S = 43, MEDIUM**, with the ML classifier at `p_calibrated = 0.864`
(`random_forest-504f-1.1.0`) and γ = 0.60.

> "Our own classifier is 86% confident this is malicious. The composite score still
> only reaches 43 — MEDIUM — because the fusion formula stays conservative while
> there is no dynamic evidence, and 43 is below our HIGH threshold of 65.
>
> So the score did **not** authorise this block. The static evidence did, and the
> phone says so rather than quietly borrowing the score's authority. That is the
> honest version, and it is the one that survives a regulator."

**If a judge asks about the LLM** — the best question you will get:

> "It ran, and it returned a behavioural risk of 0.999 with seven behaviour flags. The
> scorer excluded it, because that verdict is marked partial — static evidence only,
> no detonation — and we do not let a partial layer move the number a human acts on.
>
> And it was over-reading. It asserted this app reads SMS content and exfiltrates over
> the network. Open the decoy's source: there is no SMS code and no networking code in
> it at all. It inferred behaviour from the declared manifest surface. That is exactly
> why the architecture computes the score in Python from enumerated booleans instead
> of letting the model emit one, and why every claim must cite evidence before the
> ledger accepts it."

*Do not skip this if it comes up.* It is a stronger demonstration of the design than
a high score would have been.

### 2.4 — The veto · 30 s · the proof

> "Now let us try to install it anyway."

**Driver** — tap the APK on the phone via a file manager, *or* run:
```bash
adb shell am start -a android.intent.action.VIEW \
  -t application/vnd.android.package-archive \
  -d file:///sdcard/Download/RTO_Challan.apk \
  -n com.google.android.packageinstaller/com.android.packageinstaller.InstallStart
```

Android's own **"Blocked by your admin"** screen appears
(`com.android.settings/.enterprise.ActionDisabledByAdminDialog`).

> "That is not our dialog. That is the Android Settings app, telling the user that
> device policy forbids this. There is no 'install anyway' button, because there is
> no button to add. DRISHTI set a `DevicePolicyManager` user restriction and the
> package installer refuses before it starts."

**Verifiable on the spot** if a judge asks. Measured output, 2026-08-26:
```bash
adb shell dumpsys activity activities | grep -m1 topResumedActivity
#   topResumedActivity=ActivityRecord{… com.android.settings/.enterprise.ActionDisabledByAdminDialog …}

adb shell dumpsys user | grep -A3 'Device policy restrictions'
#   Device policy restrictions:
#     no_install_unknown_sources
#   Effective restrictions:
#     no_install_unknown_sources_globally
```

> **Do NOT try to prove the veto with `adb install`.** It succeeds, and it is supposed
> to. `adb install` runs as the shell uid, which is a privileged installer and is
> exempt from `DISALLOW_INSTALL_UNKNOWN_SOURCES` — measured: `Success`, with the
> restriction fully in force. The restriction governs the *user-facing* install path,
> so the package installer route above is the only honest test. A judge who tries
> `adb install` and sees `Success` will think the veto is theatre; get ahead of it and
> say why shell is exempt. §2.7's failsafe beat depends on exactly this exemption —
> it is how the demo installs the decoy to show Layer 4 catching it.

### 2.5 — The dashboard · 40 s

Turn to the browser. It is already showing the job. **Nobody touched it.**

> "The phone posted the APK to our analysis backend, and the analyst dashboard
> attached to that job on its own. Same evidence, analyst's view: the permission
> table, the call paths, and the evidence ledger — every claim on the phone traces to
> a hash-chained node here."

Click **Ledger → Verify chain**. Then the **Static** tab for the permission table.

### 2.6 — The report · 20 s

Back to the phone. Tap **Report**.

The complaint package comes from the backend's `/artifacts/dossier` endpoint — the
same evidence as the HTML report and the ledger, not a second generator on the phone.

> "The complaint package a victim actually needs in order to file: hash, verdict, the
> evidence cited, the MITRE techniques, the limitations. It copies to the clipboard
> and opens the official portal.
>
> It does **not** file the complaint. There is no public submission API for the
> national portal, and we are not going to tell a victim we filed something we did
> not. The backend carries that as a field — `submission_is_manual`, always true —
> and the screen renders the field rather than trusting itself to remember. The
> helpline number is there too, because for financial fraud the first phone call
> matters more than the written complaint."

If the band is LOW or MEDIUM the screen says the package is **below the reporting
threshold**, with the backend's reason. That is shown, not hidden — a triage tool that
encourages complaints it cannot support degrades the portal for everyone."

### 2.7 — The failsafe, if there is time · 30 s

> "One more. Suppose the file got past all of that — a different download folder, a
> device where we are not device owner. Layer 4 assumes we already lost."

**Driver:**
```bash
adb install -r canary/decoy-challan/dist/RTO_Challan.apk   # shell uid — exempt from the veto
```

Shield hashes the *installed* package's APK, matches it, suspends it, and offers an
uninstall prompt.

> "It matched on content, not on the file name. Renaming it changes nothing."

---

## 2A. The consumer screen — what a *person* sees

Everything in §2 is written for an analyst: evidence, MITRE IDs, a millisecond
counter, a basis card. This beat is the other audience, and it is the one the room
feels. **One command, one screen, no browser.**

### The two screens

**The interstitial.** The DRISHTI mark — an eye inside a shield — breathing on
near-black. Not a spinner. One line:

> Analysing… please wait a moment.
> This is for your safety.

The user has not been told anything is wrong, because at that moment nothing is known
to be wrong. It is held for at least **3.4 s** (`ConsumerVerdictActivity.MIN_INTERSTITIAL_MS`)
even when the answer is already in hand — an answer that appears before the screen has
finished drawing reads as canned, on a stage and in a hand. The analysis really runs
underneath; when it takes longer, the screen simply waits.

**The verdict.** Painted entirely from `recommended_action` on the contract-A15
`Verdict` (`drishti/contracts/verdict.py`) and from nothing else:

| `recommended_action` | What appears |
|---|---|
| `BLOCK` | Full-screen red. **DO NOT INSTALL**, then *"This app is impersonating …"* naming `impersonated_target`, then `consumer_summary`. Buttons: **Delete this app** / **Go back — do not proceed** |
| `REVIEW` | Amber, softer wording, no hard block. **Delete this app** / **I trust this — continue** |
| `MONITOR` | Quiet, brand purple. **Nothing harmful found**, one **Continue** |

There is **no score, no confidence, no severity band, no MITRE ID and no evidence
reference on this screen**. Those are the analyst portal's job.
`tests/contract/test_verdict_kotlin_parity.py` fails the build if any of them is
referenced in the consumer activity, so it is enforced rather than remembered.

### Running it

```bash
scripts/demo_consumer.sh              # BLOCK   — the impersonation warning
scripts/demo_consumer.sh --review     # REVIEW
scripts/demo_consumer.sh --monitor    # MONITOR
```

To swap in a different verdict without rebuilding anything — this is how the operator
pins an outcome for a rehearsal:

```bash
scripts/demo_consumer.sh --verdict my_verdict.json    # validated against A15, then pushed
scripts/demo_consumer.sh --clear                      # back to the bundled fixtures
```

`--verdict` refuses a file that does not validate as
`drishti.contracts.verdict.Verdict`, so a bad field is caught in the terminal and not
by a blank line on the projector.

For the real thing, once a job exists:

```bash
scripts/demo_consumer.sh --live <job_id>
```

The app's own order is **backend → pushed file → bundled fixture**. Swapping between
them needs no UI change; the screen never learns where the object came from except for
one line of text (below).

### Making the tap land here

```bash
scripts/demo_consumer.sh --tap-on      # a tap on an APK opens the consumer screen
scripts/demo_consumer.sh --tap-off     # back to the analyst screen (the default)
```

**Off by default, deliberately.** Armed, a tap routes Layer 2 to the consumer screen
with the real job behind it — verified end to end on 2026-08-26: tap → job →
`GET /api/jobs/{id}/verdict` → screen, `origin=BACKEND`, no fixture, no ribbon. Left
off, §2 behaves exactly as rehearsed. Arming it is one command and changes nothing
else.

**Know this before you arm it for the decoy.** The A15 verdict maps `severity_band` to
the action, and the decoy currently scores **S = 43, MEDIUM**, which is
`REVIEW` — so the consumer screen says **BE CAREFUL**, in amber, while the analyst
screen says **BLOCKED** on static evidence. Both are correct and they are reading
different things (§2.3 explains why the score did not authorise that block), but do
not put the two screens side by side without saying so. `--verdict` with a pinned
object, or the `block` fixture, is the rehearsed way to show the red screen.

A tapped file with **no** A15 verdict lands on *"we could not check this app"*, never
on a fixture. A canned verdict must never stand in for a real file's analysis — that
is how a cleared app ends up under a red screen.

### The one honesty line

When the object on screen did **not** come from a live backend analysis of those
bytes, the screen carries `REHEARSAL FIXTURE — not a live analysis of this file`. It
is derived from where the object came from, not from a flag anyone sets, and it
disappears on its own the moment a real verdict is available. If you are asked about
it, that is the answer: the same rule as the replay-vs-live badge everywhere else in
this project.

### Measured — 2026-08-26, `drishti_demo` AVD

| Thing | Measured | How |
|---|---|---|
| Interstitial hold, verdict already in hand | **3408 / 3424 / 3420 ms** (3 runs) | `consumer_screen settled after … ms` in Shield's logcat |
| Configured floor | 3400 ms | `ConsumerVerdictActivity.MIN_INTERSTITIAL_MS` |

`scripts/demo_consumer.sh` prints that logcat line at the end of every run, so the
number quoted on stage always comes from the run just performed.

---

## 3. Measured timings

Measured 2026-08-26 on the demo laptop (16 cores, 23 GB RAM, KVM, Android 34
`google_apis` x86_64 AVD, 4 vCPU / 3 GB).

| Thing | Measured | How |
|---|---|---|
| **`demo_up.sh` cold to ready** (AVD exists, quick-boot snapshot, nothing running) | **31.5 s** | wall clock around the script, `84b62ac` |
| — of which emulator boot to "all four layers armed" | ~22 s | the script's own step banners |
| `demo_up.sh` warm (emulator already up) | **9–12 s** | wall clock, 3 runs |
| `demo_up.sh --fresh` cold to ready (wiped AVD) | **35 s** | wall clock around the script |
| **File landing → verdict, cleared app** | **4411 / 4724 / 5320 / 5696 ms** (4 runs) | `elapsed_ms` in Shield's own logcat line |
| **File landing → verdict, blocked app** | **4368 / 4813 / 5156 / 5519 ms** (4 runs) | same |
| **Full `demo_run.sh --fast`, both beats** | **30.9 / 37.3 / 40.4 s** (3 runs) | wall clock around the script |
| Emulator boot (wiped AVD) | 24–35 s | `Boot completed in …` in the emulator log |
| **File landing → verdict on screen** | **5.0 / 5.4 / 8.9 s** (3 runs, earlier build) | `elapsed_ms` in Shield's own logcat line, measured from the first inotify event |
| Composite score arriving afterwards | up to 33 s total | `total_ms` in the `score` logcat line |
| — of which M2 static analysis | 4.9–9.7 s | `stage_history` from `GET /api/jobs` |
| — of which `genai_static` | **0.8 s cached, 35 s cold** | the reason the verdict does not wait for it |
| — of which everything else | < 0.3 s | ingest 76–97 ms; ml, scoring, report all ≤ 21 ms each |

**Why the verdict is faster than the score.** The block decision needs M2's static
report; the score sits behind the GenAI stage in the pipeline. A cold free-tier LLM
call measured **35 seconds**, so Shield decides on static evidence, freezes the
counter, engages the veto, and attaches the score when it arrives. Earlier
measurements of 7.9–13.1 s were taken before this split and included the wait for the
score. A score can raise the verdict; it never lowers it.
| Layer 4 detection after install | < 1 s | `package_added` → `failsafe_engaged` in logcat |
| Decoy build from clean | 12 s | `canary/decoy-challan/build.sh` |
| Shield build from clean | 17 s | `shield/build.sh` |

**The whole latency is M2 static analysis** — androguard parsing plus the call-graph
walk and bounded decompilation. Everything DRISHTI Shield itself does is under 300 ms.
Say the ten seconds out loud rather than hiding it; it is still an order of magnitude
faster than a human deciding whether to tap.

### What the on-screen counter measures

`detectedAtMs` is stamped in `WatchService.onCandidate`, at the **first inotify event
for the file** — before hashing, before upload. The counter is therefore true
end-to-end latency and not a figure measured from a flattering later point.

---

## 4. What is honest about this demo, and what is not

Say these out loud if asked. They are strengths, not admissions.

| Claim | Status |
|---|---|
| The APK is real malware | **No.** It is `canary/decoy-challan/`, an inert decoy we authored. Every method body is empty or a `Log.i`. `verify_inert.sh` proves it by grep and gates the build. Real samples never come near a laptop — `CLAUDE.md`. |
| The static analysis is real | **Yes.** The real M2 engine, the real `permission_combos.yaml` rules, on the real APK bytes. Seven rules matched. |
| The score is real | **Yes: S = 43, MEDIUM** (measured 2026-08-26), from a real trained classifier at `p_calibrated = 0.864`, γ = 0.60. It is *below* the HIGH floor of 65, so it did not authorise the block — the static evidence did, and the phone says which. Earlier in the day, before the model landed, `S` was 0; the phone's basis card was already telling the truth then too. |
| The LLM contributed to the score | **No.** It returned `B = 0.999` and the scorer excluded it as `partial` — static evidence only, no detonation. |
| The LLM's behaviour flags are right | **No, and that is a finding.** It asserted `reads_sms_content` and `exfiltrates_over_network` for an APK that contains neither SMS nor networking code. It read the manifest surface. See §2.3. |
| The block is real | **Yes.** `dumpsys user` shows the restriction; the OS's own `ActionDisabledByAdminDialog` refuses the install. Verified by a self-test that engages and observes the restriction at setup, not by `dpm list-owners`. |
| The cleared app is a fair control | **Yes, and it is the point.** `canary/benign-sanchay/` declares the *identical* five dual-use permissions as the decoy — `READ_SMS`, `RECEIVE_SMS`, `READ_CONTACTS`, `SYSTEM_ALERT_WINDOW`, `QUERY_ALL_PACKAGES` — and is cleared: `block=false basis=CLEAR`, 4411 ms. Its own `verify_inert.sh` refuses a banking roster or a `<service>` component, so it cannot quietly drift into something that gets blocked. It is authored by us, like the decoy — not a real Play Store app. |
| The icon impersonation detector runs in the demo | **No.** `assess_icon()` has no caller in the pipeline yet. The decoy now carries a raster icon so it can, but nothing in the scripted demo uses it. See §5A. |
| Dynamic analysis ran | **No.** No detonation has been performed. The limitations list on the phone says so, generated by the backend rather than typed by us. |
| DRISHTI files an NCRP complaint | **No,** and the Report screen says so in as many words. |

## 5. Failure modes and fallbacks

Rehearsed. Each has a fallback that keeps the narration going.

| Symptom | Cause | Fallback |
|---|---|---|
| Verdict screen does not appear on its own | Background-activity-start refused | The full-screen notification is already posted — **tap it**. One gesture, same screen. Narrate it as "or the user taps the alert". |
| `demo_up.sh` exits with "device owner could not be provisioned" | Race with Android's setup-complete flag, or an account on the device | Re-run `scripts/demo_up.sh --fresh`. The script already clears `device_provisioned` / `user_setup_complete` and retries 3× before giving up, so a second failure means an account exists. If there is no time: `--allow-no-owner`, and skip §2.4. |
| Verdict takes > 20 s | Backend contention; another job queued | The counter is visible and moving, so it reads as work, not as a hang. Narrate the stage line. Worst case, `scripts/demo_deliver.sh` again. |
| "Could not reach DRISHTI" on the phone | API not on `0.0.0.0`, or died | `curl 127.0.0.1:8080/api/health`, then `scripts/demo_up.sh` (idempotent — it restarts only what is down). |
| Dashboard does not follow the phone | Poll failed | Untick and re-tick **Follow the phone**, or click the job chip in the device feed. |
| Emulator will not boot | Stale lock in the AVD | `scripts/demo_down.sh && scripts/demo_up.sh --fresh`. |
| Setup dies at **"Layer 3 SELF-TEST FAILED"** | The device-owner record exists but the active-admin record does not, so the veto cannot engage | This is the script working. `scripts/demo_up.sh --fresh`. If time is short, `--allow-no-owner` and skip §2.4 — say plainly that the veto is not armed rather than narrating a block that will not happen. |
| Setup warns **"dashboard build FAILED — serving the previous build"** | A TypeScript error in the dashboard source | Not fatal, by design. The phone and all four layers are unaffected. Run the demo; skip §2.5, or show it knowing the screen may lag the source. |
| `demo_run.sh` prints **"still installed after the reset"** | A previous run left a package Layer 4 had uninstall-blocked | `scripts/demo_up.sh` clears it (its §7c lifts the quarantine, then uninstalls). If it persists, `--fresh`. Do not run the pair with the decoy already installed — beat 1's install is a no-op and the closing package list shows the app you just called blocked. |
| Closing package list shows the decoy | Leftover from an earlier run — nothing in this run installed it | The script now says so in as many words, immediately below the list. Read that line aloud; do not let the list imply the block failed. |
| Beat 2b: **"the veto IS in force but the admin dialog did not surface"** | Shield's own verdict screen took focus back | The dumpsys restriction printed directly below is the OS's own record and is the stronger evidence anyway. Narrate that instead. `install_attempt` already polls for 12 s before giving up. |
| `demo_deliver.sh`: **"No verdict line … within 90s"** | Shield was reinstalled or force-stopped mid-scan, killing the pending job | Re-run `scripts/demo_deliver.sh`. Do not rebuild or reinstall Shield while a scan is in flight — that is what caused it in rehearsal. |
| Everything is on fire | — | The evidence is all reproducible from the terminal: `curl -F "apk=@canary/decoy-challan/dist/RTO_Challan.apk" localhost:8080/api/jobs` and show the static report. The phone is the theatre; the analysis is the product. |

### Known flakiness, ranked

0. **The LLM endpoint is a free tier and returns 502 under load** (2 of 5 probe calls
   during setup). **Warm the cache in setup** — `DRISHTI_LLM_CACHE_ENABLED` is on, so
   a rehearsal delivery of the same APK makes the real run a cache hit, which is both
   safer and faster. Do a throwaway `scripts/demo_deliver.sh --instant --no-notify`
   before the audience arrives. If the endpoint is failing anyway, set
   `DRISHTI_LLM_PROVIDER=mock` in `.env` and restart the API: the demo's block
   decision does not depend on the LLM, because the score is already zero without it.
1. **Backend latency variance.** Measured 4.4–5.7 s across 8 runs on 2026-08-26 —
   tighter than the earlier 7.9–13.1 s, which included the wait for the score.
   Cause of the remaining spread: M2 static timing varies with machine load.
   Mitigation: close everything else on the laptop; **do not run a Gradle build, and
   do not let another agent rebuild Shield, during the demo.** A reinstall mid-scan
   kills the pending job and `demo_deliver.sh` reports "no verdict line" after 90 s —
   that happened once in rehearsal and it is the only thing that broke a good run.
2. **Background activity start.** Depends on the `SYSTEM_ALERT_WINDOW` app op that
   `demo_up.sh` grants. If the OS declines it anyway, the notification fallback is
   one tap and is always posted alongside.
3. **inotify on emulated storage.** FUSE-backed shared storage occasionally drops
   events, which is why `WatchService` runs a 250 ms directory sweep alongside the
   `FileObserver`. Either detector alone would be a coin flip on stage; whichever
   sees the file first wins.
4. **Device owner provisioning** was the flakiest thing in this demo until the cause
   was found: `dpm set-device-owner` over adb is refused once Android marks the user
   set up, and after `-wipe-data` that flag flips a few seconds into the first boot —
   so success depended purely on whether the script got there first. Two consecutive
   rehearsals differing only in timing produced "provisioned" and "NOT HELD".
   `demo_up.sh` now clears `global device_provisioned` and `secure
   user_setup_complete`, provisions, retries 3×, restores the flags, and **dies** if
   it still failed. Check the banner at setup anyway.
5. **The veto silently un-arming itself on every rerun** — the worst bug found in
   rehearsal, because setup reported success the whole time. `adb install -r` drops
   the active-admin record while the device-owner record survives; `dpm list-owners`
   cannot see the difference. Fixed by `dpm set-active-admin` on every run plus the
   §7b self-test that actually engages and observes the restriction. **Trust the
   self-test line, not the "HELD" line.**
6. **`adb logcat -d -t N` loses Shield's lines on a cold boot.** The boot flood pushes
   them past the tail window — measured on a freshly booted emulator: **0** Shield
   lines via `-t 400`, all of them via `-s DrishtiShield:I`. Every logcat read in the
   demo scripts filters by tag now. Worth knowing because the verdict *latency* is
   read from that line: the symptom was a demo that worked perfectly and reported
   "no verdict line".
7. **`am start --ez <extra>` can silently drop the extra**, in two different ways: to
   a stale top-most instance left over from `install -r`, and to a task "brought to
   the front" after a force-stop, which re-runs `onCreate` with the task's *original*
   intent. The demo reset was quietly doing nothing for a while. All such calls now
   pass `-f 0x10008000` (`NEW_TASK|CLEAR_TASK`).
8. **Two agents, one emulator.** During this rehearsal another workstream was
   installing and reinstalling Shield on the same AVD. That is what produced the one
   failed run and a stale decoy in the package list. Before a real take, confirm
   nobody else is driving `emulator-5554`.

## 5A. The decoy's icon, and what may be said about it

The decoy now ships a raster launcher icon at
`canary/decoy-challan/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png` — a navy field,
a red block, a white rupee. It is drawn deterministically by
`canary/decoy-challan/tools/make_launcher_icon.py` and it is a **lookalike**: the
colour and shape grammar of an Indian bank or wallet app, with no real institution's
mark, wordmark or trade dress anywhere in it.

**Why it had to exist.** `drishti/m4_genai/vision.py` pulls the launcher icon out of
the APK zip to perceptual-hash it and to show it to a vision model. It looks for a
PNG or WebP under `res/`. The decoy's only icon was a *vector drawable*, which
compiles to XML — so `_extract_icon()` returned `None` and the impersonation layer
reported "no match" for the one sample it exists to catch. It now returns a 192×192
image.

**What may be said on stage, and what may not.**

| | |
|---|---|
| ✅ Say | "The decoy wears a bank's face, and the icon is an artefact we can hash and show a model — independent of the code, and it survives obfuscation." |
| ⚠️ Say only with the number in front of you | A specific brand and confidence. |
| ❌ Never say | A fixed figure like "0.92" from memory. |

**Measured 2026-08-26, and the reason for that warning.** Three candidate designs, five
calls each to the configured VLM (`minimax/minimax-m3:free`):

| Design | Results across 5 calls |
|---|---|
| navy + red corner flash + seal ring | SBI 0.65, Paytm 0.70, SBI 0.60, 2 endpoint failures |
| bright blue + seal ring | Paytm 0.75, 3 endpoint failures |
| **navy + red block + rupee** (shipped) | **Paytm 0.92, Paytm 0.90, Paytm 0.60, Paytm 0.55, 1 endpoint failure** |

Two honest facts follow, and both belong in the answer if a judge asks:

1. **The confidence is not stable.** 0.55 to 0.92 on *identical pixels*. The threshold
   in `vision.py` is 0.80, so the same icon crosses it on one call and not the next.
   Quote the number on the screen in front of you or do not quote one.
2. **The free endpoint failed roughly 1 call in 4** during this measurement, matching
   the ~2-in-5 seen elsewhere. Assume it may not answer.

**And the load-bearing caveat: `assess_icon()` has no caller in the pipeline.** It is
exercised only by `tests/unit/test_vision.py`. Wiring it into the job flow is
`drishti/m4_genai/`'s owner's call, not this workstream's. Until that lands, **the
icon-impersonation line is not part of the scripted demo** — the PNG is in place so
the layer has something to read the moment it is wired. Do not put it on a slide as a
shipped feature.

## 6. Teardown

```bash
scripts/demo_down.sh
```

Stops the emulator, the dashboard and the API, then prints anything still listening
on the demo ports. Nothing in this demo touches GCP, so there is no cloud resource to
leave running — but run it anyway, because a forgotten emulator will eat the battery
before the next session.

## 7. Reproducing the numbers in §3

```bash
# Cold start, timed. Tear down first or the number is meaningless.
scripts/demo_down.sh
t0=$(date +%s%3N); scripts/demo_up.sh; t1=$(date +%s%3N); echo "cold start: $((t1-t0)) ms"

# Both verdict latencies, from Shield's own log, in one command.
t0=$(date +%s%3N); scripts/demo_run.sh --fast; t1=$(date +%s%3N); echo "sequence: $((t1-t0)) ms"

# Or one beat at a time.
scripts/demo_deliver.sh --benign --instant --no-notify   # prints the cleared elapsed_ms
scripts/demo_deliver.sh --instant --no-notify            # prints the blocked elapsed_ms

curl -s localhost:8080/api/jobs | python3 -m json.tool | less   # per-stage durations

# The veto, proved rather than asserted.
adb shell dumpsys user | grep -A3 'Device policy restrictions'
adb shell dumpsys activity activities | grep -m1 topResumedActivity
adb logcat -d -s DrishtiShield:I | grep veto_selftest
```

**Use `-s DrishtiShield:I`, never `-t N`,** for any logcat read — see §5 item 6.
`-t 400` returns zero Shield lines on a freshly booted emulator.
