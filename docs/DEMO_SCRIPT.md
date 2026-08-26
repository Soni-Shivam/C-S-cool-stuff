# DEMO_SCRIPT — the live interception demo

**What the audience sees:** a phone receives a WhatsApp-style forward of
`RTO_Challan.apk`. Before anyone touches it, a full-screen verdict appears on the
phone naming the evidence. The install is then attempted and the *operating system*
refuses it. The dashboard fills in on its own, with nobody touching the browser.

**Total runtime:** 4 minutes. Setup from cold: 35 seconds. Verdict on screen: ~5 seconds.

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
  Layer 3      device owner HELD
```

If provisioning fails the script exits non-zero and tells you what to do. To run
deliberately without the veto — Layers 1, 2 and 4 still work and the verdict screen
still names its evidence — pass `--allow-no-owner` and skip §2.4.

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

**Verifiable on the spot** if a judge asks:
```bash
adb shell dumpsys user | grep -A6 'Device policy restrictions'
#   Device policy restrictions:
#     no_install_unknown_sources
```

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

## 3. Measured timings

Measured 2026-08-26 on the demo laptop (16 cores, 23 GB RAM, KVM, Android 34
`google_apis` x86_64 AVD, 4 vCPU / 3 GB).

| Thing | Measured | How |
|---|---|---|
| `demo_up.sh --fresh` cold to ready | **35 s** | wall clock around the script |
| Emulator boot (wiped AVD) | 24–35 s | `Boot completed in …` in the emulator log |
| **File landing → verdict on screen** | **5.0 / 5.4 / 8.9 s** (3 runs) | `elapsed_ms` in Shield's own logcat line, measured from the first inotify event |
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
| The block is real | **Yes.** `dumpsys user` shows the restriction; the OS's own `ActionDisabledByAdminDialog` refuses the install. |
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
| Everything is on fire | — | The evidence is all reproducible from the terminal: `curl -F "apk=@canary/decoy-challan/dist/RTO_Challan.apk" localhost:8080/api/jobs` and show the static report. The phone is the theatre; the analysis is the product. |

### Known flakiness, ranked

0. **The LLM endpoint is a free tier and returns 502 under load** (2 of 5 probe calls
   during setup). **Warm the cache in setup** — `DRISHTI_LLM_CACHE_ENABLED` is on, so
   a rehearsal delivery of the same APK makes the real run a cache hit, which is both
   safer and faster. Do a throwaway `scripts/demo_deliver.sh --instant --no-notify`
   before the audience arrives. If the endpoint is failing anyway, set
   `DRISHTI_LLM_PROVIDER=mock` in `.env` and restart the API: the demo's block
   decision does not depend on the LLM, because the score is already zero without it.
1. **Backend latency variance (7.9–13.1 s).** The single biggest source of on-stage
   uncertainty. Cause: M2 static timing varies with machine load. Mitigation: close
   everything else on the laptop; do not run a Gradle build during the demo.
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
scripts/demo_up.sh --fresh                       # setup time
adb logcat -c
scripts/demo_deliver.sh --instant --no-notify    # prints the measured elapsed_ms
curl -s localhost:8080/api/jobs | python3 -m json.tool | less   # per-stage durations
adb shell dumpsys user | grep -A6 'Device policy restrictions'  # the veto, in force
```
