# shield — DRISHTI Shield, the on-device guard app

**This app defends a device. It contains no offensive capability.**

It watches the Download folder, hashes arriving APKs, asks the DRISHTI backend for a
verdict, and — as device owner — makes the operating system refuse a bad install.
There is no code in it that reads SMS, draws a capture overlay, harvests credentials,
or loads code at runtime.

Full stage instructions: `docs/DEMO_SCRIPT.md`. Bring it up: `scripts/demo_up.sh`.

## The four layers

| Layer | Where | What it does | Armed by |
|---|---|---|---|
| **1 — pre-install watcher** | `WatchService.kt` | `FileObserver` + a 250 ms sweep on `/sdcard/Download`. Hashes, uploads, and puts a verdict on screen **before anything is tapped** | `MANAGE_EXTERNAL_STORAGE` app op |
| **2 — tap-time intercept** | `ui/TapInterceptActivity.kt` | intent filter on `application/vnd.android.package-archive`, so tapping an APK can route here instead of the package installer | install time |
| **3 — the veto** | `PolicyEngine.kt` | `DevicePolicyManager.addUserRestriction(DISALLOW_INSTALL_UNKNOWN_SOURCES)`. The OS refuses; there is no dialog to dismiss | `adb shell dpm set-device-owner` |
| **4 — post-install failsafe** | `PackageAddedReceiver.kt` | hashes every newly installed package's own APK and matches it against recorded verdicts. A rename does not evade it | registered at runtime by the watcher |

## Two things worth knowing before you change anything

**Layer 4's receiver must be registered at runtime.** `ACTION_PACKAGE_ADDED` is not on
API 26's implicit-broadcast exemption list, so the manifest declaration alone is
silently never invoked — the install succeeds, Layer 4 logs nothing at all, and it
looks like a hashing bug rather than a delivery one. `WatchService.startPackageWatcher`
is what actually arms it.

**Layer 1 must not trust file size.** Emulated shared storage is FUSE-backed and the
reported size reaches its final value before the tail is readable. The first version
of `ScanEngine.settle` waited for size stability and produced a wrong sha256 on the
very first run — the verdict was computed over bytes that were not the file. The
decisive test is now the ZIP End Of Central Directory record, which cannot be written
before the rest of the archive exists, plus a double-read hash check.

## The block decision is not the score, and it does not wait for it

`BlockDecision` (`Verdict.kt`) names its own basis and the UI prints it. Two reasons,
both load-bearing.

**Correctness.** `m6_score/engine.py` refuses to let an unavailable ML model or a
*partial* GenAI verdict contribute to `S`. Measured 2026-08-26 on the decoy: `S` was 0
before a trained model existed, and 43 (MEDIUM) after one landed — both below the
HIGH floor of 65. A guard app blocking on `S >= 65` would not have blocked either
time, and one that invented a number would be lying. So the block runs on M2 static
evidence and says so on screen. If `S` later clears the floor, the basis becomes
`COMPOSITE_SCORE` with no other code change.

**Latency.** The static report is what the decision needs; `S` sits behind the GenAI
stage. A cold free-tier LLM call measured **35 s** against 5 s for static, so
`ScanEngine.analyse` decides and engages the veto on static, freezes `verdictAtMs`
there, and attaches the score when it arrives. Worst-case time-to-verdict went from
41.4 s to 8.9 s. A score can raise the verdict; it never lowers it.

Keep the on-screen text to what it can verify. An earlier version of the basis card
asserted *why* the score was low — "the ML and GenAI layers are not admitted" — and
that sentence stopped being true the moment a model landed, while it stayed on
screen. It now states the score, the floor, and points at the factor breakdown.

## The Report screen files nothing

`ReportActivity` calls `GET /api/jobs/{id}/artifacts/dossier` and renders the
backend's own fields — including `submission_is_manual`, which is always true. NCRP
has no public submission API, so nothing here files a complaint, and the button is
labelled "Prepare a report for cybercrime.gov.in" rather than anything that implies
filing. `reportable` is false for LOW and MEDIUM bands; that is shown with the
backend's reason rather than hidden, because a triage tool that encourages complaints
it cannot support degrades the portal for everyone.

The complaint body is **not** composed on the phone when the backend is reachable.
Two generators would drift, and the one a victim pastes into a government form is the
wrong one to let drift. There is an on-device fallback for when the endpoint is
unavailable, and the screen says so.

## Dependencies

None beyond the Android framework. Views are built in Kotlin, HTTP is
`HttpURLConnection`, JSON is `org.json`. One less resolution step to fail at hour 71,
and the APK stays small.

## Building

```bash
./shield/build.sh          # compile only — no adb, no install, no launch
```

The APK is **not committed**: `.gitignore` blocks `*.apk` repo-wide and allowlists
only `canary/dist/*.apk`. `scripts/demo_up.sh` builds it if `shield/dist/` is empty.
