# decoy-challan — an inert detection target shaped like challan fraud

**This application is inert. It has no payload. It cannot do anything.**

If you found this directory while auditing the repository and want the short version:
every implementation body in `app/src/main/java/` is either an empty method or a
single `Log.i` call, and `verify_inert.sh` proves it by grep before anything builds.

---

## Why it exists

DRISHTI is a malware *triage* system. To demonstrate that the static engine detects
the Indian traffic-challan fraud family, something has to be analysed. The three
options were:

1. **Use a real sample.** Forbidden. `CLAUDE.md` restricts every real APK to GCS and
   to the sealed GCE detonator; one is never allowed onto a laptop or a demo
   emulator, and the live demo runs on a laptop.
2. **Fake the verdict.** Forbidden, and worse — the honesty requirements exist
   precisely to stop a number appearing on screen that no measurement produced.
3. **Author a target whose *declared surface* is realistic and whose *behaviour* is
   nothing.** That is this directory.

The insight the decoy demonstrates is real and is the point of M2: **the manifest is
where an Android app makes its capabilities legible, and a permission
*combination* is a signal that a single permission is not.** `RECEIVE_SMS` alone is a
messaging app. `RECEIVE_SMS + READ_SMS`, an accessibility-bound service,
`SYSTEM_ALERT_WINDOW + INTERNET` with a service, and `REQUEST_INSTALL_PACKAGES`
together are an OTP interceptor with an overlay and a dropper stage. The decoy
declares that combination. It implements none of it.

## What the real analysis produces for it

Measured on 2026-08-26 by running the decoy through the real M2 engine via
`POST /api/jobs` (job `job_3bf924a506e3`), not asserted here from a design document:

| Rule | Severity | MITRE |
|---|---|---|
| `OTP_THEFT_SURFACE` | high | T1582 |
| `OVERLAY_CREDENTIAL_THEFT` | high | T1056 |
| `ACCESSIBILITY_ABUSE` | **critical** | T1417 |
| `DROPPER_CAPABILITY` | high | T1407 |
| `PERSISTENT_BOOT` | medium | T1547 |
| `CLIPBOARD_MONITOR` | medium | T1414 |
| `SCREEN_CAPTURE` | high | T1513 |

M2 also extracted both embedded endpoint constants (defanged to `hxxp://` by the
engine), the `AES/CBC/PKCS5Padding` transform string, two exported unprotected
components, and derived the `accessibility_abuse` and `overlay_attack` hypotheses.

**The composite score `S` for this sample is 0**, and that is correct rather than
broken. `m6_score/engine.py` refuses to let an unavailable ML model or a mock LLM
contribute to `S`; with no trained model and no LLM key present in this build,
`F_AI` has no inputs. The Shield app therefore blocks on the M2 evidence above and
says so on screen, naming the basis. See `docs/DEMO_SCRIPT.md`.

## What is inside, line by line

| Component | Declared in the manifest as | What the code does |
|---|---|---|
| `SmsDeliveryReceiver` | `SMS_RECEIVED`, priority 2147483647, exported | one `Log.i`. Never touches `intent.extras`, `pdus`, the address, the body, or `abortBroadcast()` |
| `ChallanAccessibilityService` | bound to `BIND_ACCESSIBILITY_SERVICE`, `canRetrieveWindowContent` | `onAccessibilityEvent` is an **empty method**. Never reads the event, walks the node tree, or calls `performGlobalAction` |
| `OverlayService` | a service, with `SYSTEM_ALERT_WINDOW` declared | one `Log.i`, then `stopSelf()`. Never obtains a `WindowManager` |
| `BootReceiver` | `BOOT_COMPLETED` | one `Log.i`. Starts nothing |
| `ChallanActivity` | launcher | renders a white screen saying this is a DRISHTI test decoy |
| `Surface` | — | `const` strings only. Never passed to anything |

### The "C2" endpoints are unroutable by construction

```kotlin
const val C2_PRIMARY  = "http://192.0.2.87:8443/rto/v3/collect"
const val C2_FALLBACK = "https://challan-verify.invalid/api/sync"
```

`192.0.2.0/24` is **TEST-NET-1**, reserved by RFC 5737 for documentation and
guaranteed never to be routed on the public internet. `.invalid` is reserved by
RFC 2606 and can never resolve. They were chosen so that even a coding mistake could
not produce a real connection — and there is no networking code here to make one.
`verify_inert.sh` fails the build if either constant is changed away from those
reserved ranges.

## The inertness gate

```bash
./canary/decoy-challan/verify_inert.sh
```

It strips comments (this file's own prose names the forbidden APIs in order to deny
them — the first run flagged four of its own sentences) and then greps the remaining
code for every API that would grant a real capability: networking, SMS, overlay,
accessibility traversal, dynamic code loading, `PackageInstaller`, content
resolution, crypto, and reflection. Any hit fails.

`build.sh` runs it before Gradle, and `scripts/demo_up.sh` runs it on every
invocation — not only on a cache miss, so a stale `dist/` artefact can never smuggle
a modified decoy onto the emulator.

## Boundaries this directory must keep

Taken directly from `CLAUDE.md`. If a task asks for any of these, stop:

- No SMS reading or forwarding code, ever — not even "just to log the sender"
- No overlay capture, no `WindowManager.addView`
- No credential harvesting, no accessibility node traversal
- No packing, no obfuscation, no minification (`isMinifyEnabled = false`, deliberately)
- No real network call, and no routable host in any constant
- The APK is **not committed**. `.gitignore` blocks `*.apk` repo-wide and allowlists
  only `canary/dist/*.apk` — this directory's `dist/` is not on that allowlist, by
  choice. `build.sh` regenerates it in about twelve seconds.

## Building

```bash
./canary/decoy-challan/build.sh     # verify_inert.sh, then gradle assembleDebug
```

Compile only. Like `canary/build.sh`, this script contains no `adb`, emulator,
install, or launch command. Putting it on the demo emulator is
`scripts/demo_up.sh`'s job, so "did we build it" and "did we put it on a device"
stay separate questions with separate answers.
