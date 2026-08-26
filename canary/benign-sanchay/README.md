# Sanchay Expenses — the demo's negative control

**This application is inert.** Every method body is a `Log.i` call or renders a
hardcoded array. `verify_inert.sh` proves it by grep and gates the build.

## Why it exists

The first question any judge asks a malware detector is *"does it just flag
everything?"*. Showing only a blocked sample cannot answer that. This is the app that
does.

It is deliberately **not** a trivially clean app. A calculator with zero permissions
would prove nothing — nobody doubts that a detector can pass a calculator. This one is
*privileged*, and privileged in exactly the ways the fraud family is:

| Permission | Sanchay | RTO Challan decoy | Truecaller |
|---|:--:|:--:|:--:|
| `READ_SMS` | ✅ | ✅ | ✅ |
| `RECEIVE_SMS` | ✅ | ✅ | ✅ |
| `READ_CONTACTS` | ✅ | ✅ | ✅ |
| `SYSTEM_ALERT_WINDOW` | ✅ | ✅ | ✅ |
| `QUERY_ALL_PACKAGES` | ✅ | ✅ | ✅ |

Five dual-use permissions, held by all three. `m2_static/lookalike.py` reports that
intersection as `shared_permissions`, and it is identical for this app and the decoy.

**So the permission set is not the finding, and the demo says so out loud.**

## What actually separates them

Measured on 2026-08-26 by submitting both APKs to the running API:

| | Sanchay Expenses | RTO Challan decoy |
|---|---|---|
| permission-combination rules matched | **1** (`OTP_THEFT_SURFACE`, high) | **5**, one of them critical |
| `lookalike.trojan_score` | **0.0625** | **0.25** |
| banking/UPI package roster in the string pool | none | `com.phonepe.app`, `com.sbi.lotusintouch`, `net.one97.paytm` |
| accessibility service declared | no | yes (`ACCESSIBILITY_ABUSE`, critical, T1417) |
| `REQUEST_INSTALL_PACKAGES` | no | yes (`DROPPER_CAPABILITY`, T1407) |
| composite score `S` | **28 — LOW** | **43 — MEDIUM** |
| Shield's block decision | `CLEAR` — install proceeds | `STATIC_EVIDENCE` — Layer 3 veto |

The block policy in `shield/.../Verdict.kt` is *one critical, or two or more highs*.
One high is below it, on purpose: `OTP_THEFT_SURFACE` fires on both apps and blocks
neither on its own.

## What it deliberately does not have

Four things, each of which would push it over the threshold or into the trojan shape.
`verify_inert.sh` enforces the first two mechanically, because "we remembered not to"
is not a control:

1. **No banking or UPI package identifiers** anywhere in the source. The grep is in
   the gate. A roster is the single strongest lookalike discriminator (weight 0.30),
   and if one ever appeared here the negative control would quietly stop being one.
2. **No `<service>` component.** `OVERLAY_CREDENTIAL_THEFT`, `CLIPBOARD_MONITOR` and
   `SCREEN_CAPTURE` all require `plus_component_type: service`, and this app holds
   `SYSTEM_ALERT_WINDOW` and `INTERNET`. A single service declaration would take it
   from one high to three and it would be blocked.
3. **No `REQUEST_INSTALL_PACKAGES`** and no accessibility service.
4. **No OTP or credential lexicon** in its strings. It carries spending categories,
   because that is what an expense tracker carries.

## Honesty

- It is **not** a real app off F-Droid. We wrote it, and the demo script says so.
  What is real is the analysis: the same M2 engine, the same rule file, over the real
  APK bytes.
- `lookalike` returns `indeterminate`, **never** `benign`. The signer is unknown and
  absence of evidence is not evidence of innocence. `LEGITIMATE_PRIVILEGED` is
  reserved for a signer on the trusted-publisher list and is a statement about the
  signer, not a clean bill of health for the code.
- Its own screen carries a disclosure panel naming it as a DRISHTI control sample,
  because unlike the decoy this app really is installed on the demo device and
  somebody may open it.

## Build

```bash
bash canary/benign-sanchay/build.sh     # 14 s from clean; gated by verify_inert.sh
```

Compile only. No adb, no emulator, no install — `scripts/demo_up.sh` stages it and
`scripts/demo_run.sh` delivers it.
