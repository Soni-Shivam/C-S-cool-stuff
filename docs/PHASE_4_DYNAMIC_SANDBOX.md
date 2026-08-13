# PHASE 4 — M3 DYNAMIC SANDBOX

**Window:** H24 → H48 · **Owner:** Track C (Vedant), Track A assists on normalisation
**Depends on:** P0 T0.7 (`TraceSource`), T0.9 (emulator groundwork), P1 T1.6 (hypotheses)
**Exit criteria:** `LiveSandboxSource.run(apk, plan)` returns a schema-valid
`DynamicTrace` with real API events, real network flows, and populated
`evasion_observations` — or Replay Mode is engaged with a real captured trace.

> **This is the highest-risk phase in the project.** Read the Tripwire section
> before you write any code, and set a literal alarm for H40. The failure pattern
> is not "we couldn't do it" — it's "we spent 14 hours almost doing it and had
> nothing else to show." The tripwire exists to make that impossible.

---

## Safety controls — implement before running a single real sample

Non-negotiable, and each one is also a slide:

1. **Dedicated analysis machine.** Not anyone's daily laptop. Not a machine with
   SSH keys, cloud credentials, or the team's git tokens on it.
2. **No host route.** Emulator networking goes to mitmproxy on the analysis host
   only. Verify with `adb shell ping -c1 8.8.8.8` → must fail. Verify the host
   firewall drops emulator-originated traffic to the LAN.
3. **No shared folders, no ADB port-forward inbound, no clipboard sharing.**
4. **Snapshot restore between every sample.** `adb emu snapshot load clean_base`.
   Also the crash-recovery mechanism (see T4.5).
5. **Real samples never leave `data/samples/`,** which is gitignored, and are
   stored password-protected-zipped at rest (`infected` convention) so nobody
   double-clicks one.
6. **The C2 stays dead.** We never contact real attacker infrastructure. Outbound
   is sinked; responses are synthesised locally. This is both a safety property and
   the technical premise of Phase 5 — mention that they're the same design choice.
7. **Synthetic victim data only.** Fake names, fake numbers, fake accounts,
   confined to the VM. `data/kb/synthetic_identities.yaml`, obviously fictional.

Screenshot the isolation verification. It goes on the responsible-use slide.

---

## T4.1 — Emulator control (H24 → H27)

`m3_dynamic/emulator.py`:

```python
class Emulator:
    def boot(self, avd: str, *, writable_system=True, proxy: str) -> None
    def wait_ready(self, timeout=180) -> bool     # poll sys.boot_completed
    def snapshot_save(self, name) -> None
    def snapshot_load(self, name) -> None         # <8s, the reset primitive
    def install(self, apk: Path) -> InstallResult # handle split installs
    def launch(self, package: str, activity: str | None = None) -> int  # pid
    def stimulate(self, stimulus: str) -> None    # see stimulus table
    def screenshot(self, dest: Path) -> Path
    def logcat_since(self, t0) -> list[str]
    def uninstall(self, package) -> None
    def healthy(self) -> bool                     # adb responsive + frida alive
```

**Install gotchas that will cost you an hour each if unanticipated:**
- Split APKs need `adb install-multiple base.apk split_*.apk`.
- `INSTALL_FAILED_NO_MATCHING_ABIS` → the sample is ARM-only and your image is
  x86_64. Options: use an `arm64-v8a` system image (slow, emulated, but Android 11+
  x86_64 images have ARM translation), or keep an ARM AVD as a second target.
  **Test your demo sample's ABI at H24, not H50.**
- `INSTALL_FAILED_DEPRECATED_SDK_VERSION` on API 33+ for very old samples → keep
  the API 30 AVD as primary.
- Some samples refuse to install if `minSdk` > image. Check before you debug blind.

**Stimulus table** (`stimulate()`), each an `adb` one-liner:

| Stimulus | Command | Triggers |
|---|---|---|
| `boot_complete` | `am broadcast -a android.intent.action.BOOT_COMPLETED` | boot receivers |
| `sms_received` | `emu sms send +919876543210 "OTP 483920 for txn"` | SMS receivers ← key one |
| `screen_on/off` | `input keyevent 26` | screen-state logic |
| `network_change` | `svc wifi disable/enable` | connectivity receivers |
| `clock_advance` | `date -s` in shell + `am broadcast TIME_SET` | time bombs |
| `app_foreground` | `am start -n pkg/.Activity` | overlay triggers |
| `home_press` | `input keyevent 3` | overlay-on-background |
| `battery_change` | `dumpsys battery set level 15` | some evasion checks |
| `call_incoming` | `emu gsm call +91...` | call-based triggers |
| `ui_random_walk` | `monkey -p pkg 200` | generic coverage |

Run stimuli on a schedule during the run window: t=5s launch, t=15s
`ui_random_walk`, t=30s `sms_received`, t=45s `home_press`, t=60s `boot_complete`,
t=75s `network_change`, t=90s second `sms_received`, t=105s screenshot.

Write the schedule as data (`stimulus_schedule.yaml`), not code, so Phase 5's morph
plans can extend it.

---

## T4.2 — Frida runner (H27 → H31)

```python
class FridaRunner:
    def attach_spawned(self, package: str, scripts: list[str],
                       on_message: Callable) -> Session
```

**Spawn-gated, not attach-after-launch.** Use `device.spawn()` +
`session.create_script()` + `device.resume()`. Attaching after launch misses
everything that happens in `<clinit>` and `attachBaseContext` — which is exactly
where packers unpack and where droppers do their work. Getting this wrong makes
your sandbox blind to the most interesting 200ms of the sample's life.

**Frida Gadget vs. frida-server:** the paper specifies Gadget (injected into the
APK, no daemon to detect). Gadget requires repackaging + re-signing the APK, which
changes the sha256 and breaks evidence provenance — so: **frida-server for the
primary path** (fast, no repackaging), with `frida-server` renamed to a non-obvious
binary name and run on a non-default port to defeat the naive detection checks.
Note the tradeoff honestly on the slide rather than claiming Gadget you didn't ship.

### Hook scripts — `m3_dynamic/scripts/*.js`

**All hooks are observational. They read arguments and return values and report
them. They do not modify app behaviour.** (Phase 5's morph hooks *do* modify
return values — that's a separate, clearly-marked file set with a different safety
rationale: we are lying to the malware about the environment, not adding capability
to it.)

| Script | Hooks | Yields |
|---|---|---|
| `sms.js` | `SmsMessage.getMessageBody/getOriginatingAddress`, `SmsManager.sendTextMessage`, dynamic `registerReceiver` with SMS action | OTP interception evidence |
| `net.js` | `URL.openConnection`, `OkHttpClient.newCall`, `Socket.connect`, `HttpURLConnection.getOutputStream` | C2 endpoints even without TLS intercept |
| `crypto.js` | `Cipher.doFinal`, `Cipher.getInstance`, `SecretKeySpec.$init` | **plaintext before encryption** — defeats custom crypto (T1521) |
| `dexload.js` | `DexClassLoader.$init`, `InMemoryDexClassLoader`, `PathClassLoader`, `System.load/loadLibrary` | second-stage payloads; dump the dex to disk |
| `reflect.js` | `Method.invoke`, `Class.forName` | reflection edges the static graph missed |
| `pm.js` | `PackageManager.getPackageInfo/getInstalledPackages/resolveActivity` | **evasion probes → Phase 5 morph input** |
| `a11y.js` | `AccessibilityService.onAccessibilityEvent`, `performGlobalAction` | automation abuse |
| `overlay.js` | `WindowManager.addView`, `TYPE_APPLICATION_OVERLAY` usage | overlay attack |
| `fs.js` | `FileOutputStream.$init`, `File.delete` | dropped payloads |
| `clipboard.js` | `ClipboardManager.getPrimaryClip/addPrimaryClipChangedListener` | address swap |
| `device.js` | `TelephonyManager.getSimCountryIso/getDeviceId/getSubscriberId`, `Build` field reads | fingerprinting → morph input |
| `ssl_unpin.js` | `TrustManagerImpl.verifyChain`, `X509TrustManager`, OkHttp `CertificatePinner` | enables TLS intercept |

Write one **generic hook factory** so adding a hook is one config line, not one
file:
```js
function hookMethod(cls, method, tag, argFormatter) { ... send({tag, args, ret, t, stack}) ... }
```
Then `hooks.json` lists ~60 hooks declaratively. This is the difference between 12
scripts you maintain by hand and a hook set you can extend from a hypothesis at
runtime — which Phase 5 needs.

**Dynamic hook selection from hypotheses:** `SandboxPlan.hooks` includes specific
method signatures from `Hypothesis.target_methods`. The runner generates a hook for
each at runtime via the factory. **This is the closed loop from the paper made
real**: static analysis decided what to watch, and the sandbox watches exactly that.
Make sure the demo log says so out loud: `[M3] hooking c.a.d.h() per hypothesis
hyp_0193 (secondary_payload)`.

---

## T4.3 — Crash recovery & bounded self-repair (H31 → H33)

The paper promises snapshot recovery plus LLM-driven Frida self-repair. Implement
it — it's genuinely good engineering and it's ~90 lines.

```python
def run_with_recovery(plan, max_retries=3):
    emulator.snapshot_save("pre_detonation")
    for attempt in range(max_retries + 1):
        try:
            return _run_once(plan)
        except (FridaProcessCrashed, ScriptError) as e:
            tombstone = emulator.pull_tombstone() or logcat_tail(200)
            emulator.snapshot_load("pre_detonation")
            if attempt == max_retries:
                log.warn("falling back to network-only observation")
                return _run_network_only(plan)
            plan = llm_repair_script(plan, error=e, tombstone=tombstone)  # ≤3 calls
```

`llm_repair_script` gets the failing script, the exception, and the tombstone, and
returns a corrected script. Cap at 3. **Log every attempt to the ledger** as
`ERROR` nodes — the recovery story is visible in the evidence trail, which is a nice
touch when someone asks "what happens when it breaks?"

Real crash causes you'll hit: hooking a method that doesn't exist in this sample's
class hierarchy (guard with `Java.available` + try/catch per hook), overload
ambiguity (`.overload('java.lang.String')` needed), and hooking in a process before
the class is loaded (use `Java.perform` + classloader enumeration).

---

## T4.4 — TLS interception & network capture (H33 → H36)

1. **mitmproxy** in `--mode regular` on `:8081`, emulator launched with
   `-http-proxy 10.0.2.2:8081`.
2. **CA into the system store** (needs `-writable-system`):
   ```
   hashed=$(openssl x509 -inform PEM -subject_hash_old -in mitm.pem | head -1)
   adb push mitm.pem /system/etc/security/cacerts/$hashed.0
   adb shell chmod 644 ... && adb reboot   # then re-snapshot
   ```
   Do this **once**, then `snapshot save clean_base`. Redoing it per run wastes
   4 minutes each time.
3. **Frida SSL unpinning** for apps with their own pinning (`ssl_unpin.js`).
4. **Custom-crypto bypass**: for samples that encrypt the *payload* before sending,
   TLS interception shows ciphertext. `crypto.js`'s `Cipher.doFinal` hook captures
   the plaintext buffer from memory. This directly neutralises T1521 and it's a
   strong technical beat in the demo — show the encrypted POST body beside the
   plaintext capture.

**mitmproxy addon** (`m3_dynamic/proxy/capture_addon.py`):
```python
class DrishtiCapture:
    def request(self, flow):  # record, assign flow_id
    def response(self, flow): # record
```
Communicates with the runner via a JSONL file (simplest reliable IPC — no sockets
to debug at 4am). Phase 5 adds a `GenerativeC2` addon to the same chain.

---

## T4.5 — Evasion observation detection (H36 → H39) · **the bridge to Phase 5**

This is the part of Phase 4 that makes Phase 4 worth doing. Everything else is
plumbing; this is the sensor that makes the frontier possible.

**Detect the probe→miss→stall pattern:**

```python
def detect_evasion(api_events, process_activity) -> list[EvasionObservation]:
    """
    A probe is an API call in the PROBE_APIS set.
    A MISS is a probe whose return value is null/empty/false.
    A STALL is: after the miss, the process makes no further hooked calls for
    >STALL_MS (default 1500ms), or calls only sleep/timer/idle APIs, or exits.
    probe + miss + stall ⇒ EvasionObservation(followed_by_stall=True)
    """

PROBE_APIS = {
  "installed_package": ["PackageManager.getPackageInfo",
                        "PackageManager.getInstalledPackages",
                        "PackageManager.resolveActivity",
                        "PackageManager.getLaunchIntentForPackage"],
  "sms_history":  ["ContentResolver.query(content://sms)"],
  "contacts":     ["ContentResolver.query(content://contacts)"],
  "accounts":     ["AccountManager.getAccounts"],
  "sim_country":  ["TelephonyManager.getSimCountryIso",
                   "TelephonyManager.getNetworkOperator"],
  "build_prop":   ["Build.MODEL","Build.FINGERPRINT","Build.PRODUCT",
                   "SystemProperties.get"],
  "emulator_hint":["Build.HARDWARE(goldfish|ranchu)","/proc/cpuinfo read",
                   "SensorManager.getSensorList"],
  "c2_reach":     ["<network flow with connection error or non-200>"],
  "files":        ["File.exists on /sys/qemu*, /dev/socket/qemud"],
}
```

Emit one `EVASION_CHECK` ledger node per observation, with `inferred_requirement`
filled in by a simple lookup (probe kind + queried value → human sentence).

**This is the single highest-value function in Phase 4.** It is what lets the demo
say: *"the sample asked whether the SBI app was installed, got no, and went to
sleep — here is the exact timestamp and the exact stack frame."* Without it,
Phase 5's morphing is a guess. With it, the frontier is a response to observed
behaviour, which is a categorically better story.

Test it deterministically: `test_evasion_detection` feeds a synthetic event list
(probe at t=1000, no events until t=4000) and asserts one observation with
`followed_by_stall=True, stall_duration_ms=3000`.

---

## T4.6 — Trace normalisation (H36 → H40) · Track A

`m3_dynamic/normaliser.py`: raw Frida messages + mitmproxy JSONL + logcat →
`DynamicTrace`.

- Deduplicate: a chatty app calls `getPackageInfo` 400 times. Collapse identical
  (api, args) into one event with `count`. Cap `api_events` at 2000; keep the
  first, last, and all *distinct-argument* events.
- Truncate arg strings to 256 chars, store the full value in a
  `DECRYPTED_BLOB`/`STRING_CONST` node if it's interesting (>64 chars, high
  printable ratio).
- `detonated` decision — a deterministic rule, defined once, never hand-waved:
  ```python
  detonated = any([
      dex_load_events_with_new_dex,           # dropped a second stage
      network_flow_with_exfil_shape,          # POST with device/sms/cred data
      overlay_view_added,
      accessibility_automation_observed,
      decrypted_blob_containing_url_or_dex,
      sms_forwarded_to_non_user_number,
  ])
  ```
  Record `detonation_reason` as the first rule that fired. This boolean is what the
  UI headlines and what `γ` reads — it must be defensible, not vibes.
- Append ledger nodes as you go, with `parents` pointing at the hypothesis node
  that caused the hook to exist. **The provenance chain from static hypothesis →
  hook → observed event is the "closed loop" claim in evidence form.** Build it.

---

## ⚠ T4.7 — TRIPWIRE @ H40 — mandatory decision point

**Set an alarm. When it rings, all three tracks stop for 15 minutes and answer one
question:**

> Does `LiveSandboxSource.run()` return a `DynamicTrace` with `detonated=True` on
> at least one real sample, reproducibly, three times in a row?

**If YES:** continue to Phase 5 live. Immediately capture and commit a replay
fixture anyway (30 minutes) — insurance is cheap once the capture works.

**If NO:** engage Replay Mode. This is a decision, not a failure:

1. Set `sandbox_mode="replay"` in the demo `.env`.
2. Spend the next 2 hours capturing **one good trace by any means necessary** —
   manual `frida -U -l script.js -f pkg`, manual mitmproxy, hand-assembled JSON if
   the hooks work but the orchestration doesn't. Partial-manual capture is fine;
   the trace is *real data from a real sample*, just not collected by our automation
   yet.
3. Save as `data/fixtures/traces/{sha}.json` with `pre_morph` / `post_morph` halves
   (Phase 5 needs both — see `PHASE_5 §5.6` for how to author `post_morph` honestly
   if you can't capture it live).
4. Keep working on live in the background *only* if Phase 5 and 6 are on track.
   Never at their expense.
5. **Write one honest slide:** *"The sandbox runs live on our analysis hardware.
   For demo reliability, this run replays a trace captured from sample
   {sha256[:12]} at {timestamp}."* Judges have seen dozens of demos die on a hung
   emulator. Disclosed replay reads as engineering maturity. Undisclosed replay
   discovered under questioning reads as dishonesty and ends your day.

The `TraceSource` abstraction from P0 means this switch costs 20 minutes. That is
the entire reason it was built at hour zero.

---

## T4.8 — Sandbox plan builder (H40 → H43)

```python
def build_plan(static: StaticReport, morphs=(), pass_num=1) -> SandboxPlan:
    hooks = BASE_HOOKS | {SINK_TAXONOMY[s].hook_id for s in static.sink_hits}
    for h in static.hypotheses[:5]:
        hooks |= set(h.target_apis) | dynamic_hooks_for(h.target_methods)
    stimuli = STIMULUS_BASE + extra_stimuli_for(static.hypotheses)
    return SandboxPlan(hooks=hooks, duration_s=120 if pass_num==1 else 180,
                       morphs=morphs, stimuli=stimuli,
                       generative_c2=any(h.kind==C2_BEACON for h in static.hypotheses))
```

Timing budget per pass: install 15s + launch 5s + observe 120s + stimuli
interleaved + teardown/snapshot 15s ≈ **~3 minutes**. Two passes plus morph
planning ≈ **8 minutes**, comfortably inside the 15–30 minute deep-analysis window
the paper claims. Assert this in the e2e test so the claim stays true.

---

## ★ INTEGRATION-2 — H48, hard 90-minute stop

- [ ] Upload → static → ML → GenAI → prelim score → **sandbox pass 1** → trace in UI
- [ ] Sandbox tab shows API timeline, network flows, screenshots
- [ ] `evasion_observations` populated and visible (even if `detonated=False` —
      **especially** if False, that's the setup for the frontier)
- [ ] Ledger has dynamic nodes with parents linking back to hypotheses
- [ ] `D` drift term now receives its dynamic half
- [ ] Full run ≤ 12 minutes
- [ ] Replay Mode toggles cleanly and produces an identical-shaped UI

Then decide Phase 5 scope based on remaining time. Sleep rotation continues.

---

## Phase 4 Definition of Done

- [ ] Emulator boots, installs, launches, stimulates, snapshots, restores
- [ ] ≥40 hooks via declarative factory; hypothesis-driven hooks added at runtime
- [ ] Spawn-gated instrumentation (catches `<clinit>`/`attachBaseContext`)
- [ ] Crash → snapshot restore → ≤3 LLM repair attempts → network-only fallback
- [ ] TLS intercept working; `Cipher.doFinal` plaintext capture working
- [ ] **Evasion observations detected with probe→miss→stall logic**
- [ ] `DynamicTrace` normalised, deduped, capped, schema-valid
- [ ] `detonated` computed by a written-down deterministic rule
- [ ] Tripwire evaluated at H40 and the decision recorded in `STATUS.md`
- [ ] Replay fixture committed with `pre_morph`/`post_morph` halves **regardless**
- [ ] Isolation verified and screenshotted
- [ ] `git tag p4-done`
