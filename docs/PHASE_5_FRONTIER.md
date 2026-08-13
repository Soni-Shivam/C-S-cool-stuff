# PHASE 5 — THE FRONTIER: ADVERSARIAL ELICITATION & STATE SYNTHESIS

**Window:** H44 → H58 · **Owner:** Track C (Vedant) + Track B (Ayusha) pairing
**Depends on:** P4 T4.5 (evasion observations) — **hard dependency**, P3 (LLM client)
**Exit criteria:** a sample that does not detonate in pass 1 detonates in pass 2
after an LLM-generated morph plan is applied, with the whole causal chain visible
in the ledger.

> This is the demo. Everything before it is infrastructure that makes this
> believable, and everything after it is presentation. If you get one thing
> working beautifully in 72 hours, make it this — because it is the one thing in
> the ideation document that no shipping tool does.

---

## The idea in one paragraph, for the pitch

Every other sandbox is passive: it runs the app and writes down what happens. But
modern trojans are *conditional programs* — they ask the device a question ("is the
SBI app installed?", "is this SIM Indian?", "does my C2 answer?") and stay inert if
the answer is wrong. A passive sandbox always gives the wrong answer, so the
malware always stays inert, so the scanner always says clean. DRISHTI inverts this:
it watches which question the sample asked, has an LLM reason about what answer the
sample is hoping for, synthesises exactly that answer, and runs it again. The
attacker's greatest strength — environmental pickiness — becomes the exact channel
through which we extract a confession. **The more carefully targeted the malware,
the more precisely it tells us what it is.**

Say that last sentence on stage. It is the thesis.

---

## The closed loop, concretely

```
  pass 1: detonated=False
     │
     ├── EvasionObservation(installed_package, "com.sbi.yono", MISS, stall 3.2s)
     ├── EvasionObservation(sms_history, count=0, MISS, stall 1.8s)
     └── NetworkFlow(POST http://x.onion/gate, ERR_CONN_REFUSED)
                        │
                        ▼
            ┌───────────────────────────┐
            │ ADVERSARIAL ELICITOR (LLM)│   1–2 calls, RAG-grounded
            │ "what environment is this │
            │  sample hunting for?"     │
            └───────────┬───────────────┘
                        ▼
                    MorphPlan
       ├ INSTALL_PACKAGES  [com.sbi.yono, com.phonepe.app]
       ├ SMS_HISTORY       42 synthetic bank-shaped messages
       ├ SIM_LOCALE        MCC 404 / "in" / Hindi
       ├ BUILD_PROPS       Redmi Note 12, non-goldfish fingerprint
       └ GENERATIVE_C2     enabled, schema inferred from parser code
                        │
                        ▼   apply_morphs()  (validated, sandboxed)
  pass 2: detonated=True → DEX dropped → exfil POST observed
                        │
                        ▼
            B rises · γ rises · S rises · C rises
            ledger: MORPH_ACTION → DETONATION → NETWORK_FLOW
```

---

## T5.1 — Morph applicator: the mechanism (H44 → H48) · Track C

**Key implementation insight that makes this feasible in 4 hours:** you do not need
to actually install real banking apps or populate a real SMS database. You need the
*sample* to believe those things. And the sample learns about its environment
exclusively through framework API calls — which we are already hooking with Frida.

**So morphing is: Frida hooks that return synthetic values.** This is why Phase 4's
hook factory was worth building.

`m3_dynamic/scripts/morph/` — a separate directory from the observational hooks,
because these deliberately alter return values:

### `morph_packages.js`
```js
// Given MORPH_PACKAGES = ["com.sbi.yono", "com.phonepe.app"]
// Hook PackageManager.getPackageInfo(String, int):
//   if arg0 in MORPH_PACKAGES and original threw NameNotFoundException,
//   construct and return a synthetic PackageInfo (packageName, versionName,
//   versionCode, firstInstallTime, applicationInfo with a plausible sourceDir).
// Also hook: getInstalledPackages (append synthetic entries),
//            getLaunchIntentForPackage, resolveActivity, getApplicationInfo,
//            queryIntentActivities.
```
Cover all six entry points — a sample that checks `getInstalledPackages` and gets a
list missing the app it just successfully queried via `getPackageInfo` may detect
the inconsistency. **Consistency across probe surfaces is the difference between a
morph that works and one that trips an anti-analysis check.** Budget time for this;
it's the subtle part.

### `morph_sms.js`
Hook `ContentResolver.query` for `content://sms/*` and return a synthetic
`MatrixCursor` populated from `synthetic_identities.yaml` — bank-shaped messages
("Rs. 2,340 debited from A/c XX4471"), OTP messages, dated over ~6 months. Also
hook `getCount`, `moveToNext`, and the column getters consistently.

### `morph_device.js`
`Build.MODEL/FINGERPRINT/PRODUCT/HARDWARE/MANUFACTURER` → a real mid-range Indian
device profile. `TelephonyManager.getSimCountryIso→"in"`,
`getNetworkOperatorName→"Jio"`, `getSimOperator→"40570"`,
`getDeviceId/getSubscriberId` → synthetic. `SystemProperties.get` for
`ro.kernel.qemu` → `""`. This is anti-emulator-detection *and* geo-targeting
satisfaction in one file.

### `morph_accounts.js`, `morph_contacts.js`, `morph_files.js`
Same pattern: hook the read surface, return synthetic data.

### `morph_clock.js`
For time bombs: hook `System.currentTimeMillis`, `new Date()`, `Calendar.getInstance`
with a configurable offset. Also `adb shell date` for the system-level path. If the
static analysis found a date comparison guarding a sink, set the offset to *past*
that date.

### The applicator
```python
def apply_morphs(morphs: tuple[Morph, ...], emulator, frida) -> AppliedMorphs:
    for m in morphs:
        validate_morph(m)                    # ← T5.2, non-negotiable
        script = render_morph_script(m)      # jinja → js, params injected as JSON
        scripts.append(script)
    ledger.append(type=MORPH_ACTION, content={...}, parents=m.derived_from)
```
Morph params are injected as a **JSON literal at the top of the script**
(`const MORPH_CONFIG = {{ params_json }};`), never string-concatenated into JS
expressions. Same discipline as SQL parameterisation, same reason.

---

## T5.2 — Morph validation (H46 → H47) · security gate, do not skip

The LLM generates morph parameters. Those parameters flow into `adb` commands and
JS. Treat LLM output as untrusted input to a command surface — because that's
exactly what it is.

```python
def validate_morph(m: Morph) -> None:
    if m.kind not in MorphKind: raise InvalidMorph
    match m.kind:
        case INSTALL_PACKAGES:
            for p in m.params["packages"]:
                if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,6}", p):
                    raise InvalidMorph(f"bad package name: {p!r}")
                if len(p) > 128: raise InvalidMorph
            if len(m.params["packages"]) > 20: raise InvalidMorph
        case SMS_HISTORY:
            if m.params["count"] > 200: raise InvalidMorph
            # bodies: strip control chars, cap 300 chars each
        case CLOCK_SKEW:
            if abs(m.params["offset_days"]) > 3650: raise InvalidMorph
        case BUILD_PROPS:
            allowed = {"MODEL","FINGERPRINT","PRODUCT","HARDWARE","MANUFACTURER",
                       "BRAND","DEVICE"}
            if set(m.params) - allowed: raise InvalidMorph
        ...
    # global: no shell metacharacters anywhere in any string value
    # global: no path separators in any value that reaches a filesystem call
```

`tests/unit/test_morph_injection.py` — feed 15 hostile morph params
(`"com.x; rm -rf /"`, `"../../../etc/passwd"`, a 10MB string, unicode
right-to-left overrides, null bytes) and assert every one raises.

This test is worth mentioning unprompted in the Q&A: *"we treat our own model's
output as untrusted input to the system-command surface"* is a mature thing to say.

---

## T5.3 — Adversarial Elicitor agent (H47 → H50) · Track B

One LLM call (two if the first plan fails). Input is **only structured
observations**, never raw sample strings — keeps the prompt small and the injection
surface minimal.

**Prompt** (`prompts/adversarial_elicitor.jinja`):

```
SYSTEM:
You are an Android malware analyst designing a controlled sandbox environment so
that a dormant sample will execute its full payload inside an isolated analysis VM.
This is defensive research: the goal is to observe hidden behaviour so it can be
detected and blocked. You do not modify the sample and you add no capability to it;
you only configure the analysis environment it observes.

Given the environment probes the sample performed and the conditions it appears to
require, produce a morph plan using ONLY the enumerated morph kinds.

Rules:
- Every morph must be justified by a specific observation id.
- Prefer the minimum set of morphs that plausibly satisfies the sample's checks.
- If observations are insufficient to infer a requirement, return an empty plan
  and say so.
- Output only JSON matching the schema.

USER:
## Observed environment probes (pass 1)
{% for e in evasion_observations %}
- [{{ e.node_id }}] t={{ e.t_ms }}ms  {{ e.probe_kind }}: queried "{{ e.queried }}"
  → {{ e.result }}{% if e.followed_by_stall %} → process stalled {{ e.stall_duration_ms }}ms{% endif %}
{% endfor %}

## Static hypotheses
{% for h in hypotheses %}- [{{ h.id }}] {{ h.statement }}{% endfor %}

## Failed network attempts
{% for f in failed_flows %}- [{{ f.node_id }}] {{ f.method }} {{ f.url }} → {{ f.error }}{% endfor %}

## Reference knowledge
<reference_knowledge>
{{ rag_family_context }}   {# e.g. "Anatsa checks for a target-bank list before
                               requesting Accessibility" #}
</reference_knowledge>

## Available morph kinds
{{ morph_kind_docs }}

## Schema
{{ schema }}
```

**Output:** `MorphPlan` — validated by pydantic, then by `validate_morph`, then
appended to the ledger as `MORPH_ACTION` nodes with `derived_from` = the cited
observation node ids.

**The grounding requirement matters here too:** a morph whose `derived_from` is
empty is rejected. We do not morph on vibes; we morph in response to observed
probes. That constraint is what makes this "adversarial elicitation" rather than
"throw a lot of fake data at it and hope."

RAG helps genuinely here: retrieving the Anatsa or GodFather write-up gives the
model real prior knowledge about what these families check for, which improves plan
quality measurably. Do a before/after comparison on one sample if time permits — it
is a nice empirical footnote.

---

## T5.4 — Generative C2 emulation (H50 → H54) · Track C + B

The hardest sub-feature, and the most impressive. Scope it in three tiers and ship
whichever you reach.

### Tier 1 — Static responder (30 min, always ship this)
mitmproxy addon: any request to a host classified as C2 (unknown domain, from a
service, no TLS or self-signed) gets a `200 OK` with `{"status":"ok"}`. Many
samples proceed past a mere connectivity check. Cheap, and it sometimes works.

### Tier 2 — Schema-inferred responder (2–3 h, the target)
1. Phase 1's call graph found the **parser**: the method that consumes the HTTP
   response. Extract its body plus the JSON key strings it references
   (`getString("cmd")`, `optJSONArray("targets")`, `has("payload_url")`).
2. One LLM call:
   ```
   Here is the method that parses the server response, and the string constants
   it references. Infer the response schema this client expects, and produce ONE
   example response that would cause the client to take its most functional path
   (e.g. proceeding to download or install a component) inside our isolated
   sandbox. Output JSON: {content_type, schema, example_response, reasoning,
   fields_that_gate_behaviour[]}.
   ```
3. mitmproxy addon serves `example_response` for that endpoint.
4. Observe: does the sample now proceed? If it requests a payload URL, serve an
   **inert** file from the sandbox's local HTTP server — a valid but harmless DEX
   (a compiled no-op class) or a marker file. **We never serve real malicious
   second-stage content**, and we log exactly what we served in a `GENERATIVE_C2`
   ledger node. If the sample loads our inert DEX, we have proven the dynamic-load
   path and captured the download URL, the request format, and the loader
   behaviour — which is the intelligence we wanted.

That last point is worth internalising: **we don't need the real payload to prove
the capability.** Observing that the sample downloads-and-loads whatever the C2
sends is the finding. This is both safer and easier than trying to obtain real
second-stage payloads.

### Tier 3 — Iterative refinement (only if hours remain)
If the sample rejects the synthesised response (parse exception in logcat, retry
loop, no state change), feed the exception back to the LLM for one refinement round.
Cap at 2 refinements. Log each attempt.

**Ledger nodes:** `GENERATIVE_C2` per synthesised response, containing the request,
the inferred schema, the served response, the LLM's reasoning, and whether the
sample's behaviour changed afterwards. That last field — *did it work* — is the
honest metric and belongs in the UI.

---

## T5.5 — The frontier orchestration loop (H52 → H56)

`drishti/frontier/loop.py`:

```python
def run_frontier(job, static, trace1, ctx) -> FrontierResult:
    if trace1.detonated:
        return FrontierResult(engaged=False, reason="detonated on first pass")
    if not trace1.evasion_observations and not failed_flows(trace1):
        return FrontierResult(engaged=False, reason="no evasion signal observed")

    plan = elicitor.plan(trace1, static, ctx)          # LLM, ≤2 calls
    if not plan.morphs:
        return FrontierResult(engaged=False, reason="insufficient evidence to infer")

    for m in plan.morphs: validate_morph(m)
    ledger.append_morph_actions(plan)

    sandbox_plan = build_plan(static, morphs=plan.morphs, pass_num=2)
    trace2 = trace_source.run(apk, sandbox_plan)

    if trace2.detonated:
        ledger.append(type=DETONATION, content={
            "reason": trace2.detonation_reason,
            "morph_plan": plan.id,
            "delta": diff_traces(trace1, trace2)},
            parents=[*morph_node_ids, trace2_run_node])
        return FrontierResult(engaged=True, success=True, ...)

    # bounded recursion: new evasion observations in pass 2 → one more attempt
    if new_observations(trace1, trace2) and ctx.frontier_rounds < 2:
        return run_frontier(job, static, trace2, ctx.next_round())
    return FrontierResult(engaged=True, success=False,
                          reason="morphs did not unlock payload")
```

**Cap recursion at 2 rounds.** The paper says "recurse until the execution graph is
fully unrolled"; in 72 hours, two rounds with a clean failure message is the honest
implementation. Say "bounded to 2 rounds in this build" rather than implying
unbounded recursion you didn't test.

### `diff_traces()` — build this, it's the demo's punchline

```python
def diff_traces(t1, t2) -> TraceDiff:
    """New APIs called, new network flows, new dex loads, new files written,
    new behaviour tags. Rendered in the UI as a side-by-side."""
```

The side-by-side "before morph / after morph" panel is the single most persuasive
UI element in the entire project. **Budget an hour on making it look good.** Left
column: 14 API calls, 0 network flows, "no payload observed." Right column: 340 API
calls, 6 network flows, 1 DEX loaded, "exfiltration POST captured." A judge
understands the entire product from that one screen.

---

## T5.6 — Replay-mode frontier (H54 → H56) · **do this even if live works**

The frontier must be demoable in Replay Mode. `ReplayTraceSource` inspects
`plan.morphs`: empty → return the `pre_morph` trace; non-empty → return `post_morph`.
The frontier loop, the LLM elicitor, the validator, and the ledger all run for real.
Only the emulator is replaced by a fixture.

**Authoring `post_morph` honestly when you couldn't capture it live:**

Best → worst, use the highest one available:
1. **Captured live.** Ideal. Use it.
2. **Captured semi-manually** — you ran the morph hooks by hand with `frida -U -l`
   and captured real output, but the orchestration wasn't automated. Still real
   data. Use it, and describe it accurately.
3. **Captured from a sample that detonates without morphing** — take a
   non-evasive banker, capture its real detonation trace, and use it as the
   `post_morph` half while a genuinely evasive sample supplies `pre_morph`. This is
   a **composite** and you must label it as such in the fixture (`"composite":
   true`) and say so on the slide. Defensible if disclosed; not otherwise.
4. **Hand-authored.** Last resort. Mark `"synthetic": true` in the fixture, and the
   UI must render a visible "SYNTHETIC FIXTURE" badge that you cannot forget to
   mention.

Wire the badge to the fixture flag in code, so honesty is automatic rather than
dependent on a tired person remembering at hour 71. That's a design decision worth
making deliberately: **make the truthful thing the default behaviour of the
system**, not a discipline you have to sustain.

---

## T5.7 — Frontier UI panel (H56 → H58) · Track C

Dedicated tab, four stacked sections:

1. **What it asked for** — the evasion observations as a timeline with the stall
   durations rendered as gaps. Visually obvious that the process went quiet.
2. **What we synthesised** — the morph plan as cards, each showing the morph kind,
   its params, the LLM's rationale, and a link to the observation that justified it.
3. **What happened next** — the `diff_traces` side-by-side.
4. **Generative C2** — request, inferred schema, synthesised response, and whether
   behaviour changed.

Live log lines during the frontier phase, written for a human reader:
```
[FRONTIER] pass 1 complete — detonated=False
[FRONTIER] 3 evasion probes observed, 2 followed by stalls
[FRONTIER] elicitor: sample requires a target banking app + Indian SIM locale
[FRONTIER] morph plan mp_0193: install_packages(2), sms_history(42), sim_locale(in)
[FRONTIER] validating morphs... 3/3 passed
[FRONTIER] pass 2 starting with synthesised environment
[M3]       PackageManager.getPackageInfo("com.sbi.yono") → SYNTHETIC HIT
[M3]       new: WindowManager.addView(TYPE_APPLICATION_OVERLAY)
[M3]       new: DexClassLoader.<init>(/data/data/.../payload.dex)
[M3]       new: POST http://x/gate  (body: 2.1KB)
[FRONTIER] ★ DETONATION — reason=dex_load_and_exfil
[M6]       score 61 → 92 · confidence 0.44 → 0.86
```

Slow the log render to ~150ms per line during the demo. It reads as a system
thinking rather than a dump, and it gives you time to narrate. Small touch, large
effect.

---

## Failure modes

| Failure | Handling |
|---|---|
| Morph hooks crash the app | Snapshot restore, drop the offending morph, retry with the remainder. Log which morph was dropped |
| Sample detects inconsistent fake state | Expand morph coverage to sibling APIs (this is why T5.1 covers 6 PackageManager entry points). If still detected, report it as an observed anti-analysis technique — a real finding, not a failure |
| Elicitor returns an empty plan | Correct behaviour when evidence is thin. UI says "insufficient evidence to infer required environment" — honest and still informative |
| Sample still doesn't detonate | Report `engaged=True, success=False` with the attempted plan. Score reflects low γ and low C. **This is an acceptable demo outcome if narrated well**: "the interrogation was attempted, documented, and honestly reported as inconclusive" beats a fabricated success |
| No evasive sample available to demo | Use the canary APK (inert, ours, checks for a package then logs). Less dramatic than real malware but the mechanism is identical and 100% reliable. Consider using it as the *primary* demo and a real sample as the secondary |

---

## Phase 5 Definition of Done

- [ ] Morph hooks for packages, SMS, device/SIM, accounts, contacts, clock
- [ ] Package morph consistent across all 6 PackageManager entry points
- [ ] `validate_morph` rejects 15 hostile inputs; test green
- [ ] Elicitor produces grounded morph plans citing observation node ids
- [ ] Empty-plan path works when evidence is insufficient
- [ ] Generative C2 Tier 1 shipped; Tier 2 shipped if time allowed
- [ ] Only inert content ever served as a second stage; logged in the ledger
- [ ] Frontier loop bounded to 2 rounds with clean failure reporting
- [ ] `diff_traces` + side-by-side UI panel
- [ ] Full frontier path works in **both** live and replay mode
- [ ] Fixture honesty flags (`composite`/`synthetic`) wired to a visible UI badge
- [ ] Score and confidence visibly move on detonation
- [ ] `git tag p5-done`
