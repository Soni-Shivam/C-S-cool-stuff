# PHASE 1 — M2 STATIC ANALYSIS ENGINE

**Window:** H04 → H16 · **Owner:** Track A (Shivam), Track B pairs on §1.6
**Depends on:** P0 T0.3 (contracts), T0.4 (ledger), T0.10 (ingest)
**Exit criteria:** `analyse(apk) -> StaticReport` on a real banking-trojan sample
in <90s, producing ≥40 ledger nodes, ≥3 call paths to real sinks, and ≥2
`Hypothesis` objects that Phase 3 and Phase 5 can consume.

> The static engine is the foundation of everything downstream: it feeds the ML
> feature vector, the LLM's context, the sandbox's hook list, and the frontier's
> morph candidates. If it is weak, every other module is guessing. This is why it
> gets 12 hours despite being the least novel component.

---

## Architectural stance

**Androguard in-process is the core. MobSF is optional garnish.**

Androguard 4.x gives us, from one parse:
- `APK` — manifest, permissions, components, certificates, resources, icon
- `DalvikVMFormat` — classes, methods, strings, opcodes
- `Analysis` — **XREF graph** (`method.get_xref_from()` / `get_xref_to()`)

That XREF graph is the whole ballgame for Code-Graph RAG, and MobSF does not
expose it. Run MobSF only if `mobsf_enabled` and merge its findings additively;
never let a MobSF failure fail the stage.

```python
# m2_static/engine.py
def analyse(apk_path: Path, ledger: LedgerStore) -> StaticReport:
    a, d, dx = AnalyzeAPK(str(apk_path))         # ~5–40s depending on dex size
    r = _manifest(a, ledger)
    r |= _certificate(a, ledger)
    r |= _strings_and_constants(d, ledger)
    r |= _packing_signals(a, d, ledger)
    r |= _callgraph(dx, ledger)                   # the expensive one
    r |= _overprivilege(a, dx, ledger)
    r |= _mobsf_enrich(apk_path, ledger)          # optional, @degrades_gracefully
    return _assemble(r, hypotheses=_derive_hypotheses(r, ledger))
```

Every sub-analyser is independently timeboxed and independently degradable. Wrap
`_callgraph` in a hard 45s budget — on a 30MB obfuscated APK the full XREF walk can
run minutes, and a timeout returning partial paths beats a hung job.

---

## T1.1 — Manifest & permission analysis (H04 → H06)

### Extraction
```python
a.get_permissions()                 # incl. uses-permission-sdk-23
a.get_activities()/services()/receivers()/providers()
a.get_element("activity", "android:exported", name=...)   # careful: API 31 default
a.get_intent_filters(kind, name)
a.get_min_sdk_version(), a.get_target_sdk_version()
```

**Export-status gotcha (worth getting right, judges who know Android will ask):**
a component with an intent-filter and no explicit `android:exported` is exported on
`targetSdk < 31` and is a *build error* on ≥31. Compute effective exported status,
don't read the attribute naively:

```python
def effective_exported(comp, target_sdk) -> bool:
    if comp.exported_attr is not None: return comp.exported_attr
    return bool(comp.intent_filters)      # legacy default
```

### Permission combination rules — `m2_static/rules/permission_combos.yaml`

Single permissions are weak. Combinations are the signal. Encode ~14 rules:

```yaml
- id: OTP_THEFT_SURFACE
  all_of: [RECEIVE_SMS, READ_SMS]
  severity: high
  weight: 0.7
  mitre: T1582
  description: Can receive and read SMS — OTP interception surface
- id: OVERLAY_CREDENTIAL_THEFT
  all_of: [SYSTEM_ALERT_WINDOW]
  any_of: [INTERNET]
  plus_component_type: service
  severity: high
  weight: 0.65
- id: ACCESSIBILITY_ABUSE
  requires_service_binding: android.permission.BIND_ACCESSIBILITY_SERVICE
  severity: critical
  weight: 0.85
  mitre: T1417
- id: DROPPER_CAPABILITY
  all_of: [REQUEST_INSTALL_PACKAGES]
  severity: high
  weight: 0.6
  mitre: T1407
- id: ANTI_UNINSTALL_PERSISTENCE
  requires_admin_receiver: true       # BIND_DEVICE_ADMIN receiver present
  severity: high
  weight: 0.7
  mitre: T1626
- id: SILENT_SMS_FRAUD        # SEND_SMS + no SMS-related UI activity
- id: SPYWARE_HARVEST         # READ_CONTACTS + READ_CALL_LOG + INTERNET
- id: SCREEN_CAPTURE          # FOREGROUND_SERVICE + MediaProjection API use
- id: PERSISTENT_BOOT         # RECEIVE_BOOT_COMPLETED + FOREGROUND_SERVICE
- id: CLIPBOARD_MONITOR       # clipboard listener in code + INTERNET
- id: LOCATION_TRACKING
- id: CAMERA_MIC_SURVEILLANCE
- id: EXTERNAL_STORAGE_EXFIL
- id: NOTIFICATION_LISTENER   # BIND_NOTIFICATION_LISTENER_SERVICE (OTP via notif)
```

Rule engine is 60 lines: load YAML → evaluate predicates against the extracted
facts → emit `PERMISSION_COMBO` ledger node per match with the matched permission
list in `content`. **Each match cites the specific `MANIFEST_ENTRY` nodes as
`parents`** — this is what makes the evidence graph a graph rather than a list.

### Deep link surface
Collect `<data android:scheme=...>` from all intent filters. Flag: schemes on
exported activities with no `android:permission`, `http/https` app-links without
`autoVerify`, and any activity that both accepts a custom scheme and touches a
`WebView` (cross-reference with the call graph in T1.4 — this is a genuine Level-2
finding and worth a UI callout).

**Acceptance:** on a known banker sample, ≥4 combos fire including
`OTP_THEFT_SURFACE`. Unit test with a hand-built fake manifest fixture.

---

## T1.2 — Certificate analysis (H06 → H07)

```python
cert = a.get_certificates()[0]      # x509 via asn1crypto
```
Compute and emit one `CERTIFICATE` node:

| Field | How | Why it matters |
|---|---|---|
| `age_days` | `now - not_before` | Fresh cert + bank branding = strong fraud signal |
| `validity_years` | `not_after - not_before` | 30-year self-signed is the Android default; not a signal alone |
| `known_bad_reuse` | sha256 of cert against `data/kb/known_bad_certs.txt` (seed from MalwareBazaar metadata) | Campaign clustering |
| `brand_mismatch` | app label / package contains a brand token from `data/kb/brands.yaml`, but cert CN/O does not match the brand's known signer | The core impersonation tell |
| `debug_cert` | CN=`Android Debug` | Amateur repack |

`brands.yaml` seeds ~20 Indian financial brands with `{name, tokens, legit_packages,
legit_cert_sha256}`. Ship it hand-written; it's 30 minutes and it powers both this
check and the VLM comparison in Phase 3.

**Explicitly do not score "self-signed".** Note in the report UI: *"every Android
APK is self-signed; DRISHTI scores reuse, age, and brand mismatch instead."* That
one sentence signals domain competence to a security judge.

---

## T1.3 — Strings, constants, packing signals (H07 → H08)

From `DalvikVMFormat.get_strings()`:
- **URLs** — regex, then classify: known-good CDN/analytics allowlist vs. unknown.
  Defang for display (`hxxp://`). Emit `STRING_CONST` node each, with the method
  that references it (`dx.get_strings()` gives xrefs — use them, a URL with no
  reference is dead weight).
- **Package names** — anything matching `^[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}$` that
  is *not* the app's own package. **These are the morph candidates for Phase 5.**
  Cross-reference against `brands.yaml` legit_packages → if the sample string-refs
  `com.sbi.yono`, that is a target-app probe candidate, and it goes straight into
  a `TARGET_APP_PROBE` hypothesis. This link is the seed of the frontier demo.
- **Crypto constants** — AES/DES key-like base64 or hex literals near
  `javax.crypto` references; `"AES/CBC/PKCS5Padding"` style transform strings.
- **Telephony/locale constants** — MCC/MNC codes, country ISO codes → logic-bomb
  and geo-fence hypotheses.

### Packing / obfuscation signals
```python
entropy_per_dex = shannon(dex_bytes)        # >7.2 → likely packed/encrypted
classes_in_manifest_not_in_dex              # stub dex, real payload in assets
assets_with_high_entropy                    # .dat/.jar in assets/ with entropy >7.5
name_obfuscation_ratio                      # fraction of classes matching ^[a-z]{1,2}$
native_lib_names                            # known packer .so names
known_packer_strings                        # "jiagu","secneo","bangcle","ijiami"...
```
Emit `packer_hints`. High entropy + tiny dex + big asset is the classic dropper
shape and it is worth its own UI badge: *"payload appears packed — static coverage
limited, dynamic analysis required."* That sentence is also the honest setup for
why the sandbox matters.

---

## T1.4 — Call-graph construction + backward sink walk (H08 → H12) · **the core**

This implements Figure 3 of the paper, and it is what keeps LLM prompts small.

### Build
```python
G = nx.DiGraph()
for m in dx.get_methods():                    # MethodAnalysis
    if m.is_external(): continue
    src = m.full_name
    for _, callee, _ in m.get_xref_to():
        G.add_edge(src, callee.full_name)
```
On large APKs this is 10⁵ edges — fine for networkx. Cache the graph pickled per
sha256 under `.cache/graphs/` so re-runs during development are instant.

### Identify sinks
For each `sink_id` in `SINK_TAXONOMY`, find matching nodes by signature prefix
match. Emit a `SINK_HIT` node per sink actually present.

### Backward BFS with entrypoint attribution
```python
def paths_to_sink(G, sink_node, entrypoints, max_depth=6, max_paths=5):
    """Reverse BFS from sink; stop at depth or when an entrypoint is reached.
    Return the SHORTEST distinct paths — analysts and LLMs both want the
    shortest explanation, and prompt budget is finite."""
```
`entrypoints` = lifecycle methods of manifest-declared components
(`onCreate`, `onReceive`, `onStartCommand`, `onAccessibilityEvent`,
`onBind`, `doInBackground`, `run`, `onHandleIntent`) plus any `<clinit>` /
`attachBaseContext` (dropper unpack point — flag specially, this is where packers
decrypt).

**`reachable_from_lifecycle` is the key boolean.** A sink reachable only from dead
code is much weaker evidence than one reachable from `onReceive` of a registered
SMS receiver. Score them differently and say so in the UI.

Emit one `CALL_PATH` node per path with `parents=[sink_hit_node, ...]`.

### Method body extraction for the LLM
For each path node, extract the decompiled body. Androguard's built-in decompiler
(`m.get_method().source()`) gives readable-enough Java. **Do not shell out to jadx
per-method** — jadx-full-decompile is 30–120s and only worth it once, in the
background, if you want browsable source in the UI. Decision: androguard inline for
the LLM path; optional background jadx for the report's "view source" link.

Store method bodies as `CODE_METHOD` nodes, truncated to 2000 chars each with a
`truncated: true` flag. These nodes are what Phase 3's Code Interpreter cites.

### Hierarchical summarisation ladder
Implemented in Phase 3 (it needs the LLM), but the *structure* is built here:
`leaf method → class → component → app`. Emit the grouping now so P3 just walks it.

**Acceptance:**
- `test_callgraph_finds_sms_path` — on the canary APK, a path from `onReceive` to
  the SMS sink exists with depth ≤ 4.
- Wall time on a 25MB obfuscated sample < 45s (assert in test, mark `slow`).

---

## T1.5 — Over-privilege & drift (H12 → H13)

```python
declared = set(a.get_permissions())
exercised = permissions_implied_by_api_calls(dx)   # via androguard's
                                                   # api permission mapping / PScout
declared_not_used = declared - exercised   # over-privilege → hidden intent tell
used_not_declared = exercised - declared   # reflection/DCL smell → feeds D
```
Androguard 4.x ships an API↔permission mapping; if it's incomplete, hand-map the 25
permissions that matter (the ones in your combo rules). Don't build a complete
PScout — diminishing returns.

`used_not_declared` is the **static half of the D (drift) term**. The dynamic half
arrives in Phase 4: permissions actually exercised at runtime that were never
declared statically (classic dynamic-code-loading tell). Wire `D` to accept both
halves now so Phase 4 just adds data.

---

## T1.6 — Hypothesis derivation (H13 → H15) · Track A + B pair

**This is the single most important function for pipeline coherence.** It converts
static facts into instructions for the sandbox and the frontier. Everything
downstream in Phases 3–5 consumes `StaticReport.hypotheses`.

```python
def derive_hypotheses(r: PartialStatic, ledger) -> list[Hypothesis]:
    H = []
    # 1. SECONDARY_PAYLOAD
    if sink_hit("dex_load") or r.dcl_indicators:
        crypto_methods = methods_on_path_between("crypto", "dex_load")
        H.append(Hypothesis(
          kind=SECONDARY_PAYLOAD, priority=1,
          statement=f"Method {crypto_methods[0]} decrypts a blob and passes it to "
                    f"DexClassLoader — suspected secondary payload.",
          target_methods=crypto_methods + dexload_methods,
          target_apis=["javax.crypto.Cipher.doFinal",
                       "dalvik.system.DexClassLoader.$init"],
          suggested_probe={"hook":"cipher_dump"},
          evidence_refs=[...]))
    # 2. TARGET_APP_PROBE   ← drives Phase 5 morphing
    if sink_hit("pkg_query"):
        candidates = [s for s in r.package_name_strings
                      if s in BRAND_PACKAGES or s in WALLET_PACKAGES]
        H.append(Hypothesis(kind=TARGET_APP_PROBE, priority=1,
          statement=f"Queries PackageManager for {candidates[:5]} — payload likely "
                    f"gated on presence of a target banking/wallet app.",
          target_apis=["android.content.pm.PackageManager.getPackageInfo",
                       "...getInstalledPackages", "...resolveActivity"],
          suggested_probe={"morph":"install_packages","candidates":candidates}))
    # 3. OTP_EXFIL          — sms sink + net sink on a common path
    # 4. OVERLAY_ATTACK     — SYSTEM_ALERT_WINDOW + WindowManager.addView path
    # 5. ACCESSIBILITY_ABUSE— accessibility service + onAccessibilityEvent → net
    # 6. C2_BEACON          — unknown URL constants + net sink from a service
    #                         → suggested_probe={"generative_c2": True}
    # 7. LOGIC_BOMB         — date/SIM/locale comparison on a path guarding a sink
    #                         → suggested_probe={"morph":"clock_skew"|"sim_locale"}
    # 8. CLIPBOARD_SWAP     — clipboard listener + crypto-address regex string
    return sorted(H, key=lambda h: h.priority)[:8]
```

Cap at 8. Each hypothesis becomes: an `AI_HYPOTHESIS` ledger node, a set of Frida
hooks in Phase 4's `SandboxPlan`, and a prompt section in Phase 3.

**Acceptance:** on the canary APK, hypotheses include `TARGET_APP_PROBE` with
`com.sbi.yono` in candidates. This is the thread that runs all the way to the
frontier demo — test it end-to-end as a unit test now.

---

## T1.7 — MobSF enrichment, optional (H15 → H16) · only if ahead of schedule

```python
@degrades_gracefully(default=None, timeout=120)
def mobsf_enrich(apk_path) -> MobSFExtras | None:
    # docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf
    # POST /api/v1/upload → POST /api/v1/scan → POST /api/v1/report_json
```
Merge only what androguard doesn't give: MobSF's hardcoded-secrets scan, its
security-score's CVE/best-practice findings, and its `apkid` packer detection.
Emit as separate ledger nodes with `source_tool="mobsf"` so provenance stays clean.

**If MobSF's first run isn't green in 40 minutes, kill it and set
`mobsf_enabled=False` permanently.** It's on the cut-list for a reason.

---

## Testing plan

`tests/unit/test_m2_*.py`:
1. `test_permission_combos` — synthetic manifests, each rule fires exactly once
2. `test_effective_exported` — targetSdk 30 vs 31 semantics
3. `test_cert_brand_mismatch` — label "SBI YONO", cert CN "anon" → mismatch True
4. `test_entropy_packer_hint` — random bytes dex → `high_entropy_dex`
5. `test_callgraph_backward_walk` — hand-built nx graph, assert shortest path
6. `test_hypotheses_from_fixture` — canary APK → TARGET_APP_PROBE present
7. `test_static_degrades` — corrupt dex → `partial=True`, `errors` non-empty,
   manifest fields still populated
8. `test_static_timeout` — monkeypatched slow callgraph → returns partial in ≤90s

`tests/e2e/test_static_e2e.py`: real sample → StaticReport valid, ≥40 ledger nodes,
`verify_chain().ok`.

**Golden-file discipline:** commit `data/fixtures/static/{sha}.json` for two
samples. Any change to the static engine that alters golden output must be an
intentional, reviewed diff. This catches accidental regressions during the
sleep-deprived hours.

---

## Failure modes & fallbacks

| Failure | Fallback |
|---|---|
| `AnalyzeAPK` OOM/hangs on huge APK | Parse manifest only via `APK()` (cheap), skip `Analysis`, set `partial=True`. Report still renders |
| Androguard decompiler throws on obfuscated method | Fall back to smali listing for that method; LLM handles smali surprisingly well — say so in the prompt |
| No sinks found (fully packed sample) | This is *itself* the finding. Emit `packer_hints` + a `SECONDARY_PAYLOAD` hypothesis with priority 1, and let the sandbox carry the analysis. Do not treat as failure — **this is the exact scenario the product exists for** and the UI should say so explicitly |
| Call graph explodes (>500k edges) | Prune to methods reachable within depth 8 of any entrypoint before BFS |

---

## Phase 1 Definition of Done

- [ ] `StaticReport` populated on 3 real samples + canary, all schema-valid
- [ ] ≥14 permission-combo rules; ≥18 sinks in the taxonomy
- [ ] Call graph + backward BFS produces attributed `CallPath` objects
- [ ] Certificate brand-mismatch works against `brands.yaml`
- [ ] Over-privilege both directions computed; `D`-static half wired
- [ ] ≥5 hypothesis kinds derivable; canary yields `TARGET_APP_PROBE`
- [ ] ≥40 ledger nodes per sample, chain verifies, parents form a real DAG
- [ ] 8 unit tests + 1 e2e green; golden files committed
- [ ] <90s wall time on a 25MB sample
- [ ] `git tag p1-done`
