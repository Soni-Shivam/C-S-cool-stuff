# Frontier C2 closure — design

**Date:** 2026-08-26 · **Author:** pairing session · **Status:** approved, pre-plan
**Scope:** Close the paper's §6.1 (Generative C2 Emulation) and §4.4 flagship claim by
wiring the already-built `generative_c2.py` into the live detonation path, adding the
network-flow capture it depends on, and proving it end to end on the sealed detonator.

---

## 1. Why this exists

The paper's flagship differentiator is the *active* sandbox: it answers a dead C2 to
force a dormant sample to unroll its payload. The code for the hard part —
`synthesise_response()`, `assert_inert()`, `derive_hints()`, `GenerativeC2Addon`,
`inert_payload_bytes()` — is **built and unit-tested** in
`drishti/m3_dynamic/generative_c2.py` (717 lines). It has **zero callers** outside its
own module. Meanwhile the detonator runs `infra/gcp/fake_c2.py`, a three-template static
sinkhole with no LLM and no grounding.

Two things are missing between "built" and "proven":

1. **Nothing records what the sample sent.** The AVD is configured with
   `http_proxy 10.0.2.2:8080` and `mitmdump` runs, but no addon writes the flows into
   the artifact. Today's `network_flows` come only from the `java.net.URL` Frida hook,
   so the proxy sees traffic nobody keeps. Generative C2 cannot ground a response in a
   request it never captured.
2. **The synthesis is never invoked.** `MorphKind.GENERATIVE_C2` is in the enum with no
   implementation; the frontier loop (`pipeline._frontier`) proposes device-state morphs
   but never a C2 response.

This design supplies both, then runs it live.

## 2. The hard constraint that shapes everything

`drishti-runtime` is **default-deny egress** (VPC firewall + host iptables + a signed
containment manifest that attests it). A process *on the detonator* physically cannot
reach `api.groq.com` / `generativelanguage.googleapis.com`. CLAUDE.md forbids opening
any route out "even for one test."

Therefore the LLM call is made **from the orchestrator host that runs the pipeline** —
the same host, same `LLMClient`, same Gemini/Groq key already used by every M4 agent.
The detonator receives a *pre-computed* answer and serves it offline. This is not "avoid
the API"; it is "call the API from the only side of the firewall that can, and stage the
result across."

This maps cleanly onto the two-pass frontier loop the pipeline already runs:

```
pass 1 (VM, sealed)        artifact           orchestrator (has egress)     pass 2 (VM, sealed)
─────────────────────      ─────────────      ─────────────────────────     ───────────────────
capture addon logs     →   CapturedFlow[]  →  build_c2_bundle():         →  proxy serves bundle
every real request         lifted into        derive_hints() from the        offline; on a
(no upstream, ever)        the artifact       OBSERVED flow, one LLM         payload-URL fetch,
                                              call per host for scalar        returns inert DEX;
                                              fill, assert_inert() gate,      DexClassLoader
                                              GENERATIVE_C2 ledger node       hook watches the load
```

A bundle entry's `derived_from` resolves to a real captured-flow evidence node from
pass 1 — so the ledger's grounding rule (`AI_CLAIM` with empty `evidence_refs` is
rejected) is satisfied by construction, not by a static guess.

**Live-callback mode** (addon calls the orchestrator at wire time to answer never-seen
hosts) is a deliberate follow-on, out of scope for this build. The bundle path is a
strict prerequisite for it, so nothing here is throwaway.

## 3. Components

Numbered in build order. Steps 1–7 are laptop-only and CI-safe; step 8 onward is live.

### 3.1 `CapturedFlow` contract + `captured_flows` field (`drishti/contracts/dynamic_trace.py`)
A new `StrictWireModel`: `t_ms_epoch`, `method`, `scheme`, `host`, `path`, `status`,
`req_body_preview`, `resp_body_preview`, `synthesised: bool`, `served_kind: str | None`.
Bodies are redacted; the field validator refuses unredacted sensitive text, exactly as
`ObservationEvent` does. `ObservationArtifact` gains
`captured_flows: tuple[CapturedFlow, ...] = ()`. `docs/01_DATA_CONTRACTS.md` gets the
field **first**, in the same commit (CLAUDE.md rule 1).

Why a new model, not an `ObservationEvent`: a flow has method/status/body/synthesised
structure that a flat 512-char `detail` string cannot hold, and `ingest.py` already
builds structured `NetworkFlow` — this keeps one structured path, not two.

### 3.2 Capture addon (`drishti/m3_dynamic/proxy/capture_addon.py`)
A mitmproxy addon that appends each flow to a JSONL file (path from `DRISHTI_FLOW_LOG`).
JSONL, not a socket — the runbook's rule ("no sockets to debug at 4am"). All bodies pass
through `redaction.redact_text` before they are written; nothing unredacted leaves the
guest. Pure parsing lives in a `parse_flow_log(text) -> list[CapturedFlow]` function
tested without mitmproxy present, mirroring how `GenerativeC2Addon` is a dumb adapter
over pure functions.

The harness records the log's byte length at install and reads the tail at teardown, so
one long-lived proxy segments cleanly per run without a restart.

### 3.3 `C2Bundle` contract (`drishti/contracts/c2_bundle.py`)
`C2BundleEntry`: `host`, `path_prefix`, `response_kind`, `served_status`,
`served_content_type`, `served_body`, `fill` (the LLM's scalar values, already
inert-checked), `is_payload_url: bool`, `derived_from: tuple[str, ...]` (evidence node
ids). `C2Bundle`: `sha256`, `entries`, `built_at`, `synthesis_client` (provider/model
string for provenance). Serialised to `<sha>.c2.json`, staged beside the APK.

### 3.4 Bundle builder (`drishti/m3_dynamic/c2_bundle.py`, orchestrator-side)
`build_c2_bundle(sha256, flows, static_report, *, client, ledger) -> C2Bundle`.
- Groups pass-1 `CapturedFlow`s by host; drops `_NOISE_HOST_SUFFIXES` (reuses
  `generative_c2._looks_like_beacon`).
- For each surviving host, derives a `C2SchemaHint` from the **observed** request (its
  path, method, body preview) fused with `derive_hints(static_report)` for that host.
- Calls `synthesise_response(observed_request, hint, client=client, ledger=ledger)` —
  one bounded LLM call per host, counting against the ≤25/job budget (asserted).
- `assert_inert()` is inside `synthesise_response`; an entry that cannot be made inert
  is **dropped**, not served.
- **Refuses to emit an entry with empty `derived_from`.** An ungrounded C2 answer is
  exactly the guess the frontier does not make. A bundle with zero grounded entries
  yields no pass 2.

### 3.5 Composed detonator proxy (`infra/gcp/drishti_proxy.py`)
Replaces `fake_c2.py` in `runtime_prepare.sh`. Loads three addons onto one mitmproxy
chain, in order:
1. **Capture** (always on) → writes `DRISHTI_FLOW_LOG`.
2. **Bundle responder** — if `DRISHTI_C2_BUNDLE` is set, serves matching
   host+path_prefix entries; marks the served flow `synthesised=True`,
   `served_kind=<response_kind>`.
3. **Inert second stage** — a request whose host+path the bundle flagged
   `is_payload_url` gets `inert_payload_bytes()` with `Content-Type:
   application/octet-stream`. The proxy already intercepts everything, so this preserves
   "never contacts upstream" without a second server.
4. **Static sinkhole fallback** — an unhinted host still gets `{"status":"sinkholed"}`,
   so a dead C2 never yields a connection error that itself changes behaviour.

The addon still runs on the sealed VM and still calls **no** LLM; it only reads the
pre-built bundle. `_ask_model` is never reached on the VM.

### 3.6 `synthesise_response` pre-supplied fill (`generative_c2.py`, small edit)
Add `fill: dict | None = None`. When present, skip `_ask_model` and use the supplied
values (still through `assert_inert`). One code path for "orchestrator pre-computed" and
"addon computed live later", the `artifact_to_trace` single-path pattern.

### 3.7 Ingest lift + honesty flags (`drishti/m3_dynamic/ingest.py`, edit)
- Lift `artifact.captured_flows` into `DynamicTrace.network_flows` with real
  method/status/host, `synthesised` carried through, `tls_intercepted=False` always
  (we capture cleartext HTTP; we do **not** install a system CA — runbook §0.0 finding
  6, and `Cipher.doFinal` is the stronger result).
- Merge with the existing Frida-URL-hook flows; dedupe by (host, path, t_ms window).
- `behaviour_changed` on each `SyntheticC2Response` is computed by differencing pass-1
  and pass-2 observation groups (`diff_traces` already exists) — **measured, never
  asserted**. No new groups in pass 2 → `False` → the report says the emulation did not
  work on this sample. A recorded negative, per the morph-then-wake precedent.

### 3.8 Wiring (`detonator_run.sh`, `scripts/dynamic_analyze.py`, `detonator.py`)
- `dynamic_analyze.py` gains `--c2-bundle <path>`; sets `DRISHTI_C2_BUNDLE` for the
  proxy and `DRISHTI_FLOW_LOG` for capture.
- `detonator_run.sh`: `c2 <sha>` subcommand = detonate pass 2 with the staged bundle.
  `MorphKind.GENERATIVE_C2` is accepted as a bundle kind, not a `.js` that will never
  exist (removes the current rc-5 refusal for that kind only).
- `RemoteDetonatorClient` stages `<sha>.c2.json` alongside the APK and passes
  `--c2-bundle` when `plan.morphs` contains a `GENERATIVE_C2` morph.
- `pipeline._frontier`: when pass-1 flows include a dead-beacon host, emit a
  `GENERATIVE_C2` morph whose `derived_from` cites the captured-flow node; the bundle is
  built in the same step.

## 4. Honesty properties (test-enforced)

- A `synthesised=True` flow is **never** published as an IOC. STIX export already filters
  on `synthesised`/`OBSERVED`; a contract test pins that a bundle-answered flow is
  excluded.
- `tls_intercepted` stays `False` everywhere. Claiming TLS interception when we only did
  cleartext capture would be false.
- `behaviour_changed` is a trace diff, never a flag.
- An all-ungrounded bundle produces **no pass 2**, never an unmorphed pass 2 relabelled
  as morphed (mirrors `detonator_run.sh morph`'s existing rc-5 refusal).
- `provably_inert` is set only by `assert_inert`; a bundle entry that failed the gate is
  absent from the bundle, so an un-inert body can never reach the wire.

## 5. Testing

Tests first for the testable-acceptance items (CLAUDE.md per-task rule):
- `tests/contract/` — `CapturedFlow`/`C2Bundle` round-trip; STIX excludes synthesised
  flows; bundle builder refuses ungrounded entries; ingest parity (a captured artifact
  with flows lifts them deterministically).
- `tests/unit/` — `parse_flow_log`; bundle builder groups/drops noise/one-call-per-host;
  `synthesise_response(fill=...)` skips the model and still inert-checks;
  `behaviour_changed` diff logic.
- Steps 1–7 run in CI (no GCP, no sample).

Live (step 8+):
- `tests/lab/test_c2_live.py` (`@pytest.mark.gcp`) — deploy proxy, detonate the **canary**
  (which does one HTTP GET to a configured local host), assert a `CapturedFlow` arrives.
  **This is the go/no-go gate**: if the canary's own GET is not captured, the plan stops
  at step 2 and we fix capture before touching real samples.

## 6. Live-run plan

1. `make lab-up` (start `m3-detonator`). Optionally stop `instance-20260817-080247`
   first (the n2-standard-16 extractor, ~$18/day, unrelated) — **operator decision**.
2. Deploy the proxy + code via `detonator_deploy.sh`.
3. Canary detonation → confirm capture end to end (the gate above).
4. Stage 5–10 corpus samples chosen for beacon-like URLs (`fetch_detonation_candidates`
   + a URL-string filter). Pass 1 (capture) → build bundle → pass 2 (serve) → collect.
5. Measure: flows captured/run, hosts hinted, C2 answered, `behaviour_changed` count,
   any inert-DEX load. Write to `STATUS.md` as a measured result — never an estimate.
6. `make lab-down`.

## 7. Risks (on the record)

- **The proxy may see very little.** Egress is blackholed; a sample that fails DNS may
  never issue an HTTP request. The canary gate (step 3) catches this before real-sample
  time. If flows don't arrive, that is the finding and the build stops at capture.
- **Android's own background traffic** hits the same proxy. Attribution is by post-install
  time window + the noise-host drop list. Imperfect; recorded as a known limit, no
  per-UID claim.
- **Packed samples with no extractable URLs** yield an empty bundle → no pass 2. Honest,
  and consistent with the measured "static intent has a ceiling" finding.
- **A pass-2 host unseen in pass 1** gets the static sinkhole, not a synthesised answer.
  That is the boundary live-callback mode would later remove.

## 8. Definition of done

- [ ] `CapturedFlow` + `C2Bundle` in contracts and `01_DATA_CONTRACTS.md`; round-trip green
- [ ] Capture addon writes redacted flows; `parse_flow_log` unit-tested
- [ ] Bundle builder: grounded-only, one LLM call/host, inert-gated, ledger nodes
- [ ] Composed proxy serves capture + bundle + inert second stage + sinkhole fallback
- [ ] Ingest lifts flows; `synthesised`/`tls_intercepted`/`behaviour_changed` correct
- [ ] Detonator wiring: `--c2-bundle`, `c2` subcommand, client staging
- [ ] All new honesty properties test-enforced; `make test` green
- [ ] Canary live capture proven (the gate)
- [ ] ≥5 real samples run through capture→bundle→serve; result measured in `STATUS.md`
- [ ] `make lab-down` run; no GCP resource left running by this work
