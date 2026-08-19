# Roadmap — completing the GenAI reverse-engineering layer and its workspace

Written 2026-08-18 against `main` @ `6db879a`. 474 tests green.

This plans two tracks that finish the paper's central claim, plus the detonation
work that unblocks half of it. Every task names the contract it fills, the test
that proves it, and what it must **not** do.

---

## 0. The finding that reorders everything

**The GenAI layer has never seen a line of the sample's code.**

`code_interpreter.explain_paths()` sends the model exactly this per call path:

```
[0] sink=pkg_query (queries installed packages) reachable_from_lifecycle=True depth=2
    entrypoint: Lcom/x/MainActivity;->onCreate
    sink signature: Landroid/content/pm/PackageManager;->getInstalledPackages
```

Signatures and graph metadata. No method body. `grep -rlnE "DecompilerDAD|get_source|decompile" drishti/`
returns nothing that decompiles — the only hit is `safety.py`, which already
declares a `decompiled_method` provenance kind for content **nothing produces**.

The paper (§ Frontier) claims the Code Interpreter "reconstructs the malware's
logic in plain English — tracing decrypted strings, exfiltration routines, and
second-stage payloads". Tracing a decrypted string requires reading the code that
decrypts it. Right now the layer narrates a call graph; it does not reverse
engineer.

**Consequence for ordering:** decompilation (A1) comes before every other GenAI
task. It is laptop-safe — androguard's DAD decompiler parses, it does not execute
— and it is the difference between a demo and the claim.

### Honest baseline

| Component | State |
|---|---|
| LLM client, budgets, cache, injection defence | **built** |
| Behaviour checklist → `B` from a Python weight table | **built** |
| Code Interpreter | **built, but reads signatures only** |
| Technique Mapper (deterministic, no LLM) | **built** |
| Verifier + claim rejection | **built** |
| Social-Engineering Analyst (T3.8) | **not built** — `VictimProfile` contract exists, unfilled |
| VLM impersonation (T3.9) | **not built** — `VisionMatch` contract exists, unfilled |
| Adversarial Elicitor | **not built** — `MorphPlan` contract exists, stub generator only |
| Generative C2 emulation | **not built** |
| Disagreement meta-check (T3.11) | **not built** — `disagreement_flag` always False |
| Gemini / Anthropic providers | **raise NotImplementedError** |
| Decompilation | **does not exist** |

The contracts are the good news: `VictimProfile`, `VisionMatch`, `MorphPlan`,
`elicitation_deployed` and `disagreement_flag` are already frozen in
`drishti/contracts/`. This roadmap fills implementations behind a stable surface,
so the UI and the ledger do not churn.

---

## Track A — the GenAI reverse-engineering layer

### A1. Decompilation feed · **blocks everything else** · ~4h

Give the model the code.

**Files:** `drishti/m2_static/decompile.py` (new),
`drishti/contracts/static_report.py` (add `DecompiledMethod`),
`tests/unit/test_decompile.py`, `tests/contract/test_roundtrip.py`

- Extract method bodies for methods **on a call path to a sink**, never the whole
  APK — a 50 MB sample decompiles to hundreds of MB and blows every budget.
- Budget: `MAX_DECOMPILED_METHODS = 12`, `MAX_METHOD_CHARS = 4000`, and the 90 s
  static ceiling still holds. Assert all three.
- Wrap output in `wrap_untrusted(..., kind="decompiled_method")` — the kind
  already exists in `safety.py`. Sample code is the most attacker-controlled input
  in the system; it goes in the user turn, XML-escaped, never a system prompt.
- Degrades: a method that will not decompile yields `errors`, never an exception.

**Acceptance:** on the canary APK, the decompiled body of the method that calls
`getInstalledPackages` appears in the report, under 4 000 chars, and the static
stage still completes inside 90 s.

**Must not:** decompile off a call path; execute anything; write source to disk
outside the job scratch.

---

### A2. Code Interpreter, reading real code · depends A1 · ~3h

Rewrite the prompt around method bodies. This is where "reverse engineering"
becomes true rather than aspirational.

Three questions per path, each answered only from the body shown:

1. What does this method do?
2. What data does it touch, and where does that data go?
3. Is any string here constructed or decrypted at runtime, and from what?

**Acceptance:** a golden test on a fixture with a base64-then-XOR string builder;
the claim must name the transformation and cite the `DECOMPILED_METHOD` node. A
claim citing nothing is rejected by the existing verifier — do not soften that.

**Must not:** classify. It explains; `B` still comes from the checklist weight
table. Rule 4 is unchanged.

---

### A3. String deobfuscation agent · depends A1 · ~3h

The single most analyst-visible win. Malware rarely ships plaintext C2 URLs.

- Input: `STRING_CONST` nodes plus the decompiled body of the method that consumes
  them.
- Output: `GroundedClaim`s of the form *"`aGVsbG8=` at
  `Lcom/x/Net;->url` decodes to `hxxp://...` via base64 then single-byte XOR"*.
- **Python verifies before the claim is kept.** The model proposes a
  transformation; a small deterministic evaluator (base64, hex, XOR, ROT, AES with
  a key found in the same class) *executes* it and the claim survives only if the
  output matches. A model-asserted decoding with no reproducible transform is
  rejected like any ungrounded claim.
- New evidence type `DEOBFUSCATED_STRING` carrying `{ciphertext, method, plaintext,
  verified_by}`.

**Acceptance:** a fixture with three encodings; all three verified, and a planted
false claim rejected.

**Must not:** run sample-supplied code to do the decoding — the evaluator is a
fixed allowlist of transforms, never `eval`.

---

### A4. Social-Engineering Analyst (T3.8) · depends A1 · ~3h

Fills `VictimProfile`, which already exists and is always `None` today.

- Input: UI strings from `resources.arsc` and layouts, the app label, the
  impersonated-brand signal from `certificate.brand_claimed`.
- Output: `language` (Hindi/Marathi/…), `tactic` (urgency/authority/fear),
  `segment`, `impersonated_target`, each with `evidence_refs`.
- Language detection is **deterministic** (Unicode block + `langdetect`), not
  model-asserted — a script range is a fact, not an opinion.

**Acceptance:** a Devanagari-string fixture yields `language="hi"` with a citation;
a sample with no UI strings yields `None`, never a guess.

**Must not:** infer a victim segment from the *package name* alone; that is
astrology, and it will be quoted back at you in a demo.

---

### A5. Disagreement meta-check (T3.11) · depends A2 · ~2h

`disagreement_flag` is wired through the contract and never set.

When `P_cal` and `B` disagree by more than a threshold, a dedicated call is asked
to reconcile them **without seeing either number** — it is given the evidence and
asked what it supports. Then Python compares. This makes figure 06's
non-determinism finding actionable rather than merely disclosed.

**Acceptance:** a fixture where ML says 0.9 and the checklist says 0.1 sets the
flag, and the note names which evidence each side leaned on.

---

### A6. Adversarial Elicitor · depends Track C (detonation) · ~4h

Turn `EvasionVerdict.morphs` — which already names the morph kinds — into a
validated `MorphPlan`.

- `evasion.detect()` already returns `install_packages`, `sms_history` etc. The
  Elicitor turns those into concrete params (*which* package, *how many* messages).
- **`validate_morph()` before anything touches adb or JS.** Params injected as
  JSON literals, never string-concatenated. Rule 7, non-negotiable.
- `human_reviewed` on `MorphPlan` exists — the UI gates on it.

**Must not:** add capability to the sample. A morph changes what the sample
*observes*, inside a sealed VM. Nothing else.

---

### A7. Generative C2 emulation · depends Track C · ~4h · **highest risk, cut first**

The paper's boldest claim and the easiest to do irresponsibly.

- mitmproxy addon; when the sample beacons to a dead C2, the model synthesises a
  response matching the schema M2 found in the parser.
- **Hard bound: the synthesised response must be provably inert.** No URL that
  resolves, no payload the sample could execute, no second stage. A fixed
  allowlist of response *shapes*, model-filled fields, schema-validated before it
  is served. If a synthesised field could be interpreted as a download URL, it is
  replaced with a sink-holed local address.
- Every synthesised response is a ledger node — this is *our* content injected
  into the analysis, and it must be auditable as such.

**Cut criterion:** if the inertness proof is not airtight by the time this comes
up, ship A1–A5 and cut this. It is better absent than sloppy.

---

### A8. Providers + retrieval · independent · ~3h

- Gemini and Anthropic paths in `_dispatch` (currently `NotImplementedError`).
  Anthropic is the sensible default for the code-reading agents.
- Retrieval stays the inlined MITRE cheat-sheet. **Do not build a vector store
  over 21 techniques** — `00_GUIDING_MAP.md` §10 item 7 pre-agreed this cut, and
  machinery without a purpose is a liability in a demo. Revisit only if the KB
  grows past a few hundred entries.

---

## Track B — the reverse-engineering workspace (GUI)

Today `AiTab.tsx` (243 lines) lists claims, techniques and the rejected-claim
count. That is a *verdict* view. Reverse engineering needs a *workspace*: code on
one side, reasoning on the other, evidence linking them.

The API surface is frozen (T0.6) and the artefact-gated pattern
(`ArtefactGate` / `DegradedNotice`) already handles partial and missing data —
keep both.

### B1. `ReverseEngineeringTab` — the centrepiece · depends A1, A2 · ~5h

Three panes:

```
┌──────────────┬────────────────────────────┬──────────────┐
│ CALL PATHS   │  DECOMPILED METHOD         │  REASONING   │
│              │                            │              │
│ ▸ pkg_query  │  public void onCreate() {  │ "Enumerates  │
│   onCreate   │    pm.getInstalled…  ◀──── │  installed   │
│   depth 2 ●  │  }                         │  packages    │
│ ▸ sms_read   │                            │  from a      │
│   receiver   │  ▲ highlighted line is the │  lifecycle   │
│              │    cited evidence          │  entrypoint" │
│              │                            │  ⛓ node 0a3f │
└──────────────┴────────────────────────────┴──────────────┘
```

- Click a claim → the cited line highlights. Click a ledger chip → the evidence
  node opens. **The link between prose and code is the product**; a claim whose
  citation does not resolve renders struck through, not hidden.
- Decompiled code is sample-derived: render as text, never `dangerouslySetInnerHTML`.
  Syntax highlighting via a tokenizer that emits React nodes, not HTML strings.
- Virtualise the code pane; a 4 000-char method is fine but twelve of them are not.

### B2. `StringLab` panel · depends A3 · ~2h

Ciphertext → transform chain → plaintext, with a **"verified by Python"** badge.
Unverified decodings appear greyed with the reason. This panel is the clearest
possible demonstration that the system does not trust its own model.

### B3. Victim profile card · depends A4 · ~2h

Language, tactic, segment, impersonated target, each with evidence chips and a
confidence bar. Absent profile renders "not determined — no UI strings extracted",
never an empty card that reads as "no risk".

### B4. Morph timeline · depends A6 · ~3h

Extends `FrontierTab`'s existing before/after diff into a timeline: what the
sample probed → what was synthesised → what changed in pass 2. The tab already
reconstructs passes from `API_TRACE` ledger nodes; keep that — reading from the
chain rather than a UI cache is the honest source.

Gate the deploy control on `MorphPlan.human_reviewed`, and label a stub-generated
plan as stub — `FrontierTab` already does this and it must survive the rewrite.

### B5. Provenance honesty pass · ~1h

`ProvenanceBadge` already derives live-vs-replay from trace metadata. Extend the
same discipline: every new panel states whether it is showing live, replayed, or
fixture data, read from the artefact — never from a config flag.

---

## Track C — detonation (unblocks A6, A7, B4)

Detailed in `docs/M3_DETONATOR_RUNBOOK.md`. Summarised:

| Task | Est |
|---|---|
| C1. Write `verify_containment.py` CLI around the tested `containment.py` logic | 2h |
| C2. Write `frida_runner.py` (`dynamic_analyze.py` on the VM) | 4h |
| C3. Fix `detonator.pkr.hcl` — it provisions four v1 `backend/scripts/` paths | 30m |
| C4. Build image, apply Terraform, verify no external IP | 1h + ~$0.15 |
| C5. Detonate 20 samples, capture traces | 2h + ~$0.40 |

After C5, every "not detonated" caveat in the evidence pack §9 can be deleted —
and only then.

---

## Sequencing

```
A1 decompile ──┬── A2 interpreter ──┬── A5 disagreement
   (4h)        │      (3h)          │
               ├── A3 strings ──────┤
               │      (3h)          │
               └── A4 victim ───────┘
                      (3h)              ──▶ B1 workspace (5h)
                                            B2 stringlab (2h)
                                            B3 victim card (2h)

C1 ─ C2 ─ C3 ─ C4 ─ C5  ──▶ A6 elicitor ──▶ B4 morph timeline
(9h + ~$1)                    (4h)              (3h)
                              A7 C2 emulation (4h, cut candidate)

A8 providers (3h) — independent, any time
```

**Critical path to the strongest demo: A1 → A2 → A3 → B1 → B2.** About 17 hours,
no GCP spend, no detonation dependency, and it converts the paper's weakest claim
("reconstructs the malware's logic") into something you can put on screen.

Track C in parallel if there is a second pair of hands — it is mostly waiting on
image builds.

### If time runs short, cut in this order

1. **A7 C2 emulation** — highest risk, needs the inertness proof done properly
2. **A8 Gemini/Anthropic** — OpenRouter already works
3. **B4 morph timeline** — `FrontierTab` already shows the pass diff
4. **A5 disagreement** — figure 06 already discloses the finding honestly

Never cut A1. Everything else in Track A is narration without it.

---

## Rules that do not move

Restating what this roadmap must not quietly erode:

1. **The LLM never emits the score.** A2, A3 and A4 add prose and structured
   fields. `B` still comes from the Python weight table.
2. **Every claim cites a resolvable node** or `ledger.append()` rejects it. The
   rejection count stays a headline number in the UI, not a footnote.
3. **Decompiled code is the most attacker-controlled input in the system.**
   `<untrusted_artifact>`, XML-escaped, user turn only. Never concatenated into a
   system prompt, never rendered as markup.
4. **Morph params are validated before they reach adb or JS**, injected as JSON
   literals.
5. **Budgets are asserts:** ≤25 LLM calls/job, ≤12k prompt tokens, ≤90 s static.
   A1 and A2 both push on these — assert, do not hope.
6. **A sample that produced no observations is inconclusive, never benign.**
7. **Nothing claims detonation until Track C actually detonates.**

---

## Definition of done

- `make test` green, contract tests still the CI gate
- The canary walks end-to-end and produces: a decompiled method, a verified string
  decoding, a victim profile, and a workspace view linking all three to ledger nodes
- `docs/PROTOTYPE_REPORT_EVIDENCE.md` §9 shrinks — each removed line replaced by a
  measurement
- No number in the UI or report that cannot be traced to a measurement
