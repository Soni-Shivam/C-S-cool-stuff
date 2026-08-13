# PHASE 6 — M7 REPORTING, DASHBOARD & DEMO

**Window:** H50 → H72 · **Owner:** Track B (report/artefacts) + Track C (UI), all hands from H64
**Depends on:** everything
**Exit criteria:** three consecutive clean rehearsals of the 6-minute demo, a backup
video, and a frozen tag.

> Judging is not a code review. A working system that is illegible on a projector
> loses to a weaker system that is legible. The last 22 hours are where the previous
> 50 either become a win or stay a repo.

---

## T6.1 — YARA generation (H50 → H52) · Track B

Auto-generate a rule from the evidence, not from an LLM's imagination. Deterministic
extraction, optional LLM polish for the comment block only.

```python
def generate_yara(static, dynamic, genai, ledger) -> str:
```

**Rule components, in priority order:**
1. **Distinctive strings** — C2 URLs, unusual package-name constants, crypto
   transform strings, error/log strings. Filter aggressively: drop anything present
   in a benign-corpus string frequency table (build one from 200 F-Droid APKs —
   30 minutes, and it's the difference between a rule that fires on half of
   Google Play and one that means something).
2. **Certificate sha256** — one condition, catches all identically-signed variants.
   High-value for campaign hunting.
3. **DEX structural hints** — class name patterns (`c.a.d.*`), distinctive method
   name sequences.
4. **Manifest hints** — the exact permission set, distinctive component names.

```yara
rule DRISHTI_Auto_{{ family_or_sha8 }} {
  meta:
    author = "DRISHTI automated triage"
    date = "{{ date }}"
    sample_sha256 = "{{ sha256 }}"
    threat_score = "{{ S }}"
    confidence = "{{ C }}"
    description = "{{ one_line_from_genai_summary }}"
    mitre = "{{ techniques | join(',') }}"
    evidence = "{{ ledger_node_ids | join(',') }}"      // ← provenance in the rule
  strings:
    $c2_1 = "{{ c2_host }}" ascii wide
    $s_1  = "{{ distinctive_string }}" ascii
    $cls  = "{{ class_pattern }}" ascii
  condition:
    uint32(0) == 0x04034b50 and 2 of ($s_*, $c2_*, $cls)
}
```

The `evidence` meta field is a small idea with real weight: **the generated
detection rule cites the ledger nodes that justified each string.** No other tool's
auto-generated rules carry provenance. Mention it.

**Validate the rule compiles** (`yara.compile(source=rule)`) before serving it, and
**test it against the sample** (must match) **and against 20 benign APKs** (must not
match). If it matches a benign, tighten the condition and retry, up to 3 times.
Report the FP-test result in the UI: *"rule validated: matches sample, 0/20 benign
false positives."* That line is worth more than the rule itself.

---

## T6.2 — STIX 2.1 export (H52 → H53) · cut-listed

`stix2` library. Bundle: `Indicator` (the YARA pattern), `Malware` (family, if
attributed), `AttackPattern` refs (the MITRE techniques), `File` (sha256),
`DomainName`/`URL` observables, `Relationship` objects tying them together.

If `stix2` fights you for more than 40 minutes, ship a plain JSON IOC export
instead (`{hashes, domains, urls, certs, yara}`) and say so. Nobody at a hackathon
is going to ingest your TAXII feed; the point is demonstrating that the output is
machine-consumable.

---

## T6.3 — HTML report (H53 → H56) · Track B

Jinja template → single self-contained HTML (inline CSS, inline base64 images) so
it downloads as one file and opens anywhere.

**Sections, in this order** — it's the analyst's reading order, not the pipeline's:

1. **Header** — filename, sha256, package, timestamp, analysis duration.
2. **Verdict** — big score, band, confidence, and the one-paragraph deterministic
   explanation from M6.
3. **Executive summary** — the GenAI 3–5 sentences. Every sentence carries a
   superscript evidence link.
4. **What this app does** — verified claims grouped by behaviour tag, each with
   evidence chips.
5. **Who it targets** — victim profile, impersonation match with the icon
   side-by-side, target language, tactic.
6. **How it evaded, and how we responded** — the frontier section: probes observed,
   morphs synthesised, detonation result, before/after diff. *This section is the
   product.* Put it above the technical appendix, not buried in it.
7. **Score breakdown** — the four factors as a table with weights and
   contributions, summing visibly to `S`.
8. **MITRE ATT&CK mapping** — grid, detected cells highlighted.
9. **IOCs** — hashes, domains, URLs (defanged), certificates.
10. **Detection artefacts** — the YARA rule, the Frida scripts that produced the
    findings, download links.
11. **Recommendations** — from the band's proposed actions, each marked
    "requires analyst confirmation".
12. **Evidence appendix** — the full ledger as a table: seq, type, source, location,
    hash prefix. Plus the chain-verification result and the public key.
13. **Limitations** — auto-generated and honest: which stages degraded, whether the
    sandbox ran live or replayed, whether the trace was composite, how many claims
    the Verifier rejected, whether the model was trained on time-split data.

**Section 13 is not optional and not a weakness.** A report that states its own
limitations is what a bank's compliance function actually requires, and it is what
separates a security product from a demo. Generate it from real flags in the data,
so it can't drift out of sync with reality.

PDF: `weasyprint` if it installs cleanly in 15 minutes; otherwise browser
print-to-PDF and move on. HTML is the deliverable.

---

## T6.4 — Dashboard completion (H50 → H64) · Track C

Build against the endpoints frozen in P0. Seven tabs:

**Overview** — score ring (animates on preliminary→final), factor bars, verdict
sentence, behaviour tag chips, top-3 findings, proposed actions with confirm
buttons.

**Static** — permission table with combos highlighted, component list with export
status, certificate card with brand-mismatch callout, packer badges, call-path
tree (collapsible, with AI-renamed symbols shown beside obfuscated names).

**AI** — claims list, each with evidence chips that navigate to the Ledger tab
filtered to that node. Rejected-claim count badge. MITRE grid. Victim profile card.
Icon comparison. LLM call count and cache-hit count.

**Sandbox** — API timeline (a horizontal scrollable event track is far more
readable than a table), network flow list with request/response bodies, dropped
files, screenshots, logcat tail.

**Frontier** — the four sections from `PHASE_5 §T5.7`. The before/after diff is the
centrepiece.

**Ledger** — sortable table of all nodes; filter by type and source tool; click any
row to expand raw content; a **"Verify chain"** button that runs verification live
and shows a green banner with the node count. Plus a small **"Tamper demo"** button
(dev-mode only) that corrupts a node and re-verifies to show red. Four seconds,
enormously persuasive.

**Report** — embedded HTML report + download buttons for HTML, YARA, STIX, ledger
JSON.

**Cross-cutting UI must-haves:**
- Live log panel, always visible, throttled render (~150ms/line).
- Every evidence chip is a link. **Test the click path** upload→score→factor→
  ML→SHAP→permission combo→manifest line. If any hop is broken, the central
  claim of the project is unverifiable on stage.
- Stage progress strip across the top showing the 13 pipeline stages with
  timings — makes the "<5 min preliminary, deep analysis async" claim visible
  rather than asserted.
- Dark theme, generous type sizes. Assume a washed-out projector and a judge
  three metres away. Test it on an actual external display before H68.

---

## ★ INTEGRATION-3 — H64, hard 2-hour stop, all hands

Full clean-room run: `python scripts/demo_reset.py` (wipe DB, clear job state,
**keep** the LLM cache), restart everything, run the complete demo path three times.

- [ ] Upload → preliminary verdict < 3 min
- [ ] Full run including frontier < 15 min
- [ ] No 500s, no unhandled exceptions in the log
- [ ] Ledger verifies; tamper demo shows red
- [ ] Every evidence chip resolves
- [ ] YARA compiles, matches the sample, 0/20 benign FPs
- [ ] Report downloads and opens standalone
- [ ] Limitations section is accurate
- [ ] Works on the actual demo laptop, on the venue's display, on battery

Log every bug found. Triage into: **demo-path blocker** (fix now), **visible but
survivable** (fix if time), **invisible** (do not touch).

---

## T6.5 — Code freeze @ H68

`make freeze`. After this: **no new features, no refactors, no dependency changes.**
Only demo-path blockers, and only with a second person watching the diff.

Every hackathon has a story about the feature added at hour 71 that broke the demo
at hour 72. Do not generate that story.

---

## T6.6 — Demo script (H64 → H70) · rehearse aloud, with a timer

Assign roles: **one driver** (hands on keyboard, says nothing), **one narrator**
(talks, never touches the machine), **one on Q&A and backup**. Splitting driving
from narrating is the highest-leverage demo decision available and almost nobody
does it.

**Beat sheet — 6 minutes:**

| Time | Beat | Line to say |
|---|---|---|
| 0:00 | The story | "A retail customer installs a KYC app from a WhatsApp link. It was scanned. It was marked clean. Her account is empty an hour later." |
| 0:30 | The gap | "It was clean because it was asleep. It only wakes up on a device that has her bank's app installed. Every sandbox that ever ran it looked like the wrong victim." |
| 1:00 | Upload | *(driver uploads)* "This is that class of sample." |
| 1:30 | Preliminary verdict | "Static and ML in under 40 seconds. Score 61, MEDIUM — and notice the confidence: 0.44. It's telling us it isn't sure yet, and it's right." |
| 2:00 | Evidence drill-down | *(click F_AI → P_cal → SHAP → permission combo → manifest line)* "Every point of that score traces to an artefact. Nothing here is an opinion." |
| 2:45 | GenAI | "It read the code the way an analyst would — and renamed the obfuscated methods. Three claims were rejected for insufficient grounding; we show that count rather than hiding it." |
| 3:15 | **The stall** | "First sandbox pass. Watch. …Nothing. It ran, it did nothing, it exited. This is where every other tool stops and writes 'benign'." |
| 3:45 | **The frontier** | "But it didn't do nothing — it asked a question. It asked whether the SBI app was installed, got no, and went to sleep for 3.2 seconds. Our model reads that and synthesises the exact victim this sample is hunting for." |
| 4:15 | **Detonation** | *(pause, let the log run)* "There it is. Overlay added. Second stage loaded. Exfiltration POST captured. Score 61 to 92. Confidence 0.44 to 0.86." |
| 5:00 | Trust | *(Verify chain → green; tamper → red)* "Every claim is hash-chained and signed. Change one byte and the chain breaks at the exact node." |
| 5:30 | Output | "YARA rule, auto-generated, validated against 20 benign apps. The SOC hunts the whole campaign, not this one file. And nothing is blocked without a human clicking confirm." |
| 6:00 | Close | "Every other system classifies an APK. DRISHTI interrogates it." |

**Rehearse three times.** Time each. Cut whatever pushes past 6:00 — almost always
the static tab, which is the least differentiated screen you have.

---

## T6.7 — Backup plan (H68 → H70) · do this before you sleep

1. **Screen-record a full successful run** with narration. If anything at all fails
   live, you play the video and keep talking. Non-negotiable.
2. Screenshot every tab at its best state into `docs/screenshots/`.
3. Pre-warm the LLM cache for the demo sample, then verify the run is fast.
4. Export a finished report for the demo sample and keep it open in a browser tab.
5. Second laptop with the repo cloned and running, or at minimum the video.
6. Assume no venue Wi-Fi: the LLM cache makes the run work offline. **Verify this
   by turning Wi-Fi off and running it.** Do it once, for real.

---

## T6.8 — Q&A preparation (H70 → H71)

Write one-sentence answers and read them aloud once. The honest answers are the
strong ones — every question below has a good answer available.

| Question | Answer |
|---|---|
| "Is the sandbox live or replayed?" | Whichever is true, said plainly, with the reason. Never hedge. |
| "How do you know the LLM isn't hallucinating?" | Two mechanisms: it can't emit the score, and the Verifier rejects any claim not bound to a ledger node. We show the rejection count. |
| "What's your false-positive rate?" | The time-split test number. If you only have random-split, say so and explain why the gap matters. |
| "Prompt injection?" | Structural separation, schema jail, the score path is LLM-free, and we report injection attempts as findings. There's a test. |
| "Could this be misused offensively?" | It analyses inside an isolated VM, generates only detection artefacts, serves only inert content, and requires human confirmation for every action. |
| "Why not just use MobSF/VirusTotal?" | They're excellent at Level 1. Neither one interrogates a sample that refuses to run. |
| "What did you actually train?" | The real answer, with the dataset, the split, and the metric. |
| "What doesn't work yet?" | Have three specific answers ready. Volunteering limitations before being asked is the strongest available move, and it's true besides. |
| "How long did the deep analysis take?" | The measured number from the stage timing strip, not the number from the paper. |

---

## T6.9 — Final hour (H71 → H72)

- [ ] `git tag v1.0-demo` and push
- [ ] README: what it is, how to run, what's real, what's stubbed
- [ ] `STATUS.md` finalised — it is the technical appendix
- [ ] Laptop charged, brightness up, notifications off, terminal font 18pt+
- [ ] Demo sample staged, cache warm, DB reset
- [ ] Video on the desktop, one click away
- [ ] Everyone has eaten and slept at least a little

---

## Phase 6 Definition of Done

- [ ] YARA generated, compiled, validated against sample + 20 benign
- [ ] STIX or JSON IOC export
- [ ] Self-contained HTML report with all 13 sections incl. auto-generated
      limitations
- [ ] Seven-tab dashboard; every evidence chip resolves
- [ ] Live chain verification + tamper demo in the UI
- [ ] Human-confirmation gate on every consequential action
- [ ] INTEGRATION-3 green three times consecutively
- [ ] Code frozen at H68
- [ ] Demo rehearsed 3× under 6 minutes with split driver/narrator
- [ ] Backup video recorded; offline run verified
- [ ] Q&A answers written and read aloud
- [ ] `git tag v1.0-demo`
