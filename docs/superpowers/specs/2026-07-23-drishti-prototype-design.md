# DRISHTI Prototype — Design Specification

**Date:** 2026-07-23
**Team:** DRISHTI — Ayusha Hongekar, Shivam Soni, Vedant Moghe
**Competition:** FinShield / CyberShield prototype track
**Status:** Approved scope — MVP vertical slice

---

## 1. Overview & Goals

DRISHTI (Dynamic Reasoning & Interrogation System for Heuristic Threat Identification) is a
GenAI-native, defence-in-depth pipeline that triages suspicious Android APKs for financial-fraud
malware. This spec covers the **prototype**: a real, working implementation of Phase 0 + Phase 1
from the paper's roadmap (Figure 5), with the adversarial "frontier" (Section 6) implemented as
real interfaces backed by a **safe, simulated executor** — never live malware detonation.

The prototype must deliver two things:

1. **Working software** — an APK upload → static analysis → ML → GenAI reasoning → calibrated
   scoring → evidence ledger → dashboard pipeline that a judge can actually run and click through.
2. **FinShield prototype paper** — the DRISHTI prototype writeup formatted into `Template.tex`
   (2-column `spconf` IEEE style), compiled to PDF.

### Success criteria

- A user uploads an APK and, within seconds, sees a calibrated 0–100 threat score with a severity
  band, a human-readable investigation report, a MITRE Mobile ATT&CK mapping, extracted IOCs,
  auto-generated YARA rules, and a browsable evidence ledger where every GenAI claim links to a
  concrete artifact.
- Every scoring number and every GenAI sentence traces to a signed ledger node (anti-hallucination).
- The whole pipeline runs end-to-end with **zero live malware execution**.
- The system degrades gracefully: with no Gemini key it runs a mock reasoning provider; with no
  AndroZoo data it runs a bundled baseline ML model.

---

## 2. Scope

### In scope (built real)
- **M1 Ingestion & Triage** — upload, SHA-256 + `dexofuzzy` fuzzy hashing, split-APK reassembly,
  threat-intel fast-pass against a known-bad hash list.
- **M2 Static Analysis** — Androguard-based manifest/permission/component/intent parsing,
  certificate & over-privilege analysis, IOC extraction (URLs, IPs, crypto addresses), a static
  call-graph, and permission-combination risk features.
- **M5 ML Classification** — multi-label XGBoost/LightGBM over tabular features + Platt (sigmoid)
  probability calibration producing `P_cal`. (GNN / Sequence-Transformer / Opcode-Image CNN are
  documented interfaces + roadmap, not trained in the prototype.)
- **M4 GenAI Reasoning Core** — a pluggable LLM provider (Gemini implementation) driving four
  agents (Code Interpreter, Technique Mapper, Social-Engineering Analyst, Verifier) with RAG over a
  MITRE Mobile ATT&CK store, a strict JSON output contract, and prompt-injection defenses.
- **M6 Composite Risk Scoring** — the exact formulas from paper §4.6 (`S`, `F_AI`, `C`), severity
  bands, and the confirmed-malicious-hash override.
- **M7 Reporting & Threat Intelligence** — report assembly, MITRE mapping, auto-generated YARA
  rules and Frida hook scripts, STIX 2.1 export.
- **Evidence Ledger** — append-only, hash-chained, Ed25519-signed directed graph with the paper's
  node schema and a verifier gate for GenAI claims.
- **API** — FastAPI endpoints for analysis, report retrieval, ledger retrieval, sample listing.
- **Frontend** — React/Next dashboard: upload, score gauge, report, MITRE grid, evidence-ledger
  graph, IOC list, YARA viewer.
- **Paper** — FinShield template filled and compiled to PDF.

### In scope (built real, pending user-supplied secrets/data)
- Gemini reasoning core — needs `GEMINI_API_KEY` + `GEMINI_MODEL`; runs mock provider until set.
- AndroZoo-trained ML model — needs `ANDROZOO_API_KEY` + a sample list; ships with a bundled
  baseline model + pre-extracted feature set so the demo scores out of the box.

### Out of scope for the prototype (real interface + simulated executor, clearly labeled)
- **M3 live dynamic detonation**, Generative C2 emulation, JIT bespoke sandbox synthesis, Frida
  live instrumentation, physical bare-metal device farm. The `sandbox` module exposes the real
  interface and a synthetic-behavior generator that produces plausible, clearly-labeled simulated
  traces (e.g., "simulated: OTP exfil to synthetic C2") so the pipeline runs end-to-end. The UI and
  paper both label these as *designed, simulated in prototype*.

### Explicitly not doing
- No execution of real malware, ever.
- No distribution of any offensive artifacts beyond defensive YARA/Frida/STIX for the analyzed sample.
- No autonomous enforcement — DRISHTI is decision-support; consequential actions require a human.

---

## 3. Tech Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Backend | Python 3.11+, FastAPI, Uvicorn | Analysis tooling (Androguard, YARA, ML) is Python-native |
| Static analysis | Androguard, yara-python | Manifest/DEX parsing, signature scanning |
| Hashing | hashlib (SHA-256), dexofuzzy | Exact + fuzzy variant clustering |
| ML | scikit-learn, xgboost/lightgbm, numpy, pandas | Tabular multi-label + Platt calibration |
| GenAI | google-genai SDK (Gemini) via pluggable interface | User-supplied Gemini 3.1 Pro preview key |
| RAG | local embeddings (sentence-transformers) + in-memory / Chroma vector store | Avoids a second cloud key; MITRE corpus is small |
| Ledger crypto | cryptography (Ed25519), hashlib | Hash-chain + signatures |
| Reporting | custom + stix2 library | STIX 2.1 export |
| Frontend | Next.js (React, TypeScript), Tailwind | Polished, deployable dashboard |
| Packaging | Docker + docker-compose | One-command run for judges |
| Tests | pytest (backend), vitest/RTL (frontend) | TDD on formulas, ledger, analyzers |

---

## 4. Repository Layout

```
drishti/
  backend/
    drishti/
      __init__.py
      config.py                 # env-driven settings (keys, model ids, paths)
      models.py                 # pydantic schemas: EvidenceNode, Verdict, Report, FeatureVector...
      ingestion/                # M1
      static/                   # M2
      ml/                       # M5
      genai/                    # M4 (agents, rag, verifier)
      sandbox/                  # M3 (interface + simulated executor)
      scoring/                  # M6
      ledger/                   # evidence ledger
      reporting/                # M7 (report, yara_gen, frida_gen, stix_export)
      pipeline/                 # orchestrator
      llm/                      # provider interface + gemini + mock
      api/                      # FastAPI app + routes
      data/                     # yara rules, mitre store, known-bad hashes, sample metadata
    tests/
    pyproject.toml
    Dockerfile
  frontend/
    app/                        # Next.js app router
    components/
    lib/
    package.json
    Dockerfile
  paper/
    finshield_drishti.tex       # from Template.tex, filled
    (reuses image1/3/4, spconf.sty, IEEEbib.bst, refs.bib)
  docker/
    docker-compose.yml
  docs/superpowers/specs/
  README.md
```

---

## 5. Data Schemas

### 5.1 Evidence Ledger Node (paper §5)
```
EvidenceNode {
  id: str                 # stable, content-addressed or sequential "n<k>"
  type: str               # "manifest" | "cert" | "api_sink" | "ioc" | "ml_signal"
                          #  | "genai_claim" | "dynamic_obs" | "score_factor" | "mitre_tag"
  source_tool: str        # "androguard" | "yara" | "xgboost" | "gemini" | "sandbox_sim" ...
  content: str            # human-readable statement / value
  location: str | null    # "manifest#L42", "c.a.d.h()", "run#7", "proxy_pcap#22"
  confidence: float       # 0..1
  timestamp: str          # ISO-8601 (injected, deterministic per run)
  refs: list[str]         # ids of nodes this node cites (edges)
  prev_hash: str          # hash of previous node (chain)
  hash: str               # H(prev_hash || canonical(this node w/o hash))
}
Ledger { nodes: [...], signature: str (Ed25519 over final hash), pubkey: str }
```
Append-only. Agents may only append. Every downstream artifact (GenAI sentence, score factor,
MITRE tag) references ≥1 node id. The **Verifier** rejects any GenAI claim whose cited node ids do
not exist.

### 5.2 Verdict (paper Listing 2)
```
Verdict {
  sha256: str
  threat_score: int          # 0..100
  severity_band: "Critical"|"High"|"Medium"|"Low"
  confidence: "High"|"Medium"|"Low"  (derived from C in [0,1])
  confidence_value: float
  impersonated_target: str | null      # e.g. "SBI"
  victim_profile: { language, tactic, segment }
  adversarial_elicitation_deployed: [str]   # e.g. "Generative_C2_Emulation" (simulated)
  attack_techniques: [str]                  # MITRE ids, e.g. "T1582","T1417","T1521"
  iocs: { c2: [str], urls: [str], addresses: [str], hashes: [str] }
  evidence_refs: [str]                      # ledger node ids
}
```

### 5.3 Feature Vector (M5 input)
Tabular: permission one-hot bitmap, permission-combo flags, requested-vs-used permission delta,
dangerous-API call counts, exported-component counts, intent-filter counts, cert features
(self-signed age, reuse flag, brand-mismatch flag), opcode histogram summary. Multi-label targets:
`{banker, spyware, dropper, overlay, sms_fraud, benign}`.

---

## 6. Composite Scoring (paper §4.6 — implemented exactly)

```
Signal groups & weights:
  R   = reputation/threat-intel   w_R   = 0.25
  F_AI= fused ML & GenAI intel    w_AI  = 0.50
  G   = signature severity (YARA) w_G   = 0.15
  D   = static+dynamic drift      w_D   = 0.10

F_AI = P_cal + B - (P_cal * B)          # joint prob, non-mutually-exclusive
S    = 100 * min(1, w_R*R + w_AI*F_AI + w_G*G + w_D*D)
C    = gamma * (1 - |P_cal - B|)        # gamma = evidence-completeness factor in [0,1]

Override: confirmed malicious hash  =>  S = 100, C = 1.0

Severity bands:
  85-100 Critical  -> Block; push IOCs; notify customers
  65-84  High      -> Quarantine; fast-track analyst
  40-64  Medium    -> Analyst review; monitor indicators
  0-39   Low       -> Log for baseline/correlation

Meta-check: severe qualitative disagreement lowers C (never silently alters S) and logs an
analyst-review flag node in the ledger.
```
Where `P_cal` = calibrated ML maliciousness probability (M5), `B` = GenAI behavioural risk from the
(simulated) dynamic interrogation. All consequential actions require explicit human confirmation.

---

## 7. Module Contracts

Each module is a pure-ish function/class with typed inputs/outputs, writes evidence nodes via the
ledger, and is independently testable.

- **M1 `ingestion`**: `ingest(file) -> ApkBundle{path, sha256, dexofuzzy, splits[], intel_hit}`.
  Reassembles split APKs; runs known-bad-hash fast pass; appends `ingest` nodes.
- **M2 `static`**: `analyze(bundle) -> StaticResult{manifest, permissions, combos[], components[],
  certs, over_privilege[], iocs, call_graph, yara_hits[]}`. Uses Androguard + yara-python; appends
  `manifest`/`cert`/`api_sink`/`ioc` nodes.
- **M5 `ml`**: `predict(features) -> MlResult{labels{...}, p_cal, top_features[]}`. XGBoost +
  Platt; appends `ml_signal` nodes.
- **M3 `sandbox`** (simulated): `interrogate(bundle, hypotheses[]) -> DynamicResult{observations[],
  B, simulated: true}`. Synthetic-behavior generator keyed off static hypotheses; appends
  `dynamic_obs` nodes flagged `simulated`.
- **M4 `genai`**: `reason(static, ml, dynamic, ledger) -> Verdict` via agents over RAG; Verifier
  enforces node citations; appends `genai_claim` + `mitre_tag` nodes. Provider is pluggable.
- **M6 `scoring`**: `score(R, p_cal, B, G, D, override) -> {S, C, band}`. Appends `score_factor`
  nodes. Pure, fully unit-tested.
- **M7 `reporting`**: `report(verdict, ledger) -> {summary, findings, mitre, iocs, yara[], frida[],
  stix}`. Generates defensive artifacts for the analyzed sample only.
- **`pipeline`**: orchestrates M1→M7 through the ledger; the entry point behind `POST /analyze`.

---

## 8. GenAI Core (Gemini)

- **`llm.LLMProvider`** interface: `generate(system, user_data) -> str`,
  `generate_json(system, user_data, schema) -> dict`. Implementations: `GeminiProvider`
  (google-genai, model + key from env), `MockProvider` (deterministic canned responses for
  tests/offline demo).
- **Agents**: Code Interpreter (explains decompiled methods, renames obfuscated symbols),
  Technique Mapper (behavior → MITRE), Social-Engineering Analyst (UI/SMS language → victim
  profile), Verifier (mechanically checks each claim cites an existing ledger node).
- **RAG**: local embeddings over a MITRE Mobile ATT&CK corpus + known-family write-ups + C2 schema
  notes. Retrieved context grounds explanations before generation.
- **Prompt-injection defense**: decompiled code and extracted strings are passed as clearly
  delimited **untrusted data**, never concatenated into system instructions; a strict JSON schema
  is enforced on output; the Verifier drops any unverifiable line. This directly implements paper
  §4.4.6.
- **Structured output**: terminates in the §5.2 Verdict JSON.

---

## 9. ML Design (M5)

- Prototype model: multi-label **XGBoost** (one calibrated binary head per label) over the §5.3
  tabular feature vector; **Platt/sigmoid calibration** so `P_cal=0.8` means ~80% empirical
  precision.
- Multi-label (sigmoid per class), not softmax — a sample can be banker + spyware + dropper + overlay.
- Class imbalance via `scale_pos_weight` / focal-style weighting.
- Training pipeline: `androzoo_ingest` (needs key) → `extract_features` → `train` → `calibrate` →
  serialized model in `data/models/`. Ships with a bundled baseline model trained on a small
  pre-extracted feature set so the demo works with no AndroZoo access.
- GNN / Sequence Transformer / Opcode-Image CNN: documented interfaces + roadmap only.

---

## 10. Evidence Ledger

- Append-only list of `EvidenceNode`. Each node's `hash = sha256(prev_hash || canonical_json(node
  without hash))`; genesis `prev_hash = "0"*64`.
- On finalize, sign the last hash with an Ed25519 key (`LEDGER_SIGNING_KEY` env, generated per-run
  if absent) and store `signature` + `pubkey`.
- `verify(ledger)` re-walks the chain and checks the signature → reproducibility guarantee.
- **Verifier gate**: `verify_claim(claim, ledger)` returns PASS only if every cited node id exists;
  else REJECT (claim excluded from the report). Implements paper Figure 4.

---

## 11. API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/analyze` | multipart APK upload → runs pipeline → returns `{analysis_id, verdict}` |
| GET | `/report/{id}` | full report (summary, findings, MITRE, IOCs, YARA, Frida, STIX) |
| GET | `/ledger/{id}` | evidence ledger graph (nodes + edges) + verification status |
| GET | `/samples` | list bundled sample APKs available to analyze |
| POST | `/analyze/sample/{name}` | analyze a bundled sample |
| GET | `/healthz` | liveness + which providers are live vs mocked |

Responses are the pydantic schemas in §5. Long analyses stream status; prototype runs synchronously
(static + ML + GenAI complete in seconds; simulated dynamic adds a bounded delay).

---

## 12. Frontend (Dashboard)

Views (Next.js app router):
- **Upload / Samples** — drag-drop APK or pick a bundled sample.
- **Verdict** — animated 0–100 score gauge, severity band, confidence, impersonated target,
  victim profile.
- **Report** — executive summary + technical findings, each finding hyperlinked to its ledger node.
- **MITRE grid** — detected techniques (Table 6) highlighted with detection layer.
- **Evidence Ledger** — interactive node/edge graph; click a node to see source tool, content,
  location, confidence; verification badge (chain valid + signed).
- **IOCs & Artifacts** — IOC list, generated YARA rule(s), Frida script(s), STIX download.
- Provider status banner ("Gemini: live / mocked", "ML: AndroZoo / baseline", "Sandbox: simulated").

---

## 13. Configuration & Secrets (env)

| Var | Purpose | Fallback |
|-----|---------|----------|
| `GEMINI_API_KEY` | Gemini auth | MockProvider |
| `GEMINI_MODEL` | model id (e.g. gemini-3.1-pro-preview) | required if key set |
| `ANDROZOO_API_KEY` | AndroZoo downloads | bundled baseline model |
| `LEDGER_SIGNING_KEY` | Ed25519 private key (hex) | generated per run |
| `EMBEDDINGS_MODEL` | local sentence-transformers model | small default |

Secrets never logged; `.env.example` documents all vars; real `.env` is gitignored.

---

## 14. Security & Safety (non-negotiable)

- **Never detonate APKs.** The dynamic sandbox is simulated; no real execution path exists in the
  prototype. This is enforced structurally (no Frida/emulator runner is wired), not just by policy.
- Uploaded APKs are stored in an isolated working dir, analyzed statically only, and are not executed.
- Decoy/synthetic data only in any simulated interrogation; nothing reaches a real network endpoint.
- Generated artifacts are **defensive** (YARA/Frida-for-analysis/STIX) and scoped to the analyzed
  sample; no offensive tooling is produced.
- AndroZoo/research datasets used within their licensing terms; credentials via env only.
- Human confirmation required before any consequential action; DRISHTI is decision-support.

---

## 15. Testing Strategy (TDD)

- **Scoring (M6)**: unit tests for `F_AI`, `S`, `C`, band boundaries (39/40, 64/65, 84/85), and the
  confirmed-hash override. Written before the implementation.
- **Ledger**: hash-chain integrity, tamper detection, signature verify/roundtrip, verifier-gate
  accept/reject.
- **Static (M2)**: fixtures — small crafted benign APKs with known manifests; assert permission
  combos, over-privilege, IOC extraction.
- **GenAI (M4)**: MockProvider; assert Verdict schema validity, verifier rejects fabricated
  citations, prompt-injection strings do not alter control flow.
- **Pipeline**: integration test on a bundled sample end-to-end producing a valid Verdict + verified
  ledger.
- **Frontend**: component tests for score gauge, ledger graph, provider banner.

---

## 16. Build Sequence (milestones)

0. **Scaffold** — repo, config, pydantic schemas, docker-compose, git init, CI-free test harness.
1. **Ledger + Scoring** (pure, TDD first) — the trust spine and the number.
2. **M1 + M2** — ingestion + Androguard static analysis + YARA + IOC + features.
3. **M5** — feature extraction + baseline XGBoost + calibration (AndroZoo pipeline wired, baseline
   bundled).
4. **M4** — LLM provider interface + Mock + Gemini + agents + RAG + Verifier.
5. **M3 (simulated)** — synthetic-behavior generator producing `B` and dynamic nodes.
6. **M6 wiring + M7** — full composite score + report + MITRE + YARA/Frida/STIX generation.
7. **API + pipeline orchestrator** — `/analyze` end-to-end.
8. **Frontend** — dashboard against the API.
9. **Sample data** — bundle safe samples; AndroZoo ingestion documented/tested.
10. **Paper** — fill FinShield template, add prototype figures/screenshots, compile PDF.
11. **End-to-end demo pass** — docker-compose up; upload → verdict → ledger; write README + demo script.

---

## 17. Needed From User (non-blocking; build proceeds with fallbacks)

- `GEMINI_API_KEY` + exact `GEMINI_MODEL` string for the live reasoning core.
- `ANDROZOO_API_KEY` + a sample list (or a small labeled APK set) to train the real ML model.
- Confirmation of the paper's title/venue name (template says "FinShield", folder says "CyberShield").
- Submission deadline (affects how deep the frontier simulation and paper polish go).

---

## 18. Open Questions

- Exact Gemini preview model string and whether it supports the JSON/structured-output mode
  (affects how strictly the output contract is enforced vs. post-validated).
- Whether the competition wants the dashboard deployed (public URL) or just runnable locally via
  docker-compose.
