# `ui/` — DRISHTI dashboard

Vite + React + TypeScript + Tailwind, per `docs/PHASE_0_FOUNDATIONS.md` T0.8, built
against the route surface frozen in T0.6.

```bash
make ui-install      # once
make up              # terminal 1 — the API on :8080
make ui              # terminal 2 — the dashboard on :5173
```

For the demo, run the production build instead — it is faster to paint and it is
the thing that will actually be on screen:

```bash
make ui-preview      # builds, then serves on :4173
```

Both `dev` and `preview` proxy `/api` to `http://127.0.0.1:8080`. Override with
`DRISHTI_API_ORIGIN` if the API is elsewhere. Nothing is served by FastAPI: the
frozen route surface has no UI mount, and adding one would put a non-`/api` route
into a file whose whole point is that its routes do not move.

## Layout

Four regions (T0.8) plus the stage strip (T6.4):

```
header: identity · drop APK · job id + live badge
stage strip: 11 pipeline stages, timings, VERDICT ▸ async marker at SCORE_PRELIM
├── score rail: ring, band, C, γ, R/F_AI/G/D factor bars, limitations
└── tabs: Overview · Static · AI · Sandbox · Frontier · Ledger · Report
live log: tailed from GET /api/logs/stream, throttled ~150 ms
```

## What this code will not do

The dashboard is the surface where an overclaim is most likely to reach a human, so
four rules are enforced by construction rather than by review:

1. **No number is computed here.** `S`, `C`, `γ` and every factor contribution are
   rendered exactly as `m6_score/engine.py` emitted them. A second implementation in
   TypeScript would be a second answer to "how did you get 92?".
2. **The provenance badge is derived from the trace, not from config.**
   `ProvenanceBadge` takes a `DynamicTrace` and nothing else, and distinguishes
   LIVE / REPLAY / SYNTHETIC / NO TRACE. There is no prop that lets a caller tell it
   what to say.
3. **A missing artefact is never drawn as an empty one.** `ArtefactGate` preserves
   the API's two conventions: 404 `not_produced_yet` renders as pending-with-stage,
   501 `not_implemented` renders as "not available in this build" naming the owning
   task. Collapsing them would make an unbuilt feature look like a slow one.
4. **`inconclusive` is never softened into benign,** and `partial`/`errors` from any
   `AnalyserResult` are surfaced wherever that module is displayed.

## Known gap

T6.4 also asks for a dev-only "tamper demo" button beside chain verification. It is
not built: the ledger is append-only in SQL via triggers, so no API call can corrupt
a node, and simulating the red banner client-side would prove nothing about the
mechanism it claims to demonstrate. Building it honestly needs a dev-mode backend
endpoint that writes directly to the SQLite file. The Ledger tab says so on screen.

## Editing `src/api/types.ts`

Hand-written mirrors of `drishti/contracts/`. The rule: a field here must exist in
the pydantic model. If a contract changes, change this file in the same commit —
`extra="forbid"` on the Python side means a typo is an error there, and there is no
equivalent guard on this side.
