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
make ui-test         # vitest — the code-graph layout
```

Both `dev` and `preview` proxy `/api` to `http://127.0.0.1:8080`. Override with
`DRISHTI_API_ORIGIN` if the API is elsewhere. Nothing is served by FastAPI: the
frozen route surface has no UI mount, and adding one would put a non-`/api` route
into a file whose whole point is that its routes do not move.

## Layout

Four regions (T0.8) plus the stage strip (T6.4):

```
header: logo lockup · drop APK · job id + live badge
stage strip: 11 pipeline stages, timings, VERDICT ▸ async marker at SCORE_PRELIM
├── numbered rail: 01–08, riding a violet arc; collapses to numbers under 1280px
├── score rail: ring, band, C, γ, R/F_AI/G/D factor bars, limitations
└── views: 01 Overview · 02 Code Graph · 03 Reverse Engineering · 04 Static
          05 Sandbox · 06 Frontier · 07 Ledger · 08 Report
live log: tailed from GET /api/logs/stream, throttled ~150 ms
```

## Design system

Tokens live in `src/index.css` under `@theme`. Three card tiers, used by a rule
that keeps the theme legible for a long session: **violet gradient** and **lilac
wash** / **white** carry summary surfaces (a verdict, a headline number), while
code, tables, the graph and the log stay on the dark ground. Severity colours are
deliberately *not* on the violet ramp — `high` is orange, not magenta — so a band
stays readable when a projector eats saturation.

The logo is the app's single loading indicator. Every wait renders `LogoSpinner`
at one of four sizes; there is no second spinner and no bare "Loading…" string.
`BootSequence` plays once per browser session, is skipped by any key or click, and
collapses to a single frame under `prefers-reduced-motion`.

### Fonts

Space Grotesk (display), Inter (UI), JetBrains Mono (code) are **vendored** into
`src/fonts/` rather than linked from Google Fonts: the demo runs from a production
build on a projector with no guaranteed network, and a `<link>` would silently fall
back to system sans at exactly the wrong moment. To refresh them, re-download the
latin and latin-ext subsets for those three families and rewrite `fonts.css` to
point at the local files.

## `02 Code Graph` — Code-Graph RAG Navigation

`src/graph/layout.ts` is pure: no React, no DOM, no clock. It builds the graph from
`StaticReport.call_paths` — every edge is a call the analyser actually walked, and
there is no inferred edge anywhere — then lays it out with longest-path layering
and a fixed number of barycentre sweeps with a stable tie-break. Deterministic on
purpose: a force simulation settles differently on every mount, which would make a
graph screenshot in a report unreproducible.

Node fill encodes retrieval, which is the point of the view: hollow-and-dashed
means no body was ever recovered for that method, so nothing said about it could
have been grounded. `nodesTouchedBy` attributes a model tool call to graph nodes
through its validated arguments and its shared evidence refs only — never by fuzzy
name — so a call that reached nothing says so.

It is the one part of the UI with its own tests (`src/graph/layout.test.ts`, 14
cases), because the only sample available on a developer machine is the canary,
whose call graph is two nodes on one path and exercises none of the layering,
ordering or cycle handling.

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
