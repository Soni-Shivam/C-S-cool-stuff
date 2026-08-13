# Replay trace fixtures

One file per sample, named `{sha256}.json`, validated against `TraceFixture` in
`drishti/m3_dynamic/trace_source.py`.

## The point of these files

`00_GUIDING_MAP.md` §3: Phase 4 (live detonation) is the highest-risk work in the
project. If it is not working by the H40 tripwire, the pipeline consumes traces from a
fixture instead and the rest of the system cannot tell the difference. That switch is
only cheap because `TraceSource` and these fixtures exist from hour zero.

Each fixture holds **two halves**, because the frontier narrative is a *change*:

| Half | Used when | Shows |
|---|---|---|
| `pre_morph` | `plan.morphs` is empty (pass 1) | the sample probes its environment, misses, and stalls |
| `post_morph` | `plan.morphs` is non-empty (pass 2) | after environment synthesis, the payload fires |

## `provenance.kind` is not decoration

```json
"provenance": { "kind": "hand_authored" | "captured", ... }
```

- **`hand_authored`** — somebody typed plausible values. The loader forces
  `synthetic=true` and `partial=true` on the resulting trace and appends a disclosure to
  `errors`, which flows into the report's Limitations section. **This is the P0 state.**
- **`captured`** — a real trace from a real detonation of a real sample in the sealed
  lab. `synthetic` stays false. Replaying one of these is legitimate and is disclosed on
  screen as a replay, per `00_GUIDING_MAP.md` §3.

You cannot set `source` or `synthetic` from the JSON. The loader overwrites both. A
replay always declares itself a replay, and a hand-authored trace always declares
itself synthetic — the disclosure does not depend on whoever edits the file
remembering to.

## Replacing a fixture with a real capture (P4)

1. Capture on the sealed detonator; the harness writes an `ObservationArtifact`.
2. Normalise it to a `DynamicTrace` (T4.6) for each half.
3. Write the file under the **real sample's** sha256, with
   `provenance.kind = "captured"` and `source_sha256` / `captured_from_image` filled in.
4. Nothing else changes. The pipeline, API, and UI are unaffected.

## Do not put a sample here

These are JSON traces. `*.apk` is gitignored repo-wide with an allowlist only for
`canary/dist/`, and no sample ever belongs in the repository.
