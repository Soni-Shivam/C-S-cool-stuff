# v1-reference — READ ONLY

This directory is the **v1 implementation, frozen**. It is here for one reason: so that
work which *adapts* v1 logic into v2 can read the original side by side.

## Rules

1. **Nothing in the v2 codebase imports from this directory.** Not `drishti/`, not `tests/`,
   not `scripts/`, not `infra/`. If you find an import crossing this boundary, it is a bug.
2. **Nothing here is executed.** No test runner collects it, no CI step touches it.
3. **Do not fix bugs here.** If v1 code is wrong, either it is being adapted (fix it in the
   v2 file) or it is `REFERENCE`/`DROP` (leave it wrong — it is a historical record).
4. **Do not treat anything here as verified.** v1 claimed 124 passing tests; v2 has not
   re-run them. Numbers in v1's own docs are v1's claims, not v2's measurements.

## What was salvaged, and what wasn't

Every path in this tree is catalogued in **`docs/SALVAGE.md`** with a verdict:

| Verdict | Meaning |
|---|---|
| `LIFT` | Ported near-verbatim. Cost real GCP hours or real measurement to produce, and is independent of v2's contracts. |
| `ADAPT` | The logic and the reasoning are right; the types are wrong. Re-typed onto `drishti/contracts/`, comments preserved. |
| `REFERENCE` | Read it for the lesson, then write v2's version fresh. v2 specifies something stronger. |
| `DROP` | Actively harmful to carry forward — stale, synthetic, secret-bearing, or a saved error page. |

The measurements and known holes worth carrying into v2 are in
**`docs/CARRIED_FINDINGS.md`**, each tagged with the v2 task that must honour it. Read that
before quoting any v1 number.

## Things in here that are NOT in git

Deliberately gitignored, because data does not belong in a repo:

- `backend/.env` — held live API keys. **Those keys were shared in plaintext and must be
  rotated.**
- `backend/samples.csv` — the real 6,000-row AndroZoo sample list. Backed up to GCS instead.
  Note its train/test split is contaminated (see `docs/CARRIED_FINDINGS.md`).
- `backend/mlflow.db`, `backend/mlruns/` — experiment tracking state.
- `backend/drishti/data/models/baseline.joblib` — the `baseline-synthetic-v1` model. `DROP`:
  a synthetic model must never ship under v2's honesty rules.
- `latest.csv` (root and `backend/`) — `DROP`: these are saved HTTP 404 HTML pages, not the
  AndroZoo index. Do not debug them; re-download the index.

## Provenance

Frozen from branch `v1` at commit `45cebe7`, also tagged **`v1-final`**. The full v1 history
is on that branch — this directory is a convenience copy, not the archive.
