# DRISHTI

Defensive Android malware triage. Ingests a suspicious APK and returns a calibrated 0–100
threat score with an explicit confidence, a grounded investigation report where every AI
sentence cites a concrete artefact, and a hash-chained Ed25519-signed evidence ledger.

The differentiator is an **active** sandbox: an LLM reads the sample's evasion checks and
synthesises the victim environment it is looking for until the dormant payload detonates.

## Safety

This project **analyses** malware; it does not create it. No APK is ever executed on a
developer machine — detonation happens only inside a sealed GCE VM with no egress, no
external IP, and no Google identity. See [`CLAUDE.md`](CLAUDE.md) for the full boundary and
[`docs/00_GUIDING_MAP.md`](docs/00_GUIDING_MAP.md) §4 for the legal one.

## Quick start

```bash
make install      # core + dev deps (no lab extras)
make test         # contract + unit tests — the gate for every change
make up           # API on :8080
make help         # everything else
```

## Where things are

| Path | What |
|---|---|
| `docs/00_GUIDING_MAP.md` | The control document. Read first. |
| `docs/01_DATA_CONTRACTS.md` | Every module boundary. Read before writing code. |
| `docs/PHASE_*.md` | Execution detail per phase. |
| `STATUS.md` | Current state of the world. Updated after every task. |
| `docs/SALVAGE.md` | What v1 gives v2, per path. |
| `docs/CARRIED_FINDINGS.md` | v1's measurements and holes. Read before quoting any number. |
| `v1-reference/` | Frozen v1 implementation. Read-only; nothing imports it. |

Status of the build is in [`STATUS.md`](STATUS.md), not here.
