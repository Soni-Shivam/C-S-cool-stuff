# DRISHTI Backend

GenAI-native Android malware triage pipeline — Python backend.

## Status

Foundation layer complete (trust spine + scoring). Delivered so far:

| Module | Responsibility |
|--------|----------------|
| `drishti.config` | Env-driven settings (Gemini/AndroZoo keys, model ids, signing key) |
| `drishti.models` | Core pydantic schemas (`EvidenceNode`) |
| `drishti.ledger` | Append-only, hash-chained, Ed25519-signed evidence ledger + verifier gate |
| `drishti.scoring` | Composite risk score, fused-AI signal, confidence, severity bands (paper §4.6) |

Coming in later plans: M1 ingestion, M2 static analysis (Androguard/YARA), M5 ML,
M4 Gemini reasoning core, M3 simulated sandbox, M6/M7 wiring, FastAPI, dashboard.

## Setup

```bash
python3.13 -m venv ../.venv
source ../.venv/bin/activate
pip install -e ".[dev]"
```

## Test

```bash
python -m pytest -v
```

## Configuration

Copy `.env.example` to `.env` and fill in secrets. All keys are optional — the
system degrades gracefully (mock LLM provider, baseline ML model) when unset.
