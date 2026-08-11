# DRISHTI Backend

GenAI-native Android malware triage pipeline — Python backend.

## Status

The M1–M7 pipeline, signed evidence ledger, static/ML/Gemini reasoning, explicit
absent/simulated/observed dynamic provenance, Android report assembler, authenticated
FastAPI job service, and MLflow GenAI evaluation tooling are implemented. The API is
parse-only: it never executes an APK and never invokes the detonator script.

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

## API

```bash
DEMO_API_TOKEN=replace-me uvicorn drishti.api.app:app --host 127.0.0.1 --port 8000 --no-access-log
```

Routes are `POST /v1/analyses`, `GET /v1/analyses/{id}`,
`GET /v1/analyses/{id}/report`, and `GET /health`. Supply the token as
`Authorization: Bearer ...` or `X-API-Token`.

## Configuration

Copy `.env.example` to `.env` and fill in secrets. All keys are optional — the
system degrades gracefully (mock LLM provider, baseline ML model) when unset.
