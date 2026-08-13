"""FastAPI application entrypoint.

T0.1 provides only the app object and a liveness probe so the skeleton is runnable
and the container healthcheck is real. The analysis route surface is frozen in T0.6
(docs/PHASE_0_FOUNDATIONS.md) and added there — do not add analysis endpoints here
ahead of that task, because the UI is built against the frozen list.
"""

from __future__ import annotations

from fastapi import FastAPI

from drishti import __version__

app = FastAPI(
    title="DRISHTI",
    description="Defensive Android malware triage",
    version=__version__,
)


@app.get("/api/health")
def health() -> dict[str, str]:
    """Liveness probe. Reports the version, never any analysis state."""
    return {"status": "ok", "version": __version__}
