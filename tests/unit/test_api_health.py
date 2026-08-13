"""The skeleton is runnable and the container healthcheck is not a lie."""

from __future__ import annotations

from fastapi.testclient import TestClient

from drishti import __version__
from drishti.api.main import app

client = TestClient(app)


def test_health_returns_ok_and_version() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_health_leaks_no_analysis_state() -> None:
    """A liveness probe must not become an information channel.

    It is reachable before auth exists, so it reports version only — no job ids,
    no sample hashes, no config values.
    """
    keys = set(client.get("/api/health").json())
    assert keys == {"status", "version"}, f"unexpected keys in health payload: {keys}"
