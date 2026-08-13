"""The HTTP surface added in T0.5: submit, poll, stream, verify.

The remaining frozen route surface is T0.6. What is asserted here is the contract a
UI depends on: a job id comes back immediately, a poll shows progress, the stream
terminates, and a corrupt or oversized upload gets a clean error rather than a 500.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from drishti.api import deps
from drishti.api import main as api_main
from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.job import JobStage
from tests.apk_fixtures import minimal_apk_bytes


@pytest.fixture
def client(tmp_path):
    settings = Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        llm_provider="mock",
    )
    runner = JobRunner(settings)
    deps.set_runner(runner)
    api_main.app.dependency_overrides[deps.get_settings] = lambda: settings
    try:
        yield TestClient(api_main.app)
    finally:
        runner.shutdown()
        api_main.app.dependency_overrides.clear()
        deps.set_runner(None)


# A real zip: M1's guards reject a corrupt archive since T0.10.
APK_BYTES = minimal_apk_bytes()


def _submit(client) -> str:
    response = client.post("/api/jobs", files={"apk": ("sample.apk", APK_BYTES)})
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


def test_submit_returns_a_job_id_immediately(client) -> None:
    """202, not 200: the work has been accepted, not completed."""
    job_id = _submit(client)
    assert job_id.startswith("job_")


def test_job_reaches_done_and_carries_both_verdicts(client) -> None:
    job_id = _submit(client)

    # Draining the SSE stream is the synchronisation point — no sleeps.
    with client.stream("GET", f"/api/jobs/{job_id}/events") as stream:
        stages = [
            json.loads(line[len("data: ") :])["stage"]
            for line in stream.iter_lines()
            if line.startswith("data: ") and "stage" in line
        ]
    assert JobStage.FRONTIER.value in stages, "the conditional branch should be visible"

    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["stage"] == JobStage.DONE.value, job.get("error")
    assert job["preliminary"] is not None
    assert job["final"] is not None


def test_ledger_verifies_over_http(client) -> None:
    """The trust claim, as an endpoint."""
    job_id = _submit(client)
    with client.stream("GET", f"/api/jobs/{job_id}/events") as stream:
        list(stream.iter_lines())

    body = client.get(f"/api/jobs/{job_id}/ledger/verify").json()
    assert body["ok"] is True, body
    assert body["node_count"] >= 5
    assert body["first_bad_seq"] is None


def test_unknown_job_is_404(client) -> None:
    assert client.get("/api/jobs/job_nope").status_code == 404
    assert client.get("/api/jobs/job_nope/events").status_code == 404
    assert client.get("/api/jobs/job_nope/ledger/verify").status_code == 404


def test_empty_upload_is_rejected_cleanly(client) -> None:
    """A malformed upload crashing the API at H70 is an avoidable embarrassment."""
    response = client.post("/api/jobs", files={"apk": ("empty.apk", b"")})
    assert response.status_code == 400
    assert "empty" in response.json()["detail"]


def test_oversized_upload_is_rejected_on_bytes_received(tmp_path) -> None:
    """The guard acts on bytes actually written, not on a header we were told.

    A Content-Length can lie; the stream cannot.
    """
    settings = Settings(
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_provider="mock",
        max_upload_bytes=1024,
    )
    runner = JobRunner(settings)
    deps.set_runner(runner)
    api_main.app.dependency_overrides[deps.get_settings] = lambda: settings
    try:
        client = TestClient(api_main.app)
        response = client.post("/api/jobs", files={"apk": ("big.apk", b"x" * 4096)})
        assert response.status_code == 413
        assert "exceeds" in response.json()["detail"]
    finally:
        runner.shutdown()
        api_main.app.dependency_overrides.clear()
        deps.set_runner(None)


def test_missing_file_field_is_422_not_500(client) -> None:
    assert client.post("/api/jobs", data={}).status_code == 422
