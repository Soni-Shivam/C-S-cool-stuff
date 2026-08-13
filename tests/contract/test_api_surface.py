"""The frozen route surface. docs/PHASE_0_FOUNDATIONS.md T0.6.

A contract test, not a unit test: the UI is built against this list and must not have
to chase changes. If a route disappears or changes shape, this fails before the UI
does.

It also pins the two distinct "not available" conventions, because collapsing them
would make a permanently-missing feature look like a slow one.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from drishti.api import deps
from drishti.api import main as api_main
from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.job import JobStage

#: Every route T0.6 freezes. `{id}` is substituted at runtime.
FROZEN_ROUTES: set[tuple[str, str]] = {
    ("GET", "/api/health"),
    ("POST", "/api/jobs"),
    ("GET", "/api/jobs/{job_id}"),
    ("GET", "/api/jobs/{job_id}/events"),
    ("GET", "/api/jobs/{job_id}/ingest"),
    ("GET", "/api/jobs/{job_id}/static"),
    ("GET", "/api/jobs/{job_id}/ml"),
    ("GET", "/api/jobs/{job_id}/genai"),
    ("GET", "/api/jobs/{job_id}/dynamic"),
    ("GET", "/api/jobs/{job_id}/score"),
    ("GET", "/api/jobs/{job_id}/ledger"),
    ("GET", "/api/jobs/{job_id}/ledger/verify"),
    ("GET", "/api/jobs/{job_id}/ledger/export"),
    ("GET", "/api/evidence/{node_id}"),
    ("GET", "/api/jobs/{job_id}/report.html"),
    ("GET", "/api/jobs/{job_id}/artifacts/yara"),
    ("GET", "/api/jobs/{job_id}/artifacts/stix"),
    ("POST", "/api/jobs/{job_id}/actions/{action}/confirm"),
    ("GET", "/api/logs/stream"),
}

APK_BYTES = b"PK\x03\x04" + b"stub" * 64


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        llm_provider="mock",
    )


@pytest.fixture
def client(settings):
    runner = JobRunner(settings)
    deps.set_runner(runner)
    api_main.app.dependency_overrides[deps.get_settings] = lambda: settings
    try:
        yield TestClient(api_main.app)
    finally:
        runner.shutdown()
        api_main.app.dependency_overrides.clear()
        deps.set_runner(None)


@pytest.fixture
def finished_job(client) -> str:
    job_id = client.post("/api/jobs", files={"apk": ("s.apk", APK_BYTES)}).json()["job_id"]
    with client.stream("GET", f"/api/jobs/{job_id}/events") as stream:
        list(stream.iter_lines())
    return job_id


# ── the surface itself ───────────────────────────────────────────────────────
def test_every_frozen_route_is_registered() -> None:
    """The whole point of T0.6: this list does not move under the UI."""
    registered = {
        (method, route.path)
        for route in api_main.app.routes
        for method in getattr(route, "methods", set()) or set()
        if method not in {"HEAD", "OPTIONS"}
    }
    missing = FROZEN_ROUTES - registered
    assert missing == set(), f"frozen routes are not registered: {sorted(missing)}"


def test_no_undeclared_api_routes_have_appeared() -> None:
    """Adding a route means adding it to the doc and this list, in that order.

    Otherwise the "frozen surface" is whatever the last commit happened to leave.
    """
    registered = {
        (method, route.path)
        for route in api_main.app.routes
        for method in getattr(route, "methods", set()) or set()
        if method not in {"HEAD", "OPTIONS"} and str(route.path).startswith("/api/")
    }
    extra = registered - FROZEN_ROUTES
    assert extra == set(), f"undeclared /api routes: {sorted(extra)}"


# ── pending vs not-implemented ───────────────────────────────────────────────
def test_artefacts_pending_before_the_stage_runs(client, settings) -> None:
    """404 carries the stage so the UI can say *why* it is empty.

    Asserted against a job that exists but has produced nothing yet.
    """
    from drishti.contracts.job import Job
    from drishti.util import new_id, now

    runner = deps.get_runner()
    queued = Job(
        id=new_id("job"),
        sha256="a" * 64,
        filename="s.apk",
        stage=JobStage.QUEUED,
        created_at=now(),
    )
    runner._store(queued)

    response = client.get(f"/api/jobs/{queued.id}/static")
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["reason"] == "not_produced_yet"
    assert detail["stage"] == JobStage.QUEUED.value


@pytest.mark.parametrize(
    ("path", "task"),
    [("report.html", "T6.3"), ("artifacts/yara", "T6.1"), ("artifacts/stix", "T6.2")],
)
def test_unbuilt_features_are_501_not_404(client, finished_job, path, task) -> None:
    """A frozen-but-unbuilt route must not look like a pending one.

    Polling a 404 is reasonable; polling something that will never exist is not, and
    the UI needs to tell those apart.
    """
    response = client.get(f"/api/jobs/{finished_job}/{path}")
    assert response.status_code == 501
    detail = response.json()["detail"]
    assert detail["reason"] == "not_implemented"
    assert detail["task"] == task


# ── artefacts after a full run ───────────────────────────────────────────────
@pytest.mark.parametrize("kind", ["ingest", "static", "ml", "genai", "dynamic", "score"])
def test_artefacts_are_served_after_the_run(client, finished_job, kind) -> None:
    response = client.get(f"/api/jobs/{finished_job}/{kind}")
    assert response.status_code == 200, response.text


def test_stub_artefacts_declare_themselves_partial(client, finished_job) -> None:
    """A stub must not read as a real analysis that found nothing."""
    body = client.get(f"/api/jobs/{finished_job}/static").json()
    assert body["partial"] is True
    assert any("stub" in e for e in body["errors"])


def test_score_reports_gamma_so_the_ui_knows_which_verdict_it_holds(client, finished_job) -> None:
    body = client.get(f"/api/jobs/{finished_job}/score").json()
    assert body["gamma"] == 1.0, "after a full run this should be the final verdict"


# ── ledger ───────────────────────────────────────────────────────────────────
def test_ledger_query_filters_and_paginates(client, finished_job) -> None:
    everything = client.get(f"/api/jobs/{finished_job}/ledger").json()
    assert len(everything) >= 5
    assert [n["seq"] for n in everything] == sorted(n["seq"] for n in everything)

    from_three = client.get(f"/api/jobs/{finished_job}/ledger?since_seq=3").json()
    assert all(n["seq"] >= 3 for n in from_three)

    typed = client.get(f"/api/jobs/{finished_job}/ledger?type=file_meta").json()
    assert typed and all(n["type"] == "file_meta" for n in typed)


def test_evidence_drilldown_resolves_a_node(client, finished_job) -> None:
    """The click path behind every evidence chip in the UI."""
    nodes = client.get(f"/api/jobs/{finished_job}/ledger").json()
    node_id = nodes[0]["id"]
    body = client.get(f"/api/evidence/{node_id}").json()
    assert body["id"] == node_id
    assert body["node_hash"] == nodes[0]["node_hash"]


def test_unknown_evidence_node_is_404(client) -> None:
    assert client.get("/api/evidence/ev_nope").status_code == 404


def test_export_is_independently_verifiable_over_http(client, finished_job) -> None:
    body = client.get(f"/api/jobs/{finished_job}/ledger/export").json()
    assert body["algorithm"] == "ed25519"
    assert "pubkey" in body and "float_precision" in body

    from drishti.ledger import crypto

    pubkey = crypto.public_key_from_hex(body["pubkey"])
    assert all(crypto.verify(pubkey, n["node_hash"], n["signature"]) for n in body["nodes"])


def test_broken_chain_is_200_with_ok_false(client, finished_job, settings) -> None:
    """A compromised ledger is a report, not a request failure.

    An HTTP error would make "the evidence is compromised" indistinguishable from
    "the network hiccuped".
    """
    import json as _json
    import sqlite3

    conn = sqlite3.connect(settings.db_path, isolation_level=None)
    for trigger in ("ev_no_update", "ev_no_delete"):
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    conn.execute(
        "UPDATE evidence SET content = ? WHERE job_id = ? AND seq = 2",
        (_json.dumps({"evil": True}), finished_job),
    )
    conn.close()

    response = client.get(f"/api/jobs/{finished_job}/ledger/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["first_bad_seq"] == 2


# ── the human gate ───────────────────────────────────────────────────────────
def test_confirming_an_action_records_evidence_and_executes_nothing(client, finished_job) -> None:
    """ "Nothing executes without a human" is a safety property, so it ships in P0."""
    response = client.post(
        f"/api/jobs/{finished_job}/actions/block/confirm",
        json={"confirmed_by": "analyst@example.com"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["action"] == "block"
    assert body["confirmed_by"] == "analyst@example.com"
    assert body["requires_confirmation"] is True

    nodes = client.get(f"/api/jobs/{finished_job}/ledger?type=analyst_action").json()
    assert len(nodes) == 1
    assert nodes[0]["content"]["confirmed_by"] == "analyst@example.com"
    assert nodes[0]["content"]["executed"] is False, "DRISHTI proposes; it does not act"


def test_confirmation_keeps_the_chain_valid(client, finished_job) -> None:
    client.post(
        f"/api/jobs/{finished_job}/actions/quarantine/confirm",
        json={"confirmed_by": "analyst"},
    )
    assert client.get(f"/api/jobs/{finished_job}/ledger/verify").json()["ok"] is True


def test_unknown_action_is_rejected(client, finished_job) -> None:
    response = client.post(
        f"/api/jobs/{finished_job}/actions/rm_rf_slash/confirm",
        json={"confirmed_by": "analyst"},
    )
    assert response.status_code == 400


def test_anonymous_confirmation_is_rejected(client, finished_job) -> None:
    """An unattributed confirmation is not a human gate."""
    response = client.post(
        f"/api/jobs/{finished_job}/actions/block/confirm", json={"confirmed_by": "   "}
    )
    assert response.status_code == 400


# ── unknown job ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path",
    ["", "/static", "/ml", "/genai", "/dynamic", "/score", "/ledger", "/ledger/verify"],
)
def test_unknown_job_is_404_everywhere(client, path) -> None:
    assert client.get(f"/api/jobs/job_nope{path}").status_code == 404
