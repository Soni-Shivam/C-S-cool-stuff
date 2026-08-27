"""The case file: every deliverable for one job in one archive (the download button).

Two things are asserted, and they are the whole reason this exists:

**Completeness** — the archive holds exactly what the Report tab offers as separate
downloads, byte-for-byte, plus a manifest. A bundle that quietly dropped the ledger
would look identical to a correct one until someone needed the ledger.

**Self-description** — the manifest states the sample hash, per-entry hashes, the
chain verification as it stood at build time, and what was *omitted and why*. An
archive kept for months has to answer "is this complete, and was the evidence intact"
without the system that produced it.

What it must never contain is the sample. CLAUDE.md: an APK does not leave the
analysis project, and a download button is not an exception.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from drishti.api import deps
from drishti.api import main as api_main
from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.evidence import ChainVerification
from drishti.contracts.job import Job, JobStage
from drishti.contracts.static_report import FileMeta
from drishti.m7_report import case_file
from drishti.util import new_id, now
from tests.apk_fixtures import minimal_apk_bytes

APK_BYTES = minimal_apk_bytes()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        groq_api_key="gsk-test",
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
    job_id = client.post("/api/jobs", files={"apk": ("sample.apk", APK_BYTES)}).json()["job_id"]
    with client.stream("GET", f"/api/jobs/{job_id}/events") as stream:
        list(stream.iter_lines())
    return job_id


def _meta() -> FileMeta:
    return FileMeta(sha256="b" * 64, size_bytes=1234, filename="sample.apk", package="com.x")


def _manifest(archive: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        return json.loads(zf.read(case_file.MANIFEST_NAME))


# ── the builder ──────────────────────────────────────────────────────────────
def test_bundle_holds_every_file_it_was_given_byte_for_byte() -> None:
    files = {"report.html": b"<html>hi</html>", "yara.yar": b"rule X {}"}
    archive = case_file.build(
        job_id="job_1",
        meta=_meta(),
        files=files,
        chain=ChainVerification(ok=True, node_count=7),
        generated_at=now(),
        omitted={},
    )

    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        assert zf.testzip() is None
        for name, payload in files.items():
            assert zf.read(name) == payload


def test_manifest_hashes_match_the_archived_bytes() -> None:
    """The manifest is the reason to keep the archive; a wrong hash makes it a liar."""
    files = {"report.html": b"<html>hi</html>", "stix.json": b"{}"}
    archive = case_file.build(
        job_id="job_1",
        meta=_meta(),
        files=files,
        chain=ChainVerification(ok=True, node_count=7),
        generated_at=now(),
        omitted={},
    )

    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        manifest = json.loads(zf.read(case_file.MANIFEST_NAME))
        for entry in manifest["contents"]:
            archived = zf.read(entry["name"])
            assert entry["sha256"] == hashlib.sha256(archived).hexdigest()
            assert entry["bytes"] == len(archived)

    assert manifest["job_id"] == "job_1"
    assert manifest["sample_sha256"] == "b" * 64
    assert {e["name"] for e in manifest["contents"]} == set(files)


def test_manifest_records_omissions_rather_than_hiding_them() -> None:
    """A missing export is stated with its reason. Silence would read as complete."""
    archive = case_file.build(
        job_id="job_1",
        meta=_meta(),
        files={"report.html": b"<html/>"},
        chain=ChainVerification(ok=True, node_count=1),
        generated_at=now(),
        omitted={"stix.json": "the exporter failed: boom"},
    )
    assert _manifest(archive)["omitted"] == {"stix.json": "the exporter failed: boom"}


def test_manifest_carries_the_chain_state_it_was_built_with() -> None:
    """A broken chain travels with the archive. It is not a reason to omit the file."""
    archive = case_file.build(
        job_id="job_1",
        meta=_meta(),
        files={"report.html": b"<html/>"},
        chain=ChainVerification(ok=False, node_count=4, first_bad_seq=3, reason="bad signature"),
        generated_at=now(),
        omitted={},
    )
    assert _manifest(archive)["evidence_chain"] == {
        "verified": False,
        "node_count": 4,
        "first_bad_seq": 3,
        "reason": "bad signature",
    }


def test_archive_framing_is_deterministic() -> None:
    """Same inputs, same bytes: entry timestamps are fixed, not taken from the clock.

    Only the framing is pinned here — the report itself carries a render time, which
    is why this asserts over two builds of identical *inputs*.
    """
    kwargs: dict = dict(
        job_id="job_1",
        meta=_meta(),
        files={"report.html": b"<html/>", "yara.yar": b"rule X {}"},
        chain=ChainVerification(ok=True, node_count=2),
        generated_at="2026-08-27T00:00:00Z",
        omitted={},
    )
    assert case_file.build(**kwargs) == case_file.build(**kwargs)


# ── the route ────────────────────────────────────────────────────────────────
def test_bundle_route_serves_a_zip_named_for_the_job(client, finished_job) -> None:
    response = client.get(f"/api/jobs/{finished_job}/artifacts/bundle.zip")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"
    assert f"{finished_job}-case-file.zip" in response.headers["content-disposition"]


def test_bundle_holds_the_same_bytes_the_single_downloads_serve(client, finished_job) -> None:
    """The button that saves everything must not save something else."""
    archive = client.get(f"/api/jobs/{finished_job}/artifacts/bundle.zip").content
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        assert set(zf.namelist()) == set(case_file.CASE_FILE_NAMES) | {case_file.MANIFEST_NAME}
        assert zf.read("yara.yar") == client.get(f"/api/jobs/{finished_job}/artifacts/yara").content
        assert zf.read("report.html") == client.get(f"/api/jobs/{finished_job}/report.html").content
        assert (
            json.loads(zf.read("stix.json"))
            == client.get(f"/api/jobs/{finished_job}/artifacts/stix").json()
        )
        assert (
            json.loads(zf.read("ledger.json"))
            == client.get(f"/api/jobs/{finished_job}/ledger/export").json()
        )
        assert (
            json.loads(zf.read("verdict.json"))
            == client.get(f"/api/jobs/{finished_job}/verdict").json()
        )
        assert (
            json.loads(zf.read("complaint-package.json"))
            == client.get(f"/api/jobs/{finished_job}/artifacts/dossier").json()
        )


def test_bundle_never_carries_the_sample(client, finished_job) -> None:
    """The one thing this archive must not contain. CLAUDE.md, hard boundary."""
    archive = client.get(f"/api/jobs/{finished_job}/artifacts/bundle.zip").content
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        assert not [n for n in zf.namelist() if n.endswith((".apk", ".dex"))]
    assert APK_BYTES not in archive


def test_bundle_is_pending_before_the_pipeline_produces_anything(client) -> None:
    """404-pending with the stage — never an empty archive, which would read as done."""
    runner = deps.get_runner()
    queued = Job(
        id=new_id("job"),
        sha256="a" * 64,
        filename="s.apk",
        stage=JobStage.QUEUED,
        created_at=now(),
    )
    runner._store(queued)

    response = client.get(f"/api/jobs/{queued.id}/artifacts/bundle.zip")
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["reason"] == "not_produced_yet"
    assert detail["stage"] == JobStage.QUEUED.value
