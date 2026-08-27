"""The staged-sample catalogue: pick a known sample instead of uploading one.

The catalogue exists so a demo can be run against samples whose true nature is
already known, and so the verdict can be put next to that truth. Three properties
carry the whole safety argument, and each is asserted here rather than described in
a comment:

**No route ever serves the APK bytes.** CLAUDE.md's hard boundary is that a real
sample does not leave the analysis project. That is why this is a *server-side*
selector: the browser names an id, the VM opens the file. There is no download
route, and `test_no_route_serves_sample_bytes` fails if one is ever added.

**An id is matched, never joined into a path.** `sample_id` is looked up among the
ids the manifest declares. A traversal string simply finds no entry.

**The ground-truth label never reaches the analysis.** `label` and `vt_detection`
are AndroZoo's VT-derived truth; feeding either into the pipeline would make every
composite score circular, which is the reason `reputation.py` refuses a
label-derived feed by default. The catalogue is read by the API and the UI only —
`test_a_sample_run_is_identical_to_an_upload_of_the_same_bytes` is what keeps that
true as the code moves.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from drishti.api import deps
from drishti.api import main as api_main
from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.m1_ingest import catalogue
from tests.apk_fixtures import minimal_apk_bytes

APK_BYTES = minimal_apk_bytes()

#: Two entries, one of each label, plus the unlabelled probe — the three cases the UI
#: has to render differently.
MANIFEST = [
    {
        "id": "aaaa1111",
        "filename": "aaaa1111.apk",
        "package": "com.evil.thing",
        "label": 1,
        "vt_detection": 47,
        "size_bytes": 0,
        "note": "corpus sample, dex 2021-07-15",
    },
    {
        "id": "bbbb2222",
        "filename": "bbbb2222.apk",
        "package": "com.good.thing",
        "label": 0,
        "vt_detection": 0,
        "size_bytes": 0,
        "note": "corpus sample, dex 2022-08-06",
    },
    {
        "id": "canary",
        "filename": "canary.apk",
        "package": "in.drishti.canary",
        "label": None,
        "vt_detection": None,
        "size_bytes": 0,
        "note": "our own inert probe app",
    },
]


@pytest.fixture
def samples_dir(tmp_path: Path) -> Path:
    """A staging directory shaped exactly like the one on the VM."""
    directory = tmp_path / "samples"
    directory.mkdir()
    for entry in MANIFEST:
        (directory / entry["filename"]).write_bytes(APK_BYTES)
    (directory / "manifest.json").write_text(json.dumps(MANIFEST))
    return directory


@pytest.fixture
def settings(tmp_path: Path, samples_dir: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        groq_api_key="gsk-test",
        samples_dir=samples_dir,
    )


@pytest.fixture
def client(settings: Settings):
    runner = JobRunner(settings)
    deps.set_runner(runner)
    api_main.app.dependency_overrides[deps.get_settings] = lambda: settings
    try:
        yield TestClient(api_main.app)
    finally:
        runner.shutdown()
        api_main.app.dependency_overrides.clear()
        deps.set_runner(None)


def _drain(client: TestClient, job_id: str) -> None:
    with client.stream("GET", f"/api/jobs/{job_id}/events") as stream:
        list(stream.iter_lines())


# ── the catalogue itself ─────────────────────────────────────────────────────
def test_the_catalogue_reads_what_the_manifest_declares(settings: Settings) -> None:
    entries = catalogue.load(settings)
    assert [e.id for e in entries] == ["aaaa1111", "bbbb2222", "canary"]
    assert entries[0].package == "com.evil.thing"
    assert entries[0].vt_detection == 47


def test_the_catalogue_computes_the_hash_of_what_is_actually_on_disk(
    settings: Settings,
) -> None:
    """The manifest may state a hash; the file decides it.

    A declared hash that disagrees with the bytes would let the catalogue name one
    sample and analyse another. The digest is read from disk for that reason.
    """
    import hashlib

    expected = hashlib.sha256(APK_BYTES).hexdigest()
    assert all(entry.sha256 == expected for entry in catalogue.load(settings))


def test_an_unset_samples_dir_is_an_empty_catalogue_not_an_error(tmp_path: Path) -> None:
    """A laptop has no staged samples. The feature is absent there, not broken."""
    bare = Settings(
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        groq_api_key="gsk-test",
    )
    assert bare.samples_dir is None
    assert catalogue.load(bare) == []


def test_an_entry_whose_file_is_missing_is_dropped(settings: Settings) -> None:
    """The catalogue offers only what it can actually run.

    Listing a sample whose file is absent produces a button that 500s when pressed.
    """
    (settings.samples_dir / "bbbb2222.apk").unlink()
    assert [e.id for e in catalogue.load(settings)] == ["aaaa1111", "canary"]


def test_resolving_an_id_never_leaves_the_samples_directory(settings: Settings) -> None:
    """Ids are matched against the manifest, never joined into a path."""
    for hostile in ("../../../etc/passwd", "..", "/etc/passwd", "aaaa1111/../../x"):
        assert catalogue.resolve(settings, hostile) is None


def test_resolving_a_known_id_gives_the_staged_file(settings: Settings) -> None:
    resolved = catalogue.resolve(settings, "aaaa1111")
    assert resolved is not None
    assert resolved.path == settings.samples_dir / "aaaa1111.apk"
    assert resolved.entry.label == 1


# ── the routes ───────────────────────────────────────────────────────────────
def test_the_catalogue_route_serves_metadata(client: TestClient) -> None:
    body = client.get("/api/samples").json()
    assert [e["id"] for e in body] == ["aaaa1111", "bbbb2222", "canary"]
    assert body[0]["label"] == 1
    assert body[2]["label"] is None


def test_no_route_serves_sample_bytes(client: TestClient) -> None:
    """The one thing this feature must never do (CLAUDE.md, hard boundary).

    Asserted two ways: no registered route looks like a sample download, and the
    catalogue payload carries no field holding the file's content.
    """
    paths = [str(route.path) for route in api_main.app.routes]
    assert not [
        p
        for p in paths
        if "/samples" in p and any(w in p for w in ("download", "file", "apk", "raw"))
    ]

    body = client.get("/api/samples").json()
    serialised = json.dumps(body).encode()
    assert APK_BYTES not in serialised
    for entry in body:
        assert not {"content", "bytes", "data", "path"} & set(entry)


def test_analysing_a_sample_queues_a_job(client: TestClient) -> None:
    response = client.post("/api/samples/aaaa1111/analyse")
    assert response.status_code == 202, response.text
    assert response.json()["job_id"].startswith("job_")


def test_an_unknown_sample_is_404_not_500(client: TestClient) -> None:
    assert client.post("/api/samples/nope/analyse").status_code == 404


def test_a_traversal_id_is_refused_by_the_route(client: TestClient) -> None:
    """Whatever the router does with the path, no file outside the directory runs."""
    for hostile in ("..%2F..%2Fetc%2Fpasswd", "%2Fetc%2Fpasswd", "..", "."):
        assert client.post(f"/api/samples/{hostile}/analyse").status_code in (404, 405)


# ── the honesty property ─────────────────────────────────────────────────────
def test_a_sample_run_is_identical_to_an_upload_of_the_same_bytes(
    client: TestClient,
) -> None:
    """The ground-truth label must not change the analysis in any way.

    `label`/`vt_detection` are VT-derived. If either reached the pipeline, every
    composite score computed over this corpus would be circular — the precise thing
    `reputation.py` refuses a label-derived feed to prevent. Starting from a labelled
    sample and starting from an upload of the same bytes must therefore produce the
    same verdict, and this is what fails if the label is ever wired in.
    """
    from_sample = client.post("/api/samples/aaaa1111/analyse").json()["job_id"]
    _drain(client, from_sample)

    from_upload = client.post("/api/jobs", files={"apk": ("aaaa1111.apk", APK_BYTES)}).json()[
        "job_id"
    ]
    _drain(client, from_upload)

    sample_score = client.get(f"/api/jobs/{from_sample}/score").json()
    upload_score = client.get(f"/api/jobs/{from_upload}/score").json()
    assert sample_score["S"] == upload_score["S"]
    assert sample_score["band"] == upload_score["band"]
    assert sample_score["C"] == upload_score["C"]


def test_analysing_a_sample_does_not_consume_it(client: TestClient, settings: Settings) -> None:
    """The staged file must survive its own analysis.

    The upload route hands the runner a file in a temp directory it created, so
    nothing there cares whether the runner cleans up afterwards. This route hands it
    a file from the corpus, and a `finally: rmtree(parent)` added to the runner one
    day would delete the staged samples on the VM the first time anyone pressed Run.
    Nothing in the current runner does that, and this is what notices if it starts.
    """
    staged = settings.samples_dir / "aaaa1111.apk"
    before = staged.read_bytes()

    job_id = client.post("/api/samples/aaaa1111/analyse").json()["job_id"]
    _drain(client, job_id)

    assert staged.is_file(), "the staged sample was deleted by its own analysis"
    assert staged.read_bytes() == before
    assert (settings.samples_dir / catalogue.MANIFEST_NAME).is_file()


def test_the_job_does_not_carry_the_label(client: TestClient) -> None:
    """Nothing downstream of `submit()` can even see the ground truth."""
    job_id = client.post("/api/samples/aaaa1111/analyse").json()["job_id"]
    _drain(client, job_id)

    serialised = json.dumps(client.get(f"/api/jobs/{job_id}").json())
    assert "vt_detection" not in serialised
    assert "ground_truth" not in serialised
