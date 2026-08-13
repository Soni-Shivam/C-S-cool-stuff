import io
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from drishti.api.app import create_app
from drishti.config import Settings

TOKEN = "test-secret-token"


def _apk_bytes(extra=b""):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex" + extra)
    return stream.getvalue()


def _report(analysis_id):
    return {
        "analysis_id": analysis_id, "sha256": "a" * 64, "threat_score": 10,
        "severity": "Low", "confidence": {"value": .7, "label": "Medium"},
        "provenance": {"static_analysis": "completed", "ml_model_version": "test", "gemini_status": "mock", "dynamic_status": "absent", "notice": "No dynamics"},
        "genai_summary": {"text": "Grounded", "evidence_refs": ["n1"]},
        "potential_consequences": [], "suspicious_permissions": [],
        "suspicious_capabilities": [], "mitre_mobile_techniques": [], "iocs": [],
        "evidence": [{"id": "n1", "type": "manifest", "source": "test", "statement": "safe", "confidence": 1.0, "provenance": "static"}],
        "safety_notice": "User controls installation",
    }


def test_api_auth_job_states_report_and_quarantine_cleanup(tmp_path, monkeypatch):
    seen = {}
    def fake_worker(path, analysis_id, config):
        seen["path"] = path
        seen["exists_during"] = __import__("pathlib").Path(path).exists()
        return {"sha256": "a" * 64, "report": _report(analysis_id)}
    monkeypatch.setattr("drishti.api.app.analyze_quarantined", fake_worker)
    settings = Settings(demo_api_token=TOKEN, quarantine_dir=tmp_path, max_upload_bytes=1024 * 1024)
    executor = ThreadPoolExecutor(max_workers=1)
    with TestClient(create_app(settings=settings, executor=executor)) as client:
        assert client.post("/v1/analyses", files={"file": ("sample.apk", _apk_bytes())}).status_code == 401
        response = client.post("/v1/analyses", headers={"Authorization": f"Bearer {TOKEN}"}, files={"file": ("real-name.apk", _apk_bytes())})
        assert response.status_code == 202
        analysis_id = response.json()["analysis_id"]
        for _ in range(100):
            status = client.get(f"/v1/analyses/{analysis_id}", headers={"X-API-Token": TOKEN}).json()
            if status["state"] == "completed": break
            time.sleep(.01)
        assert status["state"] == "completed"
        report = client.get(f"/v1/analyses/{analysis_id}/report", headers={"X-API-Token": TOKEN})
        assert report.status_code == 200
        assert seen["exists_during"] is True
        assert "real-name" not in seen["path"]
        for _ in range(100):
            if not __import__("pathlib").Path(seen["path"]).exists(): break
            time.sleep(.01)
        assert not __import__("pathlib").Path(seen["path"]).exists()
    executor.shutdown()


def test_api_rejects_non_zip_and_oversize_without_persisting(tmp_path):
    settings = Settings(demo_api_token=TOKEN, quarantine_dir=tmp_path, max_upload_bytes=32)
    executor = ThreadPoolExecutor(max_workers=1)
    with TestClient(create_app(settings=settings, executor=executor)) as client:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        assert client.post("/v1/analyses", headers=headers, files={"file": ("x.apk", b"not zip")}).status_code == 415
        assert client.post("/v1/analyses", headers=headers, files={"file": ("x.apk", _apk_bytes(b"x" * 100))}).status_code == 413
        assert list(tmp_path.iterdir()) == []
    executor.shutdown()
