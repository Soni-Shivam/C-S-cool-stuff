import asyncio
import hmac
import os
import uuid
import zipfile
from concurrent.futures import Executor, ProcessPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile, status

from drishti.api.models import AnalysisAccepted, AnalysisStatus
from drishti.api.store import InMemoryJobStore, JobStore
from drishti.api.worker import analyze_quarantined
from drishti.config import Settings, get_settings
from drishti.reporting.models import AndroidAnalysisReport

_CHUNK_SIZE = 1024 * 1024


def _public_status(job) -> AnalysisStatus:
    return AnalysisStatus(**job.model_dump(exclude={"report"}))


def create_app(
    *,
    settings: Settings | None = None,
    store: JobStore | None = None,
    executor: Executor | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    store = store or InMemoryJobStore()
    owns_executor = executor is None
    quarantine = Path(settings.quarantine_dir).resolve()
    quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(quarantine, 0o700)
    except OSError:
        pass

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        if application.state.executor is None:
            application.state.executor = ProcessPoolExecutor(
                max_workers=settings.analysis_workers
            )
        try:
            yield
        finally:
            if application.state.tasks:
                await asyncio.gather(*application.state.tasks, return_exceptions=True)
            if owns_executor and application.state.executor is not None:
                application.state.executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="DRISHTI pre-install analysis API", version="1.0.0", lifespan=lifespan
    )
    app.state.store = store
    app.state.settings = settings
    app.state.executor = executor
    app.state.tasks = set()

    def authenticate(
        authorization: str | None = Header(default=None),
        x_api_token: str | None = Header(default=None),
    ) -> None:
        supplied = x_api_token
        if authorization and authorization.startswith("Bearer "):
            supplied = authorization[7:]
        if not supplied or not hmac.compare_digest(supplied, settings.demo_api_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API token")

    async def process_job(analysis_id: str, path: Path) -> None:
        store.update(analysis_id, state="running")
        try:
            loop = asyncio.get_running_loop()
            worker_config = settings.model_dump(mode="json")
            output = await loop.run_in_executor(
                app.state.executor, analyze_quarantined, str(path), analysis_id, worker_config
            )
            report = AndroidAnalysisReport.model_validate(output["report"])
            store.update(
                analysis_id, state="completed", sha256=output["sha256"], report=report
            )
        except Exception:  # deliberately do not expose parser paths/content
            store.update(analysis_id, state="failed", error="analysis failed")
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "gemini": "live" if settings.gemini_api_key and settings.gemini_model else "mock",
            "dynamic_execution": "disabled",
        }

    @app.post(
        "/v1/analyses",
        response_model=AnalysisAccepted,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(authenticate)],
    )
    async def create_analysis(file: UploadFile = File(...)) -> AnalysisAccepted:
        analysis_id = uuid.uuid4().hex
        path = quarantine / f"{uuid.uuid4().hex}.apk"
        size = 0
        try:
            with path.open("xb") as destination:
                os.chmod(path, 0o600)
                while chunk := await file.read(_CHUNK_SIZE):
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(status_code=413, detail="APK exceeds upload limit")
                    destination.write(chunk)
            if size < 4 or not zipfile.is_zipfile(path):
                raise HTTPException(status_code=415, detail="input is not an APK/ZIP")
            with zipfile.ZipFile(path) as archive:
                if "AndroidManifest.xml" not in archive.namelist():
                    raise HTTPException(status_code=415, detail="ZIP does not contain an Android manifest")
        except HTTPException:
            path.unlink(missing_ok=True)
            raise
        except (OSError, zipfile.BadZipFile):
            path.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="upload could not be quarantined")
        finally:
            await file.close()

        store.create(analysis_id)
        task = asyncio.create_task(process_job(analysis_id, path))
        app.state.tasks.add(task)
        task.add_done_callback(app.state.tasks.discard)
        return AnalysisAccepted(analysis_id=analysis_id, state="pending")

    def require_job(analysis_id: str):
        job = store.get(analysis_id)
        if job is None:
            raise HTTPException(status_code=404, detail="analysis not found")
        return job

    @app.get(
        "/v1/analyses/{analysis_id}",
        response_model=AnalysisStatus,
        dependencies=[Depends(authenticate)],
    )
    def get_analysis(analysis_id: str) -> AnalysisStatus:
        return _public_status(require_job(analysis_id))

    @app.get(
        "/v1/analyses/{analysis_id}/report",
        response_model=AndroidAnalysisReport,
        dependencies=[Depends(authenticate)],
    )
    def get_report(analysis_id: str) -> AndroidAnalysisReport:
        job = require_job(analysis_id)
        if job.state != "completed" or job.report is None:
            raise HTTPException(status_code=409, detail=f"analysis is {job.state}")
        return job.report

    return app


app = create_app()
