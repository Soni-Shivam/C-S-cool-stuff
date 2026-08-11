from abc import ABC, abstractmethod
from datetime import datetime, timezone
from threading import RLock

from drishti.api.models import AnalysisJob


class JobStore(ABC):
    @abstractmethod
    def create(self, analysis_id: str) -> AnalysisJob: ...

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisJob | None: ...

    @abstractmethod
    def update(self, analysis_id: str, **changes) -> AnalysisJob: ...


class InMemoryJobStore(JobStore):
    """Thread-safe local-demo store; replace with a durable implementation in production."""

    def __init__(self) -> None:
        self._jobs: dict[str, AnalysisJob] = {}
        self._lock = RLock()

    def create(self, analysis_id: str) -> AnalysisJob:
        now = datetime.now(timezone.utc)
        job = AnalysisJob(
            analysis_id=analysis_id, state="pending", created_at=now, updated_at=now
        )
        with self._lock:
            self._jobs[analysis_id] = job
        return job.model_copy(deep=True)

    def get(self, analysis_id: str) -> AnalysisJob | None:
        with self._lock:
            job = self._jobs.get(analysis_id)
            return job.model_copy(deep=True) if job else None

    def update(self, analysis_id: str, **changes) -> AnalysisJob:
        with self._lock:
            current = self._jobs[analysis_id]
            changes["updated_at"] = datetime.now(timezone.utc)
            updated = current.model_copy(update=changes)
            self._jobs[analysis_id] = updated
            return updated.model_copy(deep=True)
