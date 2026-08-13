from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from drishti.reporting.models import AndroidAnalysisReport

JobState = Literal["pending", "running", "completed", "failed"]


class AnalysisAccepted(BaseModel):
    analysis_id: str
    state: JobState


class AnalysisStatus(BaseModel):
    analysis_id: str
    state: JobState
    created_at: datetime
    updated_at: datetime
    sha256: str | None = None
    error: str | None = None


class AnalysisJob(AnalysisStatus):
    report: AndroidAnalysisReport | None = None
