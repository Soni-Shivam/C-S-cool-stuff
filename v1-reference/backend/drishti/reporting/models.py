from typing import Literal

from pydantic import BaseModel, Field


class EvidenceReference(BaseModel):
    id: str
    type: str
    source: str
    statement: str
    location: str | None = None
    confidence: float
    provenance: Literal["static", "ml", "genai", "simulated", "observed", "scoring"]


class CitedStatement(BaseModel):
    text: str
    evidence_refs: list[str] = Field(default_factory=list)


class CapabilityFinding(CitedStatement):
    capability_id: str
    permissions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class Indicator(BaseModel):
    kind: str
    value: str
    evidence_refs: list[str]


class ConfidenceReport(BaseModel):
    value: float
    label: str


class ProvenanceReport(BaseModel):
    static_analysis: Literal["completed"] = "completed"
    ml_model_version: str
    gemini_status: Literal["live", "mock"]
    dynamic_status: Literal["absent", "simulated", "observed"]
    notice: str


class AndroidAnalysisReport(BaseModel):
    schema_version: str = "1.0"
    analysis_id: str
    sha256: str
    threat_score: int
    severity: str
    confidence: ConfidenceReport
    provenance: ProvenanceReport
    genai_summary: CitedStatement
    potential_consequences: list[CitedStatement] = Field(default_factory=list)
    suspicious_permissions: list[str] = Field(default_factory=list)
    suspicious_capabilities: list[CapabilityFinding] = Field(default_factory=list)
    mitre_mobile_techniques: list[CitedStatement] = Field(default_factory=list)
    iocs: list[Indicator] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    safety_notice: str = (
        "DRISHTI is decision support. Stock Android requires the user to approve installation."
    )
