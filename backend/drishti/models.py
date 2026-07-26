import json

from pydantic import BaseModel, Field


class DrishtiVerdict(BaseModel):
    """Final structured verdict (paper Listing 2)."""
    sha256: str
    threat_score: int
    severity_band: str
    confidence: float
    confidence_label: str
    impersonated_target: str | None = None
    victim_profile: dict = Field(default_factory=dict)
    adversarial_elicitation_deployed: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    iocs: dict = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    summary: str = ""
    provider: str = "mock"
    verified: bool = False
    dynamic_simulated: bool = True


class EvidenceNode(BaseModel):
    id: str
    type: str
    source_tool: str
    content: str
    location: str | None = None
    confidence: float = 1.0
    timestamp: str
    refs: list[str] = Field(default_factory=list)
    prev_hash: str = ""
    hash: str = ""

    def canonical_payload(self) -> str:
        data = self.model_dump(exclude={"hash"})
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
