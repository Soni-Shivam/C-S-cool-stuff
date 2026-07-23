import json

from pydantic import BaseModel, Field


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
