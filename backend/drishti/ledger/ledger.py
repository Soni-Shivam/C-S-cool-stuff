import hashlib

from drishti.models import EvidenceNode

GENESIS = "0" * 64


class Ledger:
    def __init__(self) -> None:
        self._nodes: list[EvidenceNode] = []

    @property
    def nodes(self) -> list[EvidenceNode]:
        return list(self._nodes)

    @property
    def head_hash(self) -> str:
        return self._nodes[-1].hash if self._nodes else GENESIS

    def _compute_hash(self, node: EvidenceNode) -> str:
        return hashlib.sha256(
            (node.prev_hash + node.canonical_payload()).encode()
        ).hexdigest()

    def append(
        self,
        type: str,
        source_tool: str,
        content: str,
        *,
        location: str | None = None,
        confidence: float = 1.0,
        timestamp: str,
        refs: list[str] | None = None,
    ) -> EvidenceNode:
        node = EvidenceNode(
            id=f"n{len(self._nodes) + 1}",
            type=type,
            source_tool=source_tool,
            content=content,
            location=location,
            confidence=confidence,
            timestamp=timestamp,
            refs=refs or [],
            prev_hash=self.head_hash,
        )
        node.hash = self._compute_hash(node)
        self._nodes.append(node)
        return node

    def verify_chain(self) -> bool:
        prev = GENESIS
        for node in self._nodes:
            if node.prev_hash != prev:
                return False
            if self._compute_hash(node) != node.hash:
                return False
            prev = node.hash
        return True
