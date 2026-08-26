"""The pre-computed, grounded, inert C2 responses staged to the detonator.

docs/01_DATA_CONTRACTS.md §A18. Built on the orchestrator, which has LLM egress; read
by the on-VM proxy, which has none — `drishti-runtime` has no NAT, so anything the
proxy answers with must already be on disk before the sample starts running.

An entry always cites the pass-1 evidence it was derived from. The *builder* refuses
to emit an ungrounded one; this contract only carries the field, because the builder
has to be able to construct a candidate and then reject it.
"""

from __future__ import annotations

from drishti.contracts.base import DrishtiModel
from drishti.contracts.dynamic_trace import Sha256


class C2BundleEntry(DrishtiModel):
    """One staged response, and the evidence that justifies serving it.

    Matched on `host` exactly and on `path_prefix` by prefix: a beacon path usually
    carries a per-run id that cannot be predicted off-VM, so an exact path would miss.
    """

    #: Answered for this host only. A bundle built for one C2 must not answer for another.
    host: str
    path_prefix: str = "/"
    #: Response shape, carried through to `CapturedFlow.served_kind` so A17's
    #: provenance line ("this content is ours, not the attacker's") survives.
    response_kind: str
    served_status: int = 200
    served_content_type: str = "application/json"
    #: Already through the inertness gate before it reached the bundle.
    served_body: str = ""
    #: True when this entry stands in for a second-stage download — the one entry a
    #: reader must not mistake for real attacker content.
    is_payload_url: bool = False
    #: Evidence node ids this response was inferred from. Empty is representable so
    #: the builder can construct-and-reject; empty is never emitted.
    derived_from: tuple[str, ...] = ()


class C2Bundle(DrishtiModel):
    """Every staged response for one sample, plus the provenance of the batch."""

    #: The sample this bundle was built for. Serving one sample's answers to another
    #: would fabricate behaviour.
    sha256: Sha256
    entries: tuple[C2BundleEntry, ...] = ()
    #: When the bundle was synthesised, so a stale bundle is visible, not assumed fresh.
    built_at: str = ""
    #: Which model/provider produced it. Empty when unknown.
    synthesis_client: str = ""

    def matches(self, host: str, path: str) -> C2BundleEntry | None:
        """The entry that answers this request, or None if the bundle stays silent.

        Longest `path_prefix` wins; equal-length prefixes resolve to the earlier entry
        in `entries`. The tie-break is declaration order, never iteration accident —
        two runs of the same bundle must answer identically or the trace cannot
        explain the divergence.
        """
        best: C2BundleEntry | None = None
        for entry in self.entries:
            if entry.host != host or not path.startswith(entry.path_prefix):
                continue
            # Strict `>` is the tie-break: an equal-length prefix leaves `best` alone,
            # so the earliest matching entry keeps the slot.
            if best is None or len(entry.path_prefix) > len(best.path_prefix):
                best = entry
        return best
