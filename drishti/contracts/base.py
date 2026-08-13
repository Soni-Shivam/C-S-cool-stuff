"""Base model for every cross-module type.

docs/01_DATA_CONTRACTS.md §0. Two properties do real work here:

`extra="forbid"` — a typo in a field name is an error, not a silently dropped
value. This is what stops three parallel tracks from drifting apart.

`frozen=True` — evidence must be immutable once created. A mutable evidence node
would let a later stage edit what an earlier stage observed, and the hash chain
would be attesting something that no longer matches what was reasoned over.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class DrishtiModel(BaseModel):
    """Immutable, strict base. Every contract model inherits from this."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        use_enum_values=False,
    )


class AnalyserResult(DrishtiModel):
    """Base for any module result that is allowed to come back incomplete.

    Degradation is expressed in DATA, not exceptions (00_GUIDING_MAP.md §9.2). A
    failing sub-analyser sets `partial` and appends to `errors`; it never raises
    past its own boundary, because a failed VLM call must not lose the static
    report.
    """

    errors: tuple[str, ...] = ()
    partial: bool = False
    duration_ms: int = 0
