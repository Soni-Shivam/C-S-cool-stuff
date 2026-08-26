"""`CapturedFlow` — the proxy's own record of what the sample talked to.

docs/01_DATA_CONTRACTS.md A17. Two things are asserted here that the generic
round-trip gate cannot: that a body preview carrying unredacted sensitive text
REFUSES TO CONSTRUCT, and that `ObservationArtifact` actually accepts the flows.
"""

from __future__ import annotations

import pytest

from drishti.contracts.dynamic_trace import CapturedFlow, ObservationArtifact
from tests.unit._observation_builders import metadata

_START = "2026-08-26T10:00:00+00:00"


@pytest.fixture
def minimal_artifact_kwargs() -> dict[str, object]:
    """The required `ObservationArtifact` fields, and nothing else."""
    return {
        "sha256": "a" * 64,
        "outcome": "completed",
        "metadata": metadata(),
        "started_at": _START,
        "finished_at": _START,
    }


def test_captured_flow_round_trips() -> None:
    f = CapturedFlow(
        t_ms_epoch=1_700_000_000_000,
        method="POST",
        scheme="http",
        host="gate.evil.tk",
        path="/register",
        status=200,
        req_body_preview="id=abc",
        resp_body_preview='{"status":"ok"}',
    )
    assert CapturedFlow.model_validate_json(f.model_dump_json()) == f


@pytest.mark.parametrize("field", ["req_body_preview", "resp_body_preview"])
def test_captured_flow_refuses_unredacted_body(field: str) -> None:
    """An unredacted secret must not construct — the gate fails closed, it does not warn.

    Both previews are gated, not just the request: a C2 answering with a credential is
    the same leak in the other direction.
    """
    bodies = {"req_body_preview": "", "resp_body_preview": ""}
    bodies[field] = "password=hunter2"
    with pytest.raises(ValueError, match="unredacted sensitive text"):
        CapturedFlow(
            t_ms_epoch=0,
            method="GET",
            scheme="http",
            host="h",
            path="/",
            status=None,
            **bodies,
        )


def test_served_kind_requires_synthesised() -> None:
    """A provenance label must not be settable on a flow we did not answer.

    `served_kind` names the response shape *we* served. Without the pairing rule it
    could be stamped on an observed flow, and the report would credit our own content
    to attacker infrastructure — exactly the lie A17 exists to prevent.
    """
    with pytest.raises(ValueError, match="served_kind"):
        CapturedFlow(
            t_ms_epoch=0,
            method="GET",
            scheme="http",
            host="gate.evil.tk",
            path="/",
            status=200,
            synthesised=False,
            served_kind="connectivity_ok",
        )


def test_synthesised_flow_carries_its_kind() -> None:
    f = CapturedFlow(
        t_ms_epoch=1,
        method="GET",
        scheme="http",
        host="gate.evil.tk",
        path="/checkin",
        status=200,
        synthesised=True,
        served_kind="connectivity_ok",
    )
    assert (f.synthesised, f.served_kind) == (True, "connectivity_ok")
    assert CapturedFlow.model_validate_json(f.model_dump_json()) == f


def test_synthesised_flow_may_omit_its_kind() -> None:
    """The invariant is one-directional: `synthesised` without a label is still honest."""
    f = CapturedFlow(t_ms_epoch=1, method="GET", scheme="http", host="h", synthesised=True)
    assert f.served_kind is None


def test_served_kind_is_bounded() -> None:
    """It reaches the report as a provenance label; every other str here is bounded."""
    with pytest.raises(ValueError):
        CapturedFlow(
            t_ms_epoch=0,
            method="GET",
            scheme="http",
            host="h",
            synthesised=True,
            served_kind="k" * 33,
        )


def test_artifact_accepts_captured_flows(minimal_artifact_kwargs: dict[str, object]) -> None:
    art = ObservationArtifact(
        **minimal_artifact_kwargs,  # type: ignore[arg-type]
        captured_flows=(
            CapturedFlow(
                t_ms_epoch=1,
                method="GET",
                scheme="http",
                host="h",
                path="/",
                status=200,
                req_body_preview="",
                resp_body_preview="",
            ),
        ),
    )
    assert len(art.captured_flows) == 1
