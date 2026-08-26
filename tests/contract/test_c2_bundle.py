"""The staged Generative C2 bundle round-trips, and its match is deterministic.

docs/01_DATA_CONTRACTS.md §A18. The on-VM proxy cannot reach an LLM, so it reads this
bundle instead of generating anything. That makes two properties matter: the bundle
must survive the trip across the VM boundary as JSON, and `matches()` must pick the
same entry every run — a detonation that answered differently on a re-run would leave
nothing in the trace to explain the divergence.
"""

from __future__ import annotations

from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry

SHA = "a" * 64


def test_bundle_round_trips() -> None:
    b = C2Bundle(
        sha256=SHA,
        built_at="2026-08-26T00:00:00Z",
        synthesis_client="groq/llama",
        entries=(
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/reg",
                response_kind="registration_ack",
                served_status=200,
                served_content_type="application/json",
                served_body='{"status":"ok"}',
                derived_from=("ledger://0x1",),
            ),
        ),
    )
    assert C2Bundle.model_validate_json(b.model_dump_json()) == b


def test_matches_longest_prefix() -> None:
    e_short = C2BundleEntry(
        host="h",
        path_prefix="/",
        response_kind="connectivity_ok",
        served_status=200,
        served_content_type="application/json",
        served_body="{}",
        derived_from=("ledger://x",),
    )
    e_long = C2BundleEntry(
        host="h",
        path_prefix="/api/v2",
        response_kind="config",
        served_status=200,
        served_content_type="application/json",
        served_body="{}",
        derived_from=("ledger://y",),
    )
    b = C2Bundle(sha256="b" * 64, built_at="t", entries=(e_short, e_long))
    assert b.matches("h", "/api/v2/poll") is e_long
    assert b.matches("h", "/other") is e_short
    assert b.matches("other", "/") is None


def test_matches_is_order_independent_for_distinct_lengths() -> None:
    """The longest prefix wins regardless of where it sits in `entries`."""
    e_short = C2BundleEntry(host="h", path_prefix="/", response_kind="connectivity_ok")
    e_long = C2BundleEntry(host="h", path_prefix="/api", response_kind="config")
    forward = C2Bundle(sha256=SHA, entries=(e_short, e_long))
    reverse = C2Bundle(sha256=SHA, entries=(e_long, e_short))
    assert forward.matches("h", "/api/poll") is e_long
    assert reverse.matches("h", "/api/poll") is e_long


def test_equal_length_prefixes_resolve_by_declaration_order() -> None:
    """A17/A18 tie-break: equal-length prefixes resolve to the earlier entry.

    Two entries can legitimately claim prefixes of the same length. Leaving that to
    iteration accident would make two runs of the same bundle answer differently.
    """
    first = C2BundleEntry(host="h", path_prefix="/api", response_kind="config")
    second = C2BundleEntry(host="h", path_prefix="/api", response_kind="command_poll")
    assert C2Bundle(sha256=SHA, entries=(first, second)).matches("h", "/api/x") is first
    assert C2Bundle(sha256=SHA, entries=(second, first)).matches("h", "/api/x") is second


def test_empty_derived_from_is_representable() -> None:
    """The contract carries grounding; it does not enforce it.

    The builder refuses to *emit* an ungrounded entry, which means it must be able to
    construct a candidate and then reject it. A validator here would make that a crash.
    """
    entry = C2BundleEntry(host="h", response_kind="connectivity_ok")
    assert entry.derived_from == ()
    assert entry.path_prefix == "/"


def test_bundle_is_frozen() -> None:
    b = C2Bundle(sha256=SHA)
    try:
        b.entries = ()  # type: ignore[misc]
    except Exception as exc:  # pragma: no cover - message asserted below
        assert "frozen" in str(exc) or "immutable" in str(exc)
    else:  # pragma: no cover - a mutable contract is the failure
        raise AssertionError("C2Bundle must be frozen")
