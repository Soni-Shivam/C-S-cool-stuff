"""The orchestrator-side C2 bundle builder, and `synthesise_response(fill=...)`.

The builder is the first code in the frontier path that actually spends an LLM call, so
these tests pin the four properties that make spending one defensible: it answers only
the sample's own beacons, it answers each host once, it never emits an entry it cannot
ground in pass-1 evidence, and two builds of the same flows produce the same bundle.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from drishti.contracts.c2_bundle import C2Bundle
from drishti.contracts.dynamic_trace import CapturedFlow, SyntheticC2Response
from drishti.m3_dynamic import c2_bundle as builder_module
from drishti.m3_dynamic.c2_bundle import build_c2_bundle
from drishti.m3_dynamic.generative_c2 import (
    C2Request,
    C2ResponseKind,
    C2SchemaHint,
    synthesise_response,
)

SHA = "a" * 64


def _static(urls=(), crypto=(), pkg=(), refs=()):
    return SimpleNamespace(
        urls=list(urls),
        crypto_constants=list(crypto),
        package_strings=list(pkg),
        ledger_refs=list(refs),
    )


def _flow(host, path="/checkin", method="GET"):
    return CapturedFlow(
        t_ms_epoch=1,
        method=method,
        scheme="http",
        host=host,
        path=path,
        status=None,
        req_body_preview="",
        resp_body_preview="",
    )


class _CountingClient:
    """A client that answers nothing, so the canned inert fallback is exercised."""

    def __init__(self) -> None:
        self.calls = 0

    def complete_as(self, **_kwargs):
        self.calls += 1
        return None


# ── the brief's four ──────────────────────────────────────────────────────────
def test_fill_short_circuits_the_model():
    # fill is used verbatim (then inert-checked); no client is consulted
    r = synthesise_response(
        C2Request(host="h", url="http://h/checkin"),
        C2SchemaHint(),
        fill={"interval": 60, "id": "x", "reasoning": "pre"},
    )
    assert r.provably_inert and r.reasoning == "pre"


def test_fill_wins_over_a_client_so_there_is_one_code_path():
    """`fill` short-circuits `_ask_model` entirely — a supplied client is never called."""
    client = _CountingClient()
    response = synthesise_response(
        C2Request(host="h", url="http://h/checkin"),
        C2SchemaHint(response_kind=C2ResponseKind.COMMAND_POLL),
        client=client,
        fill={"interval": 60, "id": "x", "reasoning": "pre"},
    )
    assert client.calls == 0
    assert response.provably_inert
    assert '"interval": 60' in response.served_body


def test_builder_drops_noise_hosts():
    flows = [_flow("clients3.google.com"), _flow("gate.evil.tk", "/register")]
    bundle = build_c2_bundle(
        SHA, flows, _static(urls=["hxxp://gate.evil.tk/register"], refs=["ledger://n1"])
    )
    hosts = {e.host for e in bundle.entries}
    assert "clients3.google.com" not in hosts
    assert "gate.evil.tk" in hosts


def test_builder_refuses_ungrounded_entry():
    # a beacon host with no static evidence ref -> no derived_from -> dropped
    flows = [_flow("gate.evil.tk", "/register")]
    bundle = build_c2_bundle(SHA, flows, _static(urls=[], refs=[]))
    assert bundle.entries == ()


def test_builder_one_call_per_host_budget():
    client = _CountingClient()
    flows = [_flow("gate.evil.tk", "/a"), _flow("gate.evil.tk", "/b"), _flow("c2.bad.su", "/x")]
    build_c2_bundle(
        SHA,
        flows,
        _static(urls=["hxxp://gate.evil.tk/a", "hxxp://c2.bad.su/x"], refs=["ledger://n"]),
        client=client,
    )
    assert client.calls <= 2  # one per distinct beacon host, not per flow


# ── R1: response_kind must be a real C2ResponseKind member ────────────────────
def test_builder_drops_an_entry_whose_kind_is_not_in_the_enum(monkeypatch):
    """`served_kind` is a free-form 32-char string downstream; the enum is the real gate.

    An unknown kind means the provenance label the report renders would be unbacked, so
    the entry is dropped and the proxy's sinkhole fallback answers instead — fail safe.
    """

    def _bogus(request, hint, *, client=None, ledger=None, fill=None):
        return SyntheticC2Response(
            host=request.host,
            url=request.url,
            response_kind="totally_invented_kind",
            served_body='{"status": "ok"}',
            provably_inert=True,
            evidence_refs=("ledger://n1",),
        )

    monkeypatch.setattr(builder_module, "synthesise_response", _bogus)
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", "/register")],
        _static(urls=["hxxp://gate.evil.tk/register"], refs=["ledger://n1"]),
    )
    assert bundle.entries == ()


def test_builder_keeps_an_entry_whose_kind_is_in_the_enum():
    """The control for the test above: a real kind survives and is carried verbatim."""
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", "/register")],
        _static(urls=["hxxp://gate.evil.tk/register"], refs=["ledger://n1"]),
    )
    assert len(bundle.entries) == 1
    assert bundle.entries[0].response_kind in {k.value for k in C2ResponseKind}


def test_builder_drops_a_non_inert_entry(monkeypatch):
    """Provable inertness is the gate: a response that failed it is never served."""

    def _not_inert(request, hint, *, client=None, ledger=None, fill=None):
        return SyntheticC2Response(
            host=request.host,
            url=request.url,
            response_kind=C2ResponseKind.CONNECTIVITY_OK.value,
            served_body='{"status": "ok"}',
            provably_inert=False,
            evidence_refs=("ledger://n1",),
        )

    monkeypatch.setattr(builder_module, "synthesise_response", _not_inert)
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", "/register")],
        _static(urls=["hxxp://gate.evil.tk/register"], refs=["ledger://n1"]),
    )
    assert bundle.entries == ()


# ── R2: determinism ───────────────────────────────────────────────────────────
def _determinism_inputs():
    flows = [
        _flow("gate.evil.tk", "/register"),
        _flow("c2.bad.su", "/poll"),
        _flow("gate.evil.tk", "/checkin"),
        _flow("panel.worse.xyz", "/api/task"),
        _flow("clients3.google.com", "/generate_204"),
    ]
    static = _static(
        urls=[
            "hxxp://gate.evil.tk/register",
            "hxxp://c2.bad.su/poll",
            "hxxp://panel.worse.xyz/api/task",
        ],
        refs=["ledger://n1", "ledger://n2"],
    )
    return flows, static


def test_two_builds_over_the_same_flows_are_byte_identical():
    """`C2Bundle.matches()` only promises a deterministic answer for deterministic
    `entries`. If the builder materialised entries out of a set, two runs of the same
    sample could order equal-length prefixes differently and the detonation would
    diverge upstream of the contract's guarantee. `built_at` is a clock reading and is
    excluded from the comparison; everything else must be identical bytes."""
    flows, static = _determinism_inputs()
    first = build_c2_bundle(SHA, flows, static)
    second = build_c2_bundle(SHA, flows, static)
    assert first.model_dump_json(exclude={"built_at"}) == second.model_dump_json(
        exclude={"built_at"}
    )
    assert len(first.entries) == 3


def test_hint_derivation_does_not_depend_on_hash_order():
    """The upstream half of determinism. `derive_hints` picks `command_key` out of a
    frozenset; unsorted, that pick varies with the per-process string hash seed, so the
    same sample produced a different hint — and a different `GENERATIVE_C2` ledger node —
    on every run. Pinned here because the symptom only shows across processes."""
    from drishti.m3_dynamic.generative_c2 import _COMMAND_KEY_HINTS, derive_hints

    static = _static(
        urls=["hxxp://gate.evil.tk/register"], pkg=sorted(_COMMAND_KEY_HINTS, reverse=True)
    )
    hint = derive_hints(static)["gate.evil.tk"]
    assert hint.command_key == min(_COMMAND_KEY_HINTS)


def test_entry_order_follows_first_observation_order():
    """Determinism with a witness: the order is the pass-1 observation order, not an
    accident of iteration, so a reader can explain why one prefix won a tie."""
    flows, static = _determinism_inputs()
    bundle = build_c2_bundle(SHA, flows, static)
    assert [e.host for e in bundle.entries] == ["gate.evil.tk", "c2.bad.su", "panel.worse.xyz"]


# ── R3: path_prefix comes from the clean leading portion of a redacted path ────
def test_path_prefix_truncates_at_the_redaction_marker():
    """`CapturedFlow.path` is redacted, and the CREDENTIAL rule's `[^\\s,;]{2,}` eats the
    rest of the path because URL paths carry no whitespace:

        raw       /log/password=hunter2/next
        redacted  /log/[REDACTED:CREDENTIAL]

    A prefix built from the redacted form can never match the live request, so the entry
    would be dead weight. `/log/` matches, is honestly broader than the true endpoint,
    and is what the builder must produce."""
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", "/log/[REDACTED:CREDENTIAL]")],
        _static(urls=["hxxp://gate.evil.tk/log"], refs=["ledger://n1"]),
    )
    assert len(bundle.entries) == 1
    assert bundle.entries[0].path_prefix == "/log/"
    assert bundle.matches("gate.evil.tk", "/log/password=hunter2/next") is not None


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/log/[REDACTED:CREDENTIAL]", "/log/"),
        ("[REDACTED:CREDENTIAL]", "/"),  # nothing clean survives -> answer the whole host
        ("/register", "/register"),
        ("", "/"),
        ("/a[REDACTED:TOKEN]/b[REDACTED:TOKEN]", "/a"),  # first marker wins
    ],
)
def test_clean_path_prefix_cases(path, expected):
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", path)] if path else [_flow("gate.evil.tk", "/")],
        _static(urls=["hxxp://gate.evil.tk/register"], refs=["ledger://n1"]),
    )
    assert bundle.entries[0].path_prefix == expected


# ── R4: ungrounded entries are refused ────────────────────────────────────────
def test_builder_refuses_an_entry_with_empty_derived_from(monkeypatch):
    """The contract lets an empty `derived_from` be *constructed* so the builder can
    build-then-reject. This is the builder doing the rejecting: the host IS grounded (the
    static report carries refs, so the call is worth making) but the synthesis came back
    citing nothing. There is no fallback to the hint's refs — an entry that lost its
    grounding somewhere in synthesis is dropped rather than re-grounded by assumption."""

    def _unref(request, hint, *, client=None, ledger=None, fill=None):
        assert hint.evidence_refs  # the host cleared the pre-call grounding check
        return SyntheticC2Response(
            host=request.host,
            url=request.url,
            response_kind=C2ResponseKind.CONNECTIVITY_OK.value,
            served_body='{"status": "ok"}',
            provably_inert=True,
            evidence_refs=(),
        )

    monkeypatch.setattr(builder_module, "synthesise_response", _unref)
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", "/register")],
        _static(urls=["hxxp://gate.evil.tk/register"], refs=["ledger://n1"]),
    )
    assert bundle.entries == ()


def test_an_ungrounded_host_costs_no_model_call():
    """Grounding is checked BEFORE the call, not only after it. A host with a hint but no
    evidence ref can never produce an emittable entry, so paying a call to find that out
    would spend the job's budget on a foregone conclusion."""
    client = _CountingClient()
    bundle = build_c2_bundle(
        SHA,
        [_flow("gate.evil.tk", "/register")],
        # a hint IS derived for this host — it just has no ledger ref behind it
        _static(urls=["hxxp://gate.evil.tk/register"], refs=[]),
        client=client,
    )
    assert bundle.entries == ()
    assert client.calls == 0


def test_every_emitted_entry_is_grounded():
    flows, static = _determinism_inputs()
    bundle = build_c2_bundle(SHA, flows, static)
    assert bundle.entries
    assert all(e.derived_from for e in bundle.entries)


# ── budget and degradation ────────────────────────────────────────────────────
def test_max_calls_is_clamped_to_the_job_budget():
    """CLAUDE.md rule 10: budgets are asserts, not hopes. A caller cannot raise the cap."""
    client = _CountingClient()
    flows = [_flow(f"c2-{i}.bad.su", "/poll") for i in range(30)]
    static = _static(urls=[f"hxxp://c2-{i}.bad.su/poll" for i in range(30)], refs=["ledger://n1"])
    build_c2_bundle(SHA, flows, static, client=client, max_calls=999)
    assert client.calls <= 25


def test_a_failing_ledger_yields_a_partial_bundle_not_an_exception():
    """A refused or broken dependency degrades to fewer entries; it never fails the
    detonation, which is the expensive thing this whole pass exists to protect."""

    class _BoomLedger:
        def append(self, **_kwargs):
            raise RuntimeError("ledger unavailable")

    flows, static = _determinism_inputs()
    bundle = build_c2_bundle(SHA, flows, static, ledger=_BoomLedger())
    assert isinstance(bundle, C2Bundle)
    assert bundle.entries == ()
    assert bundle.sha256 == SHA


def test_a_failing_client_still_produces_inert_entries():
    """A provider outage is absorbed inside `synthesise_response`; the canned
    `connectivity_ok` body is inert by construction, so the bundle is still useful."""

    class _BoomClient:
        def complete_as(self, **_kwargs):
            raise RuntimeError("provider down")

    flows, static = _determinism_inputs()
    bundle = build_c2_bundle(SHA, flows, static, client=_BoomClient())
    assert len(bundle.entries) == 3
    assert all(e.served_body for e in bundle.entries)


def test_bundle_records_its_provenance():
    flows, static = _determinism_inputs()
    bundle = build_c2_bundle(SHA, flows, static, client=_CountingClient())
    assert bundle.built_at.endswith("Z")
    assert bundle.synthesis_client == "_CountingClient"
    assert build_c2_bundle(SHA, flows, static).synthesis_client == "none"


def test_payload_stub_entries_are_flagged():
    """`is_payload_url` marks the one entry a reader must not mistake for real attacker
    content. It is read off the kind actually served, not the kind hoped for."""
    flows = [_flow("gate.evil.tk", "/dl")]
    static = _static(urls=["hxxp://gate.evil.tk/dl"], pkg=["payload_url"], refs=["ledger://n1"])
    bundle = build_c2_bundle(SHA, flows, static)
    assert len(bundle.entries) == 1
    entry = bundle.entries[0]
    assert entry.response_kind == C2ResponseKind.INERT_PAYLOAD_STUB.value
    assert entry.is_payload_url is True
