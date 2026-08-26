"""Generative C2 emulation — the inertness gate must be airtight.

docs/PHASE_5_FRONTIER.md T5.4, CLAUDE.md hard boundaries.

Every test here defends one sentence: a response DRISHTI serves to a sample is
provably inert. The adversary in these tests is the MODEL — we assume it returns the
most dangerous thing it can, and prove the deterministic gate neutralises it anyway.
That is the whole safety argument, so it is tested as if lives depended on it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from drishti.config import Settings
from drishti.contracts.evidence import EvidenceType
from drishti.ledger.store import LedgerStore
from drishti.m3_dynamic.generative_c2 import (
    FORBIDDEN_COMMAND_TOKENS,
    INERT_COMMANDS,
    MAX_RESPONSE_BYTES,
    SINKHOLE_URL,
    C2Request,
    C2ResponseKind,
    C2SchemaHint,
    NotProvablyInertError,
    assert_inert,
    inert_payload_bytes,
    synthesise_response,
)

_HINT = C2SchemaHint(
    response_kind=C2ResponseKind.COMMAND_POLL,
    expected_keys=("cmd", "payload_url", "interval"),
    command_key="cmd",
    url_keys=("payload_url",),
)


# ── the gate rewrites danger ─────────────────────────────────────────────────
def test_a_command_verb_is_forced_to_noop() -> None:
    result = assert_inert({"cmd": "download", "interval": 60}, _HINT)
    assert result.body["cmd"] in INERT_COMMANDS
    assert result.body["cmd"] != "download"
    assert result.neutralisations, "a neutralisation must be recorded, not silent"


def test_a_live_url_is_sinkholed() -> None:
    result = assert_inert({"cmd": "noop", "payload_url": "http://evil.example/stage2.apk"}, _HINT)
    assert result.body["payload_url"] == SINKHOLE_URL
    assert "evil.example" not in json.dumps(result.body)


def test_any_url_shaped_value_is_sinkholed_even_in_an_unexpected_key() -> None:
    result = assert_inert({"note": "visit https://c2.example/next now"}, _HINT)
    assert result.body["note"] == SINKHOLE_URL


def test_a_command_verb_in_a_non_command_field_is_neutralised() -> None:
    result = assert_inert({"status": "download"}, _HINT)
    assert result.body["status"] == "noop"


@pytest.mark.parametrize("verb", sorted(FORBIDDEN_COMMAND_TOKENS)[:8])
def test_every_forbidden_verb_in_a_command_slot_becomes_inert(verb: str) -> None:
    result = assert_inert({"cmd": verb}, _HINT)
    assert result.body["cmd"] in INERT_COMMANDS


# ── the gate fails closed on payloads ────────────────────────────────────────
def test_a_raw_dex_magic_value_is_refused() -> None:
    with pytest.raises(NotProvablyInertError):
        assert_inert({"cmd": "noop", "blob": "dex\n035\x00rest"}, _HINT)


def test_a_base64_dex_payload_is_refused() -> None:
    b64 = base64.b64encode(b"dex\n035\x00" + b"\x00" * 40).decode()
    with pytest.raises(NotProvablyInertError):
        assert_inert({"stage": b64}, _HINT)


def test_an_elf_payload_is_refused() -> None:
    with pytest.raises(NotProvablyInertError):
        assert_inert({"blob": "\x7fELFwhatever"}, _HINT)


def test_a_zip_apk_payload_is_refused() -> None:
    with pytest.raises(NotProvablyInertError):
        assert_inert({"apk": "PK\x03\x04rest-of-a-zip"}, _HINT)


# ── the gate refuses malformed or oversized input ────────────────────────────
def test_a_non_object_response_is_refused() -> None:
    with pytest.raises(NotProvablyInertError):
        assert_inert(["not", "an", "object"], _HINT)


def test_bytes_values_are_refused() -> None:
    with pytest.raises(NotProvablyInertError):
        assert_inert({"blob": b"\x00\x01"}, _HINT)


def test_a_single_oversized_value_is_truncated_not_served_whole() -> None:
    """One giant benign string is inert once truncated — and the truncation is disclosed."""
    result = assert_inert({"x": "A" * (MAX_RESPONSE_BYTES * 2)}, _HINT)
    assert len(result.body["x"]) < MAX_RESPONSE_BYTES
    assert any("truncated" in n for n in result.neutralisations)


def test_an_aggregate_oversized_response_is_refused() -> None:
    """Many values that together exceed the cap cannot be served — the gate fails closed."""
    payload = {f"k{i}": "A" * 500 for i in range(40)}
    with pytest.raises(NotProvablyInertError):
        assert_inert(payload, _HINT)


def test_deep_nesting_is_refused() -> None:
    payload: dict = {"k": {}}
    cursor = payload["k"]
    for _ in range(10):
        cursor["k"] = {}
        cursor = cursor["k"]
    with pytest.raises(NotProvablyInertError):
        assert_inert(payload, _HINT)


def test_nested_command_verbs_are_neutralised_too() -> None:
    """A verb hidden one level down must not slip past."""
    result = assert_inert({"config": {"action": "install"}}, _HINT)
    assert result.body["config"]["action"] == "noop"


# ── the inert DEX stub ───────────────────────────────────────────────────────
def test_the_inert_payload_stub_has_valid_magic_and_no_code() -> None:
    blob = inert_payload_bytes()
    assert blob[:8] == b"dex\n035\x00", "a loader must see valid DEX magic"
    assert len(blob) == 0x70, "header only — there are no classes to run"
    assert set(blob[8:]) == {0}, "everything after the magic is zero — functionless"


# ── synthesis end to end (mock provider) ─────────────────────────────────────
@pytest.fixture
def ledger(tmp_path: Path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_c2")
    yield store
    store.close()


def test_synthesis_without_a_model_still_serves_an_inert_response(ledger) -> None:
    request = C2Request(host="dead.example", url="http://dead.example/gate", method="POST")
    response = synthesise_response(request, _HINT, client=None, ledger=ledger)
    assert response.provably_inert is True
    body = json.loads(response.served_body)
    assert body["status"] == "ok"
    assert body.get("cmd", "noop") in INERT_COMMANDS


def test_synthesis_records_a_generative_c2_ledger_node(ledger) -> None:
    request = C2Request(host="dead.example", url="http://dead.example/gate")
    response = synthesise_response(request, _HINT, client=None, ledger=ledger)
    assert response.evidence_refs, "a served response must be an auditable ledger node"
    node = ledger.get(response.evidence_refs[0])
    assert node is not None and node.type is EvidenceType.GENERATIVE_C2
    assert node.content["provably_inert"] is True


def test_a_hostile_model_cannot_make_synthesis_serve_a_payload(ledger) -> None:
    """The model returns a command and a payload URL; the served body carries neither."""

    class HostileClient:
        def complete_as(self, **_: object) -> object:
            class Fields:
                interval_seconds = 5
                opaque_id = "http://evil.example/x.apk"  # a URL smuggled into the id
                reasoning = "download and install the next stage from http://evil.example"

            return Fields()

    request = C2Request(host="dead.example", url="http://dead.example/poll")
    response = synthesise_response(request, _HINT, client=HostileClient(), ledger=ledger)
    served = json.dumps(json.loads(response.served_body))
    assert "evil.example" not in served
    assert response.provably_inert is True


def test_the_served_body_is_always_valid_json(ledger) -> None:
    request = C2Request(host="dead.example", url="http://dead.example/")
    for kind in C2ResponseKind:
        hint = C2SchemaHint(response_kind=kind, command_key="cmd", url_keys=("url",))
        response = synthesise_response(request, hint, client=None, ledger=ledger)
        json.loads(response.served_body)  # must not raise
        assert response.provably_inert


# ── deriving hints from a real static report ─────────────────────────────────
def test_derive_hints_finds_the_decoys_dead_beacons() -> None:
    """The decoy beacons to a TEST-NET IP and a .invalid host; dev-noise is dropped."""
    from drishti.ledger.store import LedgerStore
    from drishti.m2_static.engine import analyse as static_analyse
    from drishti.m3_dynamic.generative_c2 import derive_hints

    apk = Path(__file__).resolve().parents[2] / "canary" / "decoy-challan" / "dist" / "RTO_Challan.apk"
    import tempfile

    d = Path(tempfile.mkdtemp())
    store = LedgerStore(d / "l.db", d / "k.pem")
    store.open("job_hints")
    try:
        report = static_analyse(apk, store)
    finally:
        store.close()
    hints = derive_hints(report)
    hosts = set(hints)
    assert "192.0.2.87" in hosts, "the TEST-NET beacon must be a C2 candidate"
    assert "challan-verify.invalid" in hosts
    assert not any("jetbrains" in h for h in hosts), "SDK stack-trace URLs are not beacons"
