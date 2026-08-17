"""Hash-chain integrity, append-only enforcement, and tamper detection.

docs/01_DATA_CONTRACTS.md §9.2, docs/PHASE_0_FOUNDATIONS.md T0.4. CI gate.

`test_tamper_detected_at_exact_seq` is a demo asset: it runs in well under a second
and proves the trust claim better than any slide.
"""

from __future__ import annotations

import itertools
import json
import sqlite3
from pathlib import Path

import pytest

from drishti.contracts.evidence import EvidenceType
from drishti.ledger import crypto
from drishti.ledger.store import (
    APPEND_ONLY_TRIGGERS,
    LedgerStore,
    MissingParentError,
    UngroundedClaimError,
)

JOB = "job_01932ab90e2f"


@pytest.fixture
def store(tmp_path):
    ledger = LedgerStore(tmp_path / "ledger.db", tmp_path / "key.pem")
    ledger.open(JOB)
    yield ledger
    ledger.close()


def _append_n(store: LedgerStore, count: int):
    return [
        store.append(
            type=EvidenceType.MANIFEST_ENTRY,
            source_tool="androguard",
            content={"permission": f"android.permission.PERM_{i}", "index": i},
            location=f"AndroidManifest.xml#L{i}",
            confidence=1.0,
        )
        for i in range(count)
    ]


def _raw_update(db_path, node_id: str, **columns) -> None:
    """Tamper with a row, defeating the append-only triggers to do it.

    The triggers have to be dropped first, which is the point: they stop an
    application or a careless operator, but they cannot stop someone with write
    access to the file. The hash chain is the layer that catches that person, and
    this helper exists to prove it rather than assert it.
    """
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        for trigger in APPEND_ONLY_TRIGGERS:
            conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        assignments = ", ".join(f"{k} = ?" for k in columns)
        conn.execute(
            f"UPDATE evidence SET {assignments} WHERE id = ?",
            (*columns.values(), node_id),
        )
    finally:
        conn.close()


# ── chain construction ───────────────────────────────────────────────────────
def test_genesis_node_links_to_zeros(store) -> None:
    node = _append_n(store, 1)[0]
    assert node.seq == 0
    assert node.prev_hash == crypto.GENESIS_HASH


def test_chain_is_contiguous_and_linked(store) -> None:
    nodes = _append_n(store, 50)
    assert [n.seq for n in nodes] == list(range(50))
    for previous, current in itertools.pairwise(nodes):
        assert current.prev_hash == previous.node_hash


def test_fifty_node_chain_verifies(store) -> None:
    _append_n(store, 50)
    result = store.verify_chain()
    assert result.ok is True
    assert result.node_count == 50
    assert result.first_bad_seq is None


# NOTE: `test_empty_chain_verifies` used to live here, asserting that an empty chain
# is "vacuously valid, not an error". That was reversed deliberately — see
# `test_empty_chain_does_not_verify` at the end of this file. The result of
# verify_chain() is rendered to a human as a trust signal, and a green badge on a job
# that produced no evidence is indistinguishable from a real one.


# ── the tamper test ──────────────────────────────────────────────────────────
def test_tamper_detected_at_exact_seq(store) -> None:
    """Editing node 17's content is caught, and reported as seq 17 precisely."""
    nodes = _append_n(store, 50)
    _raw_update(store.db_path, nodes[17].id, content=json.dumps({"evil": True}))

    result = store.verify_chain()

    assert result.ok is False
    assert result.first_bad_seq == 17
    assert result.reason is not None and "tampered" in result.reason


def test_tamper_on_any_field_is_detected(store) -> None:
    """Every hashed field is covered, not just `content`.

    A chain that only protected `content` would let an attacker relabel which tool
    produced a finding, or move a citation, without detection.
    """
    for column, value, index in [
        ("source_tool", "totally-legit-tool", 3),
        ("confidence", 0.01, 5),
        ("location", "SomeOtherFile.xml#L1", 7),
        ("timestamp", "1999-01-01T00:00:00.000Z", 9),
        ("parents", json.dumps(["ev_fabricated"]), 11),
    ]:
        ledger = LedgerStore(
            store.db_path.parent / f"t_{column}.db", store.db_path.parent / "key.pem"
        )
        ledger.open(JOB)
        nodes = _append_n(ledger, 15)
        _raw_update(ledger.db_path, nodes[index].id, **{column: value})

        result = ledger.verify_chain()
        assert result.ok is False, f"tampering with {column} was NOT detected"
        assert result.first_bad_seq == index, f"{column}: wrong seq reported"
        ledger.close()


def test_deleting_a_node_is_detected_as_a_gap(store) -> None:
    """Removing a node breaks contiguity and is reported at the gap."""
    nodes = _append_n(store, 20)
    conn = sqlite3.connect(store.db_path, isolation_level=None)
    for trigger in APPEND_ONLY_TRIGGERS:
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    conn.execute("DELETE FROM evidence WHERE id = ?", (nodes[12].id,))
    conn.close()

    result = store.verify_chain()
    assert result.ok is False
    assert result.first_bad_seq == 13, "the gap should be reported at the first shifted seq"


def test_forged_signature_is_detected(store) -> None:
    """Recomputing the hash is not enough — the signature must also verify.

    This is the attacker who understood the hash chain but does not have the key.
    """
    nodes = _append_n(store, 10)
    tampered_content = json.dumps({"evil": True})
    payload = {
        "id": nodes[4].id,
        "job_id": JOB,
        "seq": 4,
        "type": nodes[4].type.value,
        "source_tool": nodes[4].source_tool,
        "content": json.loads(tampered_content),
        "location": nodes[4].location,
        "confidence": nodes[4].confidence,
        "parents": list(nodes[4].parents),
        "timestamp": nodes[4].timestamp,
        "prev_hash": nodes[4].prev_hash,
    }
    _raw_update(
        store.db_path,
        nodes[4].id,
        content=tampered_content,
        node_hash=crypto.node_hash(payload),  # hash recomputed to match the lie
    )

    result = store.verify_chain()
    assert result.ok is False
    assert result.first_bad_seq == 4
    assert result.reason is not None and "signature" in result.reason


# ── append-only enforcement in SQL ───────────────────────────────────────────
def test_sql_trigger_blocks_update(store) -> None:
    nodes = _append_n(store, 1)
    conn = sqlite3.connect(store.db_path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE evidence SET content = '{}' WHERE id = ?", (nodes[0].id,))
    finally:
        conn.close()


def test_sql_trigger_blocks_delete(store) -> None:
    nodes = _append_n(store, 1)
    conn = sqlite3.connect(store.db_path, isolation_level=None)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM evidence WHERE id = ?", (nodes[0].id,))
    finally:
        conn.close()


def test_triggers_exist_in_schema(store) -> None:
    """Guards against a future migration quietly dropping them."""
    rows = store._conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall()
    names = {r["name"] for r in rows}
    assert set(APPEND_ONLY_TRIGGERS) <= names


# ── parents ──────────────────────────────────────────────────────────────────
def test_parents_must_exist(store) -> None:
    with pytest.raises(MissingParentError, match="does not exist"):
        store.append(
            type=EvidenceType.SINK_HIT,
            source_tool="androguard",
            content={"sink_id": "sms_read"},
            parents=("ev_does_not_exist",),
        )


def test_rejected_append_leaves_no_gap(store) -> None:
    """A refused append must not consume a sequence number.

    Otherwise a rejected ungrounded claim would leave a hole and every later
    verify_chain() would report a gap that no one caused.
    """
    _append_n(store, 3)
    with pytest.raises(UngroundedClaimError):
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="gemini:code_interpreter",
            content={"claim": "It is bad.", "evidence_refs": []},
        )
    tail = _append_n(store, 1)[0]
    assert tail.seq == 3, "sequence should continue from 3, not skip to 4"
    assert store.verify_chain().ok is True


def test_provenance_dag_is_preserved(store) -> None:
    """parents are stored and returned in order — the closed-loop trail."""
    base = _append_n(store, 2)
    child = store.append(
        type=EvidenceType.CALL_PATH,
        source_tool="androguard",
        content={"sink": "sms_read"},
        parents=(base[0].id, base[1].id),
    )
    assert store.get(child.id).parents == (base[0].id, base[1].id)


# ── cross-machine determinism ────────────────────────────────────────────────
def test_float_normalisation_makes_hashes_stable() -> None:
    """0.1+0.2 must hash identically to 0.3.

    This is the cross-machine failure mode: without rounding, the same logical node
    hashes differently depending on how its floats were computed, and chain
    verification fails on a machine that did the arithmetic differently.
    """
    a = {"confidence": 0.1 + 0.2}
    b = {"confidence": 0.3}
    assert crypto.canonical_json(a) == crypto.canonical_json(b)
    assert crypto.node_hash(a) == crypto.node_hash(b)


def test_canonical_json_is_key_order_independent() -> None:
    assert crypto.canonical_json({"b": 1, "a": 2}) == crypto.canonical_json({"a": 2, "b": 1})


def test_tuples_and_lists_hash_identically() -> None:
    """JSON has no tuple, so a round-tripped node must still verify."""
    assert crypto.node_hash({"refs": ("a", "b")}) == crypto.node_hash({"refs": ["a", "b"]})


def test_booleans_are_not_rounded_into_ints() -> None:
    """isinstance(True, int) is True in Python — the float branch must not catch it."""
    assert crypto.canonical_json({"x": True}) == '{"x":true}'
    assert crypto.canonical_json({"x": 1}) == '{"x":1}'
    assert crypto.node_hash({"x": True}) != crypto.node_hash({"x": 1})


def test_negative_zero_normalises(store) -> None:
    assert crypto.canonical_json({"v": -0.0}) == crypto.canonical_json({"v": 0.0})


def test_export_is_independently_verifiable(store) -> None:
    """An export carries the pubkey and algorithm, so a third party can re-verify."""
    _append_n(store, 5)
    exported = store.export()
    assert exported["job_id"] == JOB
    assert exported["algorithm"] == "ed25519"
    assert exported["float_precision"] == crypto.FLOAT_PRECISION
    assert len(exported["nodes"]) == 5

    pubkey = crypto.public_key_from_hex(exported["pubkey"])
    for node in exported["nodes"]:
        assert crypto.verify(pubkey, node["node_hash"], node["signature"])


def test_empty_chain_does_not_verify(tmp_path: Path) -> None:
    """ "Nothing to verify" is not "verified".

    A vacuous pass here would let the demo's verify_chain beat go green on a job that
    produced no evidence at all — the same shape as v1's `nc -z` bug, where a probe
    reported success because it had never actually run.
    """
    store = LedgerStore(tmp_path / "ledger.db", tmp_path / "key.pem")
    try:
        result = store.verify_chain("job_that_never_ran")
        assert result.ok is False
        assert result.node_count == 0
        assert result.first_bad_seq is None
        assert result.reason is not None
        assert "no nodes" in result.reason
    finally:
        store.close()


def test_chain_with_one_node_still_verifies(tmp_path: Path) -> None:
    """Guard the boundary: rejecting empty must not reject a single-node chain."""
    store = LedgerStore(tmp_path / "ledger.db", tmp_path / "key.pem")
    try:
        store.open("job_single")
        store.append(
            type=EvidenceType.FILE_META,
            source_tool="test",
            content={"sha256": "a" * 64},
        )
        result = store.verify_chain("job_single")
        assert result.ok is True
        assert result.node_count == 1
    finally:
        store.close()
