"""Id generation must not collide, and must stay sortable.

This file exists because the convention in docs/01_DATA_CONTRACTS.md §0 —
`uuid7_hex[:12]` — is unsafe: those 12 hex chars are exactly the 48-bit millisecond
timestamp of a UUIDv7, so every id minted in the same millisecond is identical.
Appending 50 ledger nodes in a loop produced 50 identical ids.
"""

from __future__ import annotations

import re

from drishti.util import new_id, now, uuid7_hex

ID_PATTERN = re.compile(r"^[a-z]+_[0-9a-f]{12}$")


def test_id_format_matches_the_convention() -> None:
    assert ID_PATTERN.match(new_id("ev")), "ids must be prefix_12hex per §0"


def test_ten_thousand_ids_in_a_tight_loop_are_unique() -> None:
    """The regression test for the truncated-uuid7 collision.

    A tight loop is the realistic case: the ledger appends a burst of nodes per stage,
    all inside the same millisecond.
    """
    ids = [new_id("ev") for _ in range(10_000)]
    assert len(set(ids)) == 10_000, "ids collided — see new_id's docstring"


def test_ids_are_time_ordered_within_a_process() -> None:
    """Sortability is the reason for a time prefix; assert it actually holds."""
    ids = [new_id("ev") for _ in range(500)]
    assert ids == sorted(ids)


def test_prefixes_are_preserved() -> None:
    assert new_id("job").startswith("job_")
    assert new_id("hyp").startswith("hyp_")


def test_uuid7_has_correct_version_and_variant_bits() -> None:
    """If uuid7_hex is used directly anywhere, it must be a real v7."""
    for _ in range(100):
        raw = bytes.fromhex(uuid7_hex())
        assert raw[6] >> 4 == 0x7, "version nibble must be 7"
        assert raw[8] >> 6 == 0b10, "variant bits must be 0b10"


def test_uuid7_is_time_ordered_at_millisecond_granularity() -> None:
    """UUIDv7 sorts by time only down to the millisecond.

    Within a single millisecond the ordering is decided by the random bits, because
    this implementation does not use RFC 9562's optional sub-millisecond counter. So
    the guarantee to assert is that the 48-bit timestamp prefix never goes backwards
    — not that the full values sort, which they do not.

    This is exactly why `new_id` uses an explicit counter rather than truncating a
    uuid7: it needs strict per-process ordering AND uniqueness, and v7 alone gives
    neither inside one millisecond.
    """
    prefixes = [uuid7_hex()[:12] for _ in range(200)]
    assert prefixes == sorted(prefixes)


def test_now_is_iso8601_utc_with_z() -> None:
    stamp = now()
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", stamp), stamp
