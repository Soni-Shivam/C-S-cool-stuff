"""Shared primitives. Deliberately tiny and dependency-free.

Global conventions from docs/01_DATA_CONTRACTS.md §0:
  - timestamps: UTC ISO-8601 with `Z`, produced by `now()`
  - hashes: lowercase hex SHA-256
  - ids: `f"{prefix}_{12 hex chars}"` — e.g. `ev_01932ab8f4c1`
"""

from __future__ import annotations

import itertools
import os
import time
from datetime import UTC, datetime

#: Per-process counter for the low bits of an id. Seeded randomly so two processes
#: starting in the same millisecond do not emit the same first id.
_COUNTER = itertools.count(int.from_bytes(os.urandom(2), "big"))

#: Width of the id suffix in hex chars, per §0's `ev_01932ab8f4c1` examples.
_ID_HEX_WIDTH = 12
#: Of those, how many encode time. The remainder is the counter.
_TIME_HEX = 8
_COUNTER_HEX = _ID_HEX_WIDTH - _TIME_HEX
_COUNTER_MOD = 16**_COUNTER_HEX


def now() -> str:
    """UTC ISO-8601 with a trailing `Z`.

    The single source of wall-clock time for anything that reaches a contract.
    `m6_score` never calls this — the scorer is pure (00_GUIDING_MAP.md §9.3).
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def uuid7_hex() -> str:
    """A UUIDv7 as 32 hex chars, per RFC 9562 §5.7.

    Time-ordered, so ids sort chronologically. Python 3.11 has no `uuid.uuid7`.

    Layout: 48-bit big-endian Unix ms | version 7 | 12 random bits | variant 0b10
    | 62 random bits.

    **Do not truncate this for an id** — see `new_id`.
    """
    unix_ms = int(time.time() * 1000)
    rand = os.urandom(10)

    b = bytearray(16)
    b[0:6] = unix_ms.to_bytes(6, "big")
    b[6:16] = rand
    b[6] = 0x70 | (b[6] & 0x0F)  # version 7
    b[8] = 0x80 | (b[8] & 0x3F)  # variant 0b10
    return bytes(b).hex()


def new_id(prefix: str) -> str:
    """`f"{prefix}_{12 hex}"` — time-ordered and collision-free within a process.

    §0 specifies `uuid7_hex[:12]`, and that convention is **unsafe as written**: the
    first 12 hex chars of a UUIDv7 are exactly its 48-bit millisecond timestamp, so
    every id minted in the same millisecond is identical and every random bit is
    discarded by the truncation. Appending 50 ledger nodes in a loop produced 50
    identical ids and a `UNIQUE constraint failed` — which the ledger tests caught.

    Widening the random part is not a fix either. At 24 random bits a 400-node job
    has roughly a 1-in-200 chance of an internal collision, and a system whose entire
    claim is evidence integrity cannot ship a 0.5% chance of two artefacts sharing an
    identity.

    So: 8 hex chars of millisecond time (sortable, wraps every ~49 days, which does
    not matter because the prefix and the ledger's `job_id` scope it) plus 4 hex
    chars of a per-process counter. Two ids can only collide if one process issues
    65,536 ids inside a single millisecond. `UNIQUE(id)` in SQL remains the backstop.
    """
    stamp = int(time.time() * 1000) & 0xFFFFFFFF
    tick = next(_COUNTER) % _COUNTER_MOD
    return f"{prefix}_{stamp:0{_TIME_HEX}x}{tick:0{_COUNTER_HEX}x}"
