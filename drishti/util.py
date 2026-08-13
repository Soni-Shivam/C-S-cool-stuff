"""Shared primitives. Deliberately tiny and dependency-free.

Global conventions from docs/01_DATA_CONTRACTS.md §0:
  - timestamps: UTC ISO-8601 with `Z`, produced by `now()` and nothing else
  - hashes: lowercase hex SHA-256
  - ids: `f"{prefix}_{uuid7_hex[:12]}"`
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime


def now() -> str:
    """UTC ISO-8601 with a trailing `Z`.

    The single source of wall-clock time for anything that reaches a contract.
    `m6_score` never calls this — the scorer is pure (00_GUIDING_MAP.md §9.3).
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def uuid7_hex() -> str:
    """A UUIDv7 as 32 hex chars, per RFC 9562 §5.7.

    Python 3.11 has no `uuid.uuid7`. Rolling it is 12 lines and worth it: v7 is
    time-ordered, so ids sort chronologically. That means `ev_01932ab8f4c1` sorts
    the way a human expects when reading a ledger, and truncating to 12 chars keeps
    the timestamp prefix rather than throwing away the ordering.

    Layout: 48-bit big-endian Unix ms | version 7 | 12 random bits | variant 0b10
    | 62 random bits.
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
    """`f"{prefix}_{uuid7_hex[:12]}"` — e.g. `ev_01932ab8f4c1`."""
    return f"{prefix}_{uuid7_hex()[:12]}"
