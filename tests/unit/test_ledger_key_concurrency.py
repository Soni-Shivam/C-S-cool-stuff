"""The signing key must be created exactly once, however many creators race.

docs/superpowers/plans/2026-08-17-ledger-hardening-and-reconciliation.md Task 1.

If two threads each generate a key and the second overwrites the first, the first
thread's nodes are signed with a key that no longer exists on disk and the chain can
never verify. That is unrecoverable: the evidence is not re-signable.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from drishti.ledger import crypto

RACERS = 8


def test_concurrent_creation_yields_exactly_one_key(tmp_path: Path) -> None:
    key_path = tmp_path / "ledger_ed25519.key"
    barrier = threading.Barrier(RACERS)
    seen: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        # Release every thread at the same instant to maximise the overlap.
        barrier.wait()
        key = crypto.load_or_create_key(key_path)
        with lock:
            seen.append(crypto.public_key_hex(key))

    threads = [threading.Thread(target=worker) for _ in range(RACERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(seen) == RACERS
    assert len(set(seen)) == 1, f"{len(set(seen))} distinct keys were created, expected 1"

    # The key every caller returned must be the one that is actually on disk.
    on_disk = crypto.public_key_hex(crypto.load_or_create_key(key_path))
    assert set(seen) == {on_disk}


def test_existing_key_is_reused(tmp_path: Path) -> None:
    key_path = tmp_path / "ledger_ed25519.key"
    first = crypto.public_key_hex(crypto.load_or_create_key(key_path))
    second = crypto.public_key_hex(crypto.load_or_create_key(key_path))
    assert first == second


def test_key_file_is_owner_only(tmp_path: Path) -> None:
    key_path = tmp_path / "ledger_ed25519.key"
    crypto.load_or_create_key(key_path)
    assert key_path.stat().st_mode & 0o077 == 0, "signing key must not be group/world readable"


def test_unreadable_key_file_raises_rather_than_regenerating(tmp_path: Path) -> None:
    """Silently regenerating would invalidate every chain already signed.

    An operator deleting a corrupt key is a decision; a library making it silently is
    evidence destruction.
    """
    key_path = tmp_path / "ledger_ed25519.key"
    key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot actually a key\n")
    with pytest.raises(crypto.LedgerKeyError):
        crypto.load_or_create_key(key_path)
