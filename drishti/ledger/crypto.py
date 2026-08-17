"""Canonicalisation, hashing, and Ed25519 signing for the evidence ledger.

docs/PHASE_0_FOUNDATIONS.md T0.4, docs/01_DATA_CONTRACTS.md §1.2.

The whole trust story rests on one property: **two machines must compute the same
hash for the same node.** Everything in this module exists to make that true.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Genesis predecessor. 64 zeros, matching the sha256 hex width.
GENESIS_HASH = "0" * 64

#: Fields excluded from the hash payload: a node cannot commit to its own hash, and
#: the signature is over the hash rather than part of it.
_UNHASHED_FIELDS = frozenset({"node_hash", "signature"})

#: Float precision in the canonical form. 6dp is far beyond any precision this
#: system means (confidences, SHAP values, scores) and well inside float64's exact
#: decimal range, so rounding never loses meaning but always removes ambiguity.
FLOAT_PRECISION = 6


class LedgerKeyError(Exception):
    """The signing key file exists but is not a usable Ed25519 private key.

    Deliberately fatal. Regenerating would leave every previously signed node
    unverifiable, so replacing a corrupt key is an operator decision.
    """


def normalise(obj: Any) -> Any:
    """Recursively canonicalise a value for hashing.

    Floats are rounded to `FLOAT_PRECISION`. This is not pedantry: `0.1 + 0.2`
    serialises as `0.30000000000000004` on one machine and can differ on another,
    which silently breaks chain verification. You will lose two hours at 3am finding
    it (PHASE_0 T0.4 says so explicitly, from experience).

    Tuples become lists because JSON has no tuple, so a tuple and a list must hash
    identically or a round-tripped node stops verifying.

    `bool` is checked before `int` — in Python `isinstance(True, int)` is True, and
    rounding a bool would turn it into `1` and change the serialised form.
    """
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        # -0.0 and 0.0 are == but serialise differently; normalise the sign too.
        rounded = round(obj, FLOAT_PRECISION)
        return 0.0 if rounded == 0 else rounded
    if isinstance(obj, dict):
        return {str(k): normalise(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [normalise(v) for v in obj]
    return obj


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, unicode preserved."""
    return json.dumps(
        normalise(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def node_hash(node: dict[str, Any]) -> str:
    """sha256 over the canonical form of everything except hash and signature."""
    payload = {k: v for k, v in node.items() if k not in _UNHASHED_FIELDS}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _read_key(path: Path) -> Ed25519PrivateKey | None:
    """Return the key at `path`, or None if there is nothing there yet.

    A zero-length file counts as absent: that is what a crash mid-create leaves
    behind, and it is the one corrupt state it is safe to overwrite.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    if not raw:
        return None
    try:
        loaded = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise LedgerKeyError(f"{path} is not a readable PEM private key: {exc}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise LedgerKeyError(f"{path} is not an Ed25519 private key: {type(loaded).__name__}")
    return loaded


def load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Load a PEM Ed25519 private key, generating and persisting one if absent.

    Safe against concurrent creators. The previous check-then-act version let two
    threads each generate a key and the second overwrite the first, so the first
    thread signed nodes with a key that was no longer on disk and its chain could
    never verify.

    v1 left `LEDGER_SIGNING_KEY` empty, so a fresh key was generated per run and
    chains from different runs could not be compared against a stable public key
    (docs/CARRIED_FINDINGS.md H8). Persisting on first use fixes that.

    The file is written `0600`. It is unencrypted at rest because a passphrase we
    would have to store next to it buys nothing; the threat model here is evidence
    tampering, not key theft from an already-compromised analysis host.
    """
    path = Path(path)
    existing = _read_key(path)
    if existing is not None:
        return existing

    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Create with restrictive permissions rather than chmod-ing afterwards, so the
    # key is never briefly world-readable.
    # `Path.open()` has no `opener` parameter — only the builtin does.
    def _private_opener(target: str, flags: int) -> int:
        return os.open(target, flags, 0o600)

    # Write to a uniquely-named temp file in the same directory, fsync it, then hard-link
    # it into place. os.link raises FileExistsError if the destination exists, which makes
    # "create only if absent" a single atomic step instead of a check followed by a write.
    # Same directory so the link cannot cross a filesystem boundary.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with open(tmp, "wb", opener=_private_opener) as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        # Suppressed FileExistsError means another creator won the race and theirs is
        # the key of record — which the re-read below picks up.
        with contextlib.suppress(FileExistsError):
            os.link(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)

    # Always re-read. Whoever won the link race owns the key on disk and every caller
    # must return that one — returning our in-memory key after losing the race is
    # precisely the bug this function used to have.
    winner = _read_key(path)
    if winner is None:
        raise LedgerKeyError(f"failed to create or read a signing key at {path}")
    return winner


def public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    """Raw 32-byte public key as hex, for embedding in a report export."""
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def public_key_from_hex(hex_key: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))


def sign(key: Ed25519PrivateKey, digest_hex: str) -> str:
    """Sign a hex digest. Returns hex.

    The signature covers the digest string, not the raw bytes it encodes, so a
    verifier only ever needs the value stored in the row.
    """
    return key.sign(digest_hex.encode("ascii")).hex()


def verify(pubkey: Ed25519PublicKey, digest_hex: str, sig_hex: str) -> bool:
    """True if `sig_hex` is a valid signature over `digest_hex`.

    Returns False rather than raising: verification failure is an expected outcome
    that the caller reports as `first_bad_seq`, not an exceptional condition.
    """
    try:
        pubkey.verify(bytes.fromhex(sig_hex), digest_hex.encode("ascii"))
    except (InvalidSignature, ValueError):
        return False
    return True
