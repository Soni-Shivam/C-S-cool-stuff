"""The Frida hook catalogue must observe, never add capability.

CLAUDE.md hard boundaries. CI gate.

The project analyses malware and does not create it. Frida hooks sit exactly on that
line: an observational hook reports that a call happened, while a hook that changes a
return value or invents a message is putting behaviour into the sample. Morphs DO return
synthetic values, but they live in scripts/morph/ and are a separate deliberate thing.

This test reads the catalogue as text, because the property is about what the file is
allowed to contain — and a reviewer skimming 200 lines of JS at hour 60 will not catch a
single changed return.
"""

from __future__ import annotations

import re
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[2] / "drishti" / "m3_dynamic" / "scripts" / "hooks.js"


def test_the_catalogue_exists() -> None:
    assert HOOKS.exists(), "the hook catalogue is what makes M3 an instrument"


def test_every_hook_calls_through_to_the_original() -> None:
    """An observational hook must return the real value, not a fabricated one."""
    source = HOOKS.read_text()
    # Split on the assignment rather than regex-matching a closing brace: the file uses
    # varied indentation and a brace-counting regex is a fragile way to read code.
    chunks = source.split(".implementation = function")[1:]
    bodies = [c.split("\n    });")[0] for c in chunks]
    assert bodies, "no hook implementations found — the parser or the file changed"
    for body in bodies:
        assert "return" in body, f"a hook does not return anything: {body[:120]}"
        calls_through = "this." in body or "original.call" in body or "overload.apply" in body
        assert calls_through, (
            f"a hook does not call through to the original implementation: {body[:160]}"
        )


def test_no_hook_sends_sms_or_writes_data() -> None:
    """Nothing here may perform an action on the device."""
    source = HOOKS.read_text()
    for forbidden in (
        "sendTextMessage(",  # constructing a send, as opposed to hooking one
        "startActivity(",
        "setPrimaryClip(",
        "getWritableDatabase(",
        "openFileOutput(",
    ):
        # The hook DECLARATIONS legitimately name these APIs; what is forbidden is
        # invoking them. Declarations appear as `.overload(` or `Java.use(`.
        for line in source.splitlines():
            if forbidden in line and "emit(" not in line and "overload" not in line:
                assert line.strip().startswith("*") or "//" in line, (
                    f"possible action rather than observation: {line.strip()[:120]}"
                )


def test_values_are_redacted_before_leaving_the_guest() -> None:
    """Redaction in the guest, plus a contract that refuses unredacted text. Both."""
    source = HOOKS.read_text()
    assert "function redact(" in source
    assert re.search(r"replace\(/\\d/g", source), "digits must be masked: OTPs, IMEIs, cards"
    assert "redacted: true" in source


def test_every_hook_is_individually_failure_isolated() -> None:
    """One missing class must cost one hook, not the whole session."""
    source = HOOKS.read_text()
    assert "function safe(" in source
    implementations = source.count(".implementation = function")
    safe_wrappers = source.count("safe('")
    assert safe_wrappers >= implementations - 2, (
        "hooks are not individually wrapped; a single missing class would silently "
        "return an empty detonation"
    )


def test_the_crypto_hook_is_present() -> None:
    """Cipher.doFinal yields plaintext before encryption.

    It is why HTTPS interception is a deferred nicety rather than a blocker, and it
    also defeats custom crypto rather than only TLS.
    """
    source = HOOKS.read_text()
    assert "Cipher.doFinal" in source
    assert "T1521" in source
