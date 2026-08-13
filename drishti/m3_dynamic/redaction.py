"""Fail-closed redaction for data allowed to leave the detonator.

LIFTed from v1 (`sandbox/redaction.py`) — see docs/SALVAGE.md.

This module deliberately favours losing diagnostic detail over exporting a secret.
A detonated sample handles synthetic victim data, but it also touches whatever the
guest happens to contain, and an observation string is written to the ledger, sent
to an LLM, and rendered in a report. Anything sensitive that reaches here has three
onward paths, so the boundary is enforced at the point of egress.

Redaction happens twice by design: once inside the Frida hook, before the value
leaves the guest process, and again in `ObservationEvent`, which refuses to
construct if this module still detects a secret. A hook bug must not become a leak.
"""

from __future__ import annotations

import re

#: Ordered (label, pattern) rules. Patterns are intentionally broad — a false
#: redaction costs a line of debug output, a missed one exports a credential.
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "OTP",
        re.compile(
            r"(?i)\b(?:otp|one[ -]?time(?: password| code)?|verification code)\D{0,20}(\d{4,8})\b"
        ),
    ),
    (
        "CREDENTIAL",
        re.compile(r"(?i)\b(?:password|passwd|passcode|pin|username|login)\s*[:=]\s*[^\s,;]{2,}"),
    ),
    (
        "TOKEN",
        re.compile(
            r"(?i)\b(?:bearer\s+[a-z0-9._~+/=-]{8,}"
            r"|(?:access|refresh|api|auth)[_-]?token\s*[:=]\s*[^\s,;]{8,})"
        ),
    ),
    ("JWT", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")),
)

#: Hard cap on any exported string, mirroring ObservationEvent.detail.
DEFAULT_LIMIT = 512


def redact_text(value: object, *, message_body: bool = False, limit: int = DEFAULT_LIMIT) -> str:
    """Redact and truncate a value for export.

    `message_body=True` drops the content entirely rather than pattern-matching it.
    An SMS body is the payload an OTP-stealing trojan is after; that we observed
    `SmsMessage.getMessageBody` being called is the evidence, and the body itself
    adds nothing an analyst needs.
    """
    if message_body:
        return "[REDACTED:MESSAGE_BODY]"
    text = str(value or "")
    for label, pattern in _RULES:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text[:limit]


def contains_sensitive_text(value: str) -> bool:
    """True if any redaction rule still matches — i.e. this string must not ship."""
    return any(pattern.search(value) for _, pattern in _RULES)
