"""Fail-closed redaction for data allowed to leave the detonator.

This module deliberately favours losing diagnostic detail over exporting a secret.
"""
from __future__ import annotations

import re


_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OTP", re.compile(r"(?i)\b(?:otp|one[ -]?time(?: password| code)?|verification code)\D{0,20}(\d{4,8})\b")),
    ("CREDENTIAL", re.compile(r"(?i)\b(?:password|passwd|passcode|pin|username|login)\s*[:=]\s*[^\s,;]{2,}")),
    ("TOKEN", re.compile(r"(?i)\b(?:bearer\s+[a-z0-9._~+/=-]{8,}|(?:access|refresh|api|auth)[_-]?token\s*[:=]\s*[^\s,;]{8,})")),
    ("JWT", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")),
)


def redact_text(value: object, *, message_body: bool = False, limit: int = 512) -> str:
    if message_body:
        return "[REDACTED:MESSAGE_BODY]"
    text = str(value or "")
    for label, pattern in _RULES:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text[:limit]


def contains_sensitive_text(value: str) -> bool:
    return any(pattern.search(value) for _, pattern in _RULES)
