"""Bounded extraction of the strings a victim actually reads.

docs/PHASE_3_GENAI_CORE.md T3.8.

M2 extracts DEX string constants and filters them to URLs, package names and crypto
material — the things a *detector* needs. None of that reaches the Social-Engineering
Analyst, because the sentence that tells you who a sample targets is UI text:
*"आपका KYC निलंबित कर दिया गया है"*, and it lives in `resources.arsc`, not in the DEX.

This module reads it. It parses; it never executes. androguard's resource table walker
is the same code path M2 already uses for the manifest, so running it on a laptop is as
safe as running M2 on a laptop — the rule that matters (CLAUDE.md) is that no installer,
emulator or `subprocess` touches a sample here, and none does.

The `locale` on each string is the strongest signal in the file and it is a **fact**:
a `values-hi` resource directory is Hindi because the Android resource system says so,
not because a model thought it looked like Hindi.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from drishti.contracts.evidence import EvidenceType
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger

log = get_logger(__name__)

#: A real app has thousands of resource strings, most of them framework boilerplate.
#: The profile needs the handful a victim reads, and the prompt budget is 12k tokens.
MAX_UI_STRINGS = 80
MAX_STRING_CHARS = 200

#: Strings shorter than this carry no social-engineering signal ("OK", "%1$s").
MIN_STRING_CHARS = 4

#: Ledger nodes are appended for the strings the profile may cite. Capped separately
#: because every node is a row, a hash and a signature.
MAX_LEDGER_STRINGS = 40


@dataclass(frozen=True)
class UiString:
    """One user-facing string, with the provenance that makes it citable."""

    value: str
    locale: str
    resource_id: str
    evidence_ref: str = ""

    @property
    def scripts(self) -> frozenset[str]:
        """Unicode script blocks present. A codepoint range is a fact, not an opinion."""
        return scripts_of(self.value)


def scripts_of(text: str) -> frozenset[str]:
    """Unicode script blocks in `text`, by character name prefix.

    `unicodedata.name` gives 'DEVANAGARI LETTER KA' for U+0915, so the first word is
    the script. This is deliberately not `langdetect`: a model or an n-gram classifier
    guesses, while a codepoint block is definitional. Hindi and Marathi share
    Devanagari, so the *script* is what we assert and the language is narrowed only
    where a resource locale says so.
    """
    found: set[str] = set()
    for char in text:
        if char.isspace() or not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        first = name.split(" ", 1)[0]
        if first in {"LATIN", "DIGIT"}:
            continue
        found.add(first.title())
    return frozenset(found)


def extract_ui_strings(apk_path: Path) -> tuple[tuple[UiString, ...], tuple[str, ...]]:
    """Read bounded UI strings from an APK's resource table.

    Returns `(strings, errors)`. A sample whose resources will not parse yields an
    error string and an empty tuple — never an exception, and never a guess.
    """
    try:
        from androguard.core.apk import APK

        apk = APK(str(apk_path))
        resources = apk.get_android_resources()
        if resources is None:
            return (), ("no resource table in the APK",)
        resolved: dict[str, dict[str, dict[int, str]]] = resources.get_resolved_strings()
    except Exception as exc:  # androguard raises a wide family on malformed archives
        log.warning("ui_string_extraction_failed", error=str(exc)[:200])
        return (), (f"UI string extraction failed: {type(exc).__name__}: {exc}"[:200],)

    collected: list[UiString] = []
    seen: set[str] = set()
    for package, locales in sorted(resolved.items()):
        for locale, entries in sorted(locales.items()):
            for resource_id, value in sorted(_iter_entries(entries)):
                text = str(value).strip()
                if len(text) < MIN_STRING_CHARS or text in seen:
                    continue
                seen.add(text)
                collected.append(
                    UiString(
                        value=text[:MAX_STRING_CHARS],
                        locale=str(locale),
                        resource_id=f"{package}:{resource_id:#010x}",
                    )
                )
                if len(collected) >= MAX_UI_STRINGS:
                    return tuple(collected), ()
    return tuple(collected), ()


def _iter_entries(entries: Any) -> list[tuple[int, str]]:
    if not isinstance(entries, dict):
        return []
    return [(int(k), str(v)) for k, v in entries.items() if isinstance(v, str)]


def record_ui_strings(
    strings: tuple[UiString, ...],
    ledger: LedgerStore,
) -> tuple[UiString, ...]:
    """Append a citable `STRING_CONST` node per UI string, returning them with refs.

    The Social-Engineering Analyst's whole value is that "targets Hindi speakers" links
    back to the Devanagari string that justified it. Without a node id there is nothing
    to link to and `ledger.append()` would reject the claim — correctly.
    """
    out: list[UiString] = []
    for item in strings[:MAX_LEDGER_STRINGS]:
        node = ledger.append(
            type=EvidenceType.STRING_CONST,
            source_tool="m4_genai:resources",
            content={
                "value": item.value,
                "kind": "ui_string",
                "locale": item.locale,
                "resource_id": item.resource_id,
                "scripts": sorted(item.scripts),
            },
            location=item.resource_id,
        )
        out.append(
            UiString(
                value=item.value,
                locale=item.locale,
                resource_id=item.resource_id,
                evidence_ref=node.id,
            )
        )
    # Strings beyond the ledger cap are dropped rather than kept uncitable: a string
    # the profile cannot cite is one the verifier would reject anyway.
    return tuple(out)
