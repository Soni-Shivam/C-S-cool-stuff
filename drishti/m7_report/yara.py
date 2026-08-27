"""YARA rule generation. `docs/PHASE_6_REPORT_UI_DEMO.md` T6.1.

The rule is deliberately built from things that survive repacking. Fraudsters rebuild
these apps every few hours: a new hash, a fresh self-signed certificate, a renamed
package. A rule keyed on the hash catches exactly one build and is obsolete before it
ships, so the hash appears only as a comment, never as a condition.

What does survive is the *code* — hardcoded endpoints, embedded crypto constants,
native library names, and the class paths the sink walk actually reached. Those are
what the author would have to genuinely rewrite.

Nothing here is a detection guarantee. The rule is a starting point for an analyst,
and it says so in its own metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from drishti.contracts.score import CompositeScore
from drishti.contracts.static_report import FileMeta, StaticReport

#: Below this many distinct strings a rule is more likely to false-positive than to
#: catch a variant, so it is emitted disabled with the reason stated.
MIN_STRINGS_FOR_CONFIDENCE = 3

#: Rules are read by humans and pasted into other tooling; an unbounded rule from a
#: string-heavy sample is useless in both settings.
MAX_STRINGS = 20

#: Strings shorter than this match everywhere. Rejecting them is the single biggest
#: false-positive control in the generator.
MIN_STRING_LEN = 8

#: Substrings so common in Android builds that including them guarantees a hit on
#: essentially every APK ever compiled. The second group is toolchain and popular
#: third-party library boilerplate: a measured run over the canary produced a rule
#: keyed on the Kotlin reflection warning string, which is present in every Kotlin
#: app ever shipped and would have matched most of the Play Store.
_BORING = (
    "android",
    "google",
    "gstatic",
    "googleapis",
    "schemas.android.com",
    "apache.org",
    "w3.org",
    "example.com",
    "localhost",
    "127.0.0.1",
    # toolchain / library boilerplate
    "kotlin",
    "jetbrains",
    "youtrack",
    "androidx",
    "squareup",
    "okhttp",
    "retrofit",
    "gson",
    "firebase",
    "crashlytics",
    "github.com",
    "sqlite.org",
    "bouncycastle",
    "slf4j",
)

#: A URL string extracted from a DEX is only useful if it is actually a URL. M2's
#: extractor returns the surrounding literal, so a prose sentence that merely mentions
#: a link arrives here looking like an endpoint. Whitespace is the giveaway.
_URL_SHAPE = re.compile(r"^h(?:tt|xx)ps?://\S+$", re.IGNORECASE)


@dataclass(frozen=True)
class GeneratedRule:
    """A YARA rule plus whether we are willing to stand behind it."""

    name: str
    text: str
    enabled: bool
    reason: str
    string_count: int


def _identifier(value: str) -> str:
    """A YARA-legal rule name. Must not start with a digit."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_") or "sample"
    return cleaned if cleaned[0].isalpha() else f"r_{cleaned}"


def _refang(value: str) -> str:
    """Undo M2's `hxxp` defanging so the literal matches the bytes in the file.

    M2 stores extracted URLs defanged, so a report or a ledger node can never be
    turned into a live link by a reader's terminal. A YARA string is the opposite
    kind of object: it is matched byte-for-byte against the sample, and the sample
    contains `http`. Emitting the defanged form produced rules that were syntactically
    valid, shipped with confidence, and could never fire — the decoy's own rule listed
    two endpoints and matched neither, leaving one crypto constant against a
    `2 of ($s*)` condition.

    Only the scheme is rewritten, and only at the start of the value: `hxxp` inside a
    path is a literal the sample really does contain.
    """
    for defanged, real in (("hxxps://", "https://"), ("hxxp://", "http://")):
        if value.startswith(defanged):
            return real + value[len(defanged) :]
    return value


def _escape(value: str) -> str:
    r"""Escape for a YARA double-quoted string literal.

    Backslash first — escaping quotes before backslashes would double-escape the
    backslash that the quote escape just introduced.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _is_useful(value: str) -> bool:
    if len(value) < MIN_STRING_LEN or len(value) > 200:
        return False
    if not value.isprintable():
        return False
    lowered = value.lower()
    return not any(boring in lowered for boring in _BORING)


def _candidate_strings(static: StaticReport | None) -> list[tuple[str, str]]:
    """(comment, literal) pairs, most distinctive first, deduplicated."""
    if static is None:
        return []

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(comment: str, value: str) -> None:
        if not _is_useful(value) or value in seen:
            return
        seen.add(value)
        candidates.append((comment, value))

    # Hardcoded endpoints are the strongest survivor: changing them means standing up
    # new infrastructure, not just rebuilding the app. Shape-checked, because a prose
    # literal that merely contains a link is not an endpoint.
    for url in static.urls:
        if _URL_SHAPE.match(url):
            # Refanged: this literal is matched against the file, not shown to a reader.
            _add("hardcoded endpoint", _refang(url))
    for constant in static.crypto_constants:
        _add("embedded crypto constant", constant)
    for lib in static.native_libs:
        _add("native library", lib)
    # The class path a sink was actually reached through, rather than every class.
    # Only lifecycle-reachable paths: dead library code reaches sinks constantly and
    # keying a rule on it would match every app that vendored the same library.
    for path in static.call_paths:
        if path.reachable_from_lifecycle and path.entrypoint:
            _add("sink path entrypoint", path.entrypoint)
    for hint in static.packer_hints:
        _add("packer artefact", hint)

    return candidates[:MAX_STRINGS]


def build_rule(
    *,
    meta: FileMeta,
    score: CompositeScore,
    static: StaticReport | None = None,
) -> GeneratedRule:
    """Generate one YARA rule for a sample, and report whether it is trustworthy."""
    base = meta.package or meta.filename.removesuffix(".apk") or meta.sha256[:12]
    name = f"DRISHTI_{_identifier(base)}_{meta.sha256[:8]}"

    candidates = _candidate_strings(static)
    enabled = len(candidates) >= MIN_STRINGS_FOR_CONFIDENCE
    reason = (
        "generated from repack-resistant static artefacts"
        if enabled
        else (
            f"only {len(candidates)} distinctive string(s) survived filtering; "
            f"below the {MIN_STRINGS_FOR_CONFIDENCE} needed to be worth deploying"
        )
    )

    lines: list[str] = []
    if not enabled:
        lines.append("/*")
        lines.append(" * DISABLED — this rule is not safe to deploy as written.")
        lines.append(f" * {reason}")
        lines.append(" */")
        lines.append("")

    lines.append(f"rule {name}")
    lines.append("{")
    lines.append("    meta:")
    lines.append('        author = "DRISHTI automated triage"')
    lines.append(f'        description = "{_escape(score.explanation[:180] or "Android sample")}"')
    # The hash is metadata, never a condition: it identifies the build we analysed
    # and is worthless against the next repack.
    lines.append(f'        reference_sha256 = "{meta.sha256}"')
    lines.append(f'        package = "{_escape(meta.package or "unknown")}"')
    lines.append(f"        drishti_score = {score.S}")
    lines.append(f'        drishti_band = "{score.band.value}"')
    lines.append(f"        drishti_confidence = {score.C:.2f}")
    lines.append('        note = "Generated, not curated. Validate before deployment."')

    if candidates:
        lines.append("")
        lines.append("    strings:")
        for index, (comment, value) in enumerate(candidates):
            lines.append(f'        $s{index} = "{_escape(value)}" ascii wide  // {comment}')

    lines.append("")
    lines.append("    condition:")
    if candidates:
        # A zip magic guard keeps the rule from scanning unrelated file types, and
        # `2 of them` tolerates the author dropping any single string.
        threshold = "2 of ($s*)" if len(candidates) >= 2 else "$s0"
        lines.append(f"        uint32(0) == 0x04034b50 and {threshold}")
    else:
        lines.append("        false  // no distinctive strings were extracted")
    lines.append("}")

    return GeneratedRule(
        name=name,
        text="\n".join(lines) + "\n",
        enabled=enabled,
        reason=reason,
        string_count=len(candidates),
    )
