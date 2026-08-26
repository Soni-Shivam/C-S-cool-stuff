"""Social-Engineering Analyst: who is this written for, and who is it pretending to be.

docs/PHASE_3_GENAI_CORE.md T3.8, docs/ROADMAP_GENAI_RE.md A4.

For the Indian fraud families this system is built for, the finding is usually in the
text rather than in the bytecode. An `e-Challan` lure and a `KYC` lure share a
permission set; what separates them — and what an analyst writes in the first line of
the report — is that one says *"आपका चालान लंबित है"* and the other says *"KYC
suspended"*.

**The split between fact and inference is the design.** Three of the four fields are
decided in Python:

  * `script` — the Unicode block of the characters. Definitional.
  * `language` — narrowed from an Android resource locale (`values-hi`) when one
    exists; otherwise the script is reported and the language is left null rather
    than guessed. Hindi and Marathi share Devanagari and we will not pick one by vibe.
  * `impersonated_target` — a literal match against `data/kb/impersonated_brands.txt`,
    cross-checked against the certificate's brand-mismatch signal.

Only `tactic` and `segment` are asked of the model, because both are readings of
wording, and both are dropped unless they cite a string node that resolves.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import GroundedClaim, VerifierStatus, VictimProfile
from drishti.contracts.static_report import StaticReport
from drishti.ledger.store import LedgerStore
from drishti.ledger.verifier import Verifier
from drishti.logging import get_logger
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.resources import UiString, scripts_of
from drishti.m4_genai.safety import wrap_untrusted

log = get_logger(__name__)

_PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
BRANDS_PATH = Path(__file__).resolve().parents[3] / "data" / "kb" / "impersonated_brands.txt"

#: Strings shown to the model. Enough to read a lure, few enough to stay in budget.
MAX_STRINGS_IN_PROMPT = 40

#: Tactics the model may return. Anything else is discarded rather than passed through:
#: an unenumerated tactic is a free-text field, and free text is where injected
#: instructions would live.
ALLOWED_TACTICS = frozenset({"urgency", "authority", "fear", "reward", "curiosity", "none"})

#: Script -> the languages that use it. Where a script maps to exactly one language we
#: may name it; where it does not, we report the script and leave `language` null.
_SCRIPT_LANGUAGES: dict[str, tuple[str, ...]] = {
    "Devanagari": ("hi", "mr", "ne", "sa"),
    "Bengali": ("bn", "as"),
    "Gurmukhi": ("pa",),
    "Gujarati": ("gu",),
    "Oriya": ("or",),
    "Tamil": ("ta",),
    "Telugu": ("te",),
    "Kannada": ("kn",),
    "Malayalam": ("ml",),
    "Sinhala": ("si",),
    "Arabic": ("ur", "ar", "fa"),
    "Thai": ("th",),
    "Han": ("zh",),
    "Cyrillic": ("ru", "uk"),
}


class ProfileOut(BaseModel):
    """Exactly what the model may return. Two judgements and their support."""

    tactic: str | None = None
    segment: str | None = None
    reason: str = ""
    confidence: float = 0.0
    evidence_refs: list[str] = Field(default_factory=list)


@lru_cache(maxsize=1)
def load_brands(path: str | None = None) -> tuple[tuple[str, str, str], ...]:
    """The impersonation lexicon: (token, canonical name, sector)."""
    target = Path(path) if path else BRANDS_PATH
    if not target.exists():
        log.warning("brand_lexicon_missing", path=str(target))
        return ()
    rows: list[tuple[str, str, str]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if len(parts) == 3 and parts[0]:
            rows.append((parts[0].lower(), parts[1], parts[2]))
    return tuple(rows)


def detect_script(strings: tuple[UiString, ...]) -> tuple[str | None, tuple[str, ...]]:
    """The dominant non-Latin script across the strings, and the ids that show it.

    Dominant rather than any: one stray Devanagari glyph in an otherwise English app is
    a font sample, not a targeting signal.
    """
    counts: Counter[str] = Counter()
    refs: dict[str, list[str]] = {}
    for item in strings:
        for script in item.scripts:
            counts[script] += 1
            if item.evidence_ref:
                refs.setdefault(script, []).append(item.evidence_ref)
    if not counts:
        return None, ()
    script, _ = counts.most_common(1)[0]
    return script, tuple(refs.get(script, ())[:4])


def detect_language(
    script: str | None, strings: tuple[UiString, ...]
) -> tuple[str | None, bool, tuple[str, ...]]:
    """Language, whether it was decided deterministically, and its notes.

    A resource locale is authoritative — `values-hi` means Hindi because the platform
    says so. Absent one, a script that maps to a single language may name it; a script
    shared by several does not, and the honest output is a null language beside a
    stated script.
    """
    notes: list[str] = []
    locales = {
        item.locale.split("-")[0].lower()
        for item in strings
        if item.locale and item.locale.upper() != "DEFAULT"
    }
    known = sorted(code for code in locales if len(code) == 2 and code.isalpha())
    if known:
        notes.append(f"language read from Android resource locale(s): {', '.join(known)}")
        return known[0], True, tuple(notes)
    if script is None:
        return None, False, ()
    candidates = _SCRIPT_LANGUAGES.get(script, ())
    if len(candidates) == 1:
        notes.append(f"language implied uniquely by the {script} script")
        return candidates[0], True, tuple(notes)
    if candidates:
        notes.append(
            f"{script} script observed; it is shared by {', '.join(candidates)}, and no "
            "resource locale narrowed it — language left undetermined rather than guessed"
        )
    return None, False, tuple(notes)


def detect_brands(
    strings: tuple[UiString, ...],
    static: StaticReport,
) -> tuple[tuple[str, ...], str | None, tuple[str, ...]]:
    """Literal brand-lexicon matches: (tokens, canonical target, citable refs)."""
    lexicon = load_brands()
    if not lexicon:
        return (), None, ()
    hits: dict[str, tuple[str, str]] = {}
    refs: list[str] = []
    haystacks: list[tuple[str, str]] = [(item.value.lower(), item.evidence_ref) for item in strings]
    haystacks.append((static.app_label.lower(), ""))
    for token, canonical, sector in lexicon:
        for text, ref in haystacks:
            if not _matches(token, text):
                continue
            hits[token] = (canonical, sector)
            if ref and ref not in refs:
                refs.append(ref)
            break
    if not hits:
        return (), None, ()
    # The canonical target is the most specific hit: a sample naming both "sbi" and the
    # generic "kyc" is impersonating SBI, and compliance language is the wrapper.
    ranked = sorted(hits.items(), key=lambda kv: (kv[1][1] == "compliance", -len(kv[0])))
    return tuple(sorted(hits)), ranked[0][1][0], tuple(refs[:6])


def _matches(token: str, text: str) -> bool:
    """Whole-token containment. Avoids `rto` firing inside `important`."""
    if token not in text:
        return False
    index = text.find(token)
    before = text[index - 1] if index > 0 else " "
    after = text[index + len(token)] if index + len(token) < len(text) else " "
    return not (before.isalnum() or after.isalnum())


def _system_prompt() -> str:
    environment = Environment(
        loader=FileSystemLoader(_PROMPTS),
        autoescape=select_autoescape(enabled_extensions=(), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return environment.get_template("social_engineering.jinja").render()


def build_user_turn(
    strings: tuple[UiString, ...],
    static: StaticReport,
    *,
    script: str | None,
    language: str | None,
    brand: str | None,
) -> str:
    """Facts we established, then the sample's own words inside an untrusted block."""
    lines = [
        "Established mechanically (do not restate as your own finding):",
        f"  script: {script or 'none detected (Latin only)'}",
        f"  language: {language or 'not determined'}",
        f"  impersonated institution: {brand or 'none matched the lexicon'}",
        f"  app label: {static.app_label}",
        f"  certificate brand mismatch: {static.certificate.brand_mismatch}",
        "",
        "User-facing strings, with the evidence id you must cite for each:",
    ]
    for item in strings[:MAX_STRINGS_IN_PROMPT]:
        lines.append(f"\n{item.evidence_ref or '(uncitable)'}  locale={item.locale}")
        lines.append(wrap_untrusted(item.value, kind="ui_string"))
    lines.append("\nReturn the required JSON object.")
    return "\n".join(lines)


def profile_victim(
    static: StaticReport,
    strings: tuple[UiString, ...],
    ledger: LedgerStore,
    job_id: str,
    client: LLMClient,
) -> VictimProfile | None:
    """Build the victim profile, or return None when the evidence will not support one.

    None is a real answer here. `PHASE_3 §T3.8` requires the string-less APK path to be
    exercised explicitly, and the UI renders an absent profile as "not determined — no
    UI strings extracted" rather than as an empty card that reads as "no risk".
    """
    if not strings:
        log.info("victim_profile_skipped", reason="no UI strings extracted")
        return None

    script, script_refs = detect_script(strings)
    language, deterministic, language_notes = detect_language(script, strings)
    brand_tokens, brand, brand_refs = detect_brands(strings, static)

    notes = list(language_notes)
    deterministic_refs = tuple(dict.fromkeys((*script_refs, *brand_refs)))

    if script is None and not brand_tokens:
        # Latin-only strings with no brand match. There is nothing here that a profile
        # could assert deterministically, so we do not spend a call inviting the model
        # to invent one.
        log.info("victim_profile_skipped", reason="no script or brand signal")
        return None

    response = client.complete_as(
        system=_system_prompt(),
        user=build_user_turn(strings, static, script=script, language=language, brand=brand),
        schema=ProfileOut,
        purpose="social_engineering",
        max_output_tokens=800,
    )

    tactic: str | None = None
    segment: str | None = None
    model_refs: tuple[str, ...] = ()
    confidence = 0.0
    if response is None:
        notes.append("the model was unavailable; only the deterministic fields are reported")
    else:
        # Citation validity is decided by the Verifier, not by a second opinion
        # implemented here. One source of truth: if the verifier would reject a claim
        # resting on these refs, this profile does not get to assert them either.
        verifier = Verifier(ledger, job_id or None)
        citable = tuple(
            ref
            for ref in dict.fromkeys(response.evidence_refs[:8])
            if verifier.check_claim(
                GroundedClaim(
                    text="victim profile support",
                    evidence_refs=(ref,),
                    agent="social_engineering",
                    verifier_status=VerifierStatus.PASS,
                )
            )
            is VerifierStatus.PASS
        )
        model_refs = citable
        if citable:
            tactic = response.tactic if response.tactic in ALLOWED_TACTICS else None
            if tactic == "none":
                tactic = None
            segment = (response.segment or "").strip()[:200] or None
            confidence = min(max(float(response.confidence), 0.0), 1.0)
        else:
            # Same discipline as a rejected claim: an inference citing nothing is not
            # reported as a finding. It is reported as an inference we would not keep.
            notes.append(
                "the model's tactic/segment reading cited no resolvable evidence node "
                "and was dropped; the deterministic fields stand"
            )
        if response.reason.strip():
            notes.append(response.reason.strip()[:300])

    if brand and static.certificate.brand_mismatch:
        notes.append(
            f"the signing certificate does not correspond to {brand}; brand claim and "
            "signer disagree, which is the conjunction that matters"
        )

    refs = tuple(dict.fromkeys((*deterministic_refs, *model_refs)))
    if not refs:
        log.info("victim_profile_skipped", reason="no citable evidence for any field")
        return None

    profile = VictimProfile(
        language=language,
        script=script,
        language_is_deterministic=deterministic,
        tactic=tactic,
        segment=segment,
        impersonated_target=brand,
        brand_tokens=brand_tokens,
        # Deterministic findings alone are worth stating with moderate confidence; the
        # model's reading raises it only as far as the model claimed.
        confidence=round(max(confidence, 0.5 if (script or brand) else 0.0), 3),
        notes=tuple(notes[:6]),
        evidence_refs=refs[:8],
    )
    ledger.append(
        type=EvidenceType.AI_CLAIM,
        source_tool="m4_genai:social_engineering",
        content={
            "agent": "social_engineering",
            "language": profile.language,
            "script": profile.script,
            "tactic": profile.tactic,
            "segment": profile.segment,
            "impersonated_target": profile.impersonated_target,
            "brand_tokens": list(profile.brand_tokens),
            "evidence_refs": list(profile.evidence_refs),
        },
        parents=profile.evidence_refs,
        confidence=profile.confidence,
    )
    log.info(
        "victim_profile_built",
        script=script,
        language=language,
        deterministic=deterministic,
        brand=brand,
        tactic=tactic,
    )
    return profile


__all__ = [
    "ALLOWED_TACTICS",
    "detect_brands",
    "detect_language",
    "detect_script",
    "load_brands",
    "profile_victim",
    "scripts_of",
]
