"""Social-Engineering Analyst: facts are deterministic, inferences must be grounded.

docs/PHASE_3_GENAI_CORE.md T3.8, docs/ROADMAP_GENAI_RE.md A4.

The property the pitch rests on: a Devanagari KYC lure yields language="hi" and an
impersonated bank, each citing a real string node — while a string-less app yields no
profile at all, never a confident guess.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.config import Settings
from drishti.contracts.static_report import CertificateInfo, StaticReport
from drishti.ledger.store import LedgerStore
from drishti.m4_genai.agents.social_engineering import (
    detect_brands,
    detect_language,
    detect_script,
    load_brands,
    profile_victim,
    scripts_of,
)
from drishti.m4_genai.client import LLMClient
from drishti.m4_genai.resources import UiString

_CERT = CertificateInfo(
    subject="CN=t",
    issuer="CN=t",
    sha256="0" * 64,
    not_before="2020-01-01",
    not_after="2030-01-01",
    age_days=10,
    self_signed=True,
    brand_mismatch=True,
)


def _report(label: str = "SBI Secure") -> StaticReport:
    return StaticReport(
        sha256="a" * 64,
        package="com.x",
        app_label=label,
        version_name="1",
        version_code=1,
        min_sdk=21,
        target_sdk=33,
        certificate=_CERT,
    )


@pytest.fixture
def ledger(tmp_path: Path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_se")
    yield store
    store.close()


def _recorded(store: LedgerStore, strings: list[tuple[str, str, str]]) -> tuple[UiString, ...]:
    """Append STRING_CONST nodes and return citable UiStrings (value, locale, resid)."""
    from drishti.contracts.evidence import EvidenceType

    out = []
    for value, locale, resid in strings:
        node = store.append(
            type=EvidenceType.STRING_CONST,
            source_tool="test",
            content={"value": value, "kind": "ui_string", "locale": locale},
            location=resid,
        )
        out.append(UiString(value=value, locale=locale, resource_id=resid, evidence_ref=node.id))
    return tuple(out)


# ── deterministic script and language ────────────────────────────────────────
def test_devanagari_is_a_fact_not_a_guess() -> None:
    assert "Devanagari" in scripts_of("आपका खाता निलंबित")
    assert scripts_of("Account suspended") == frozenset()


def test_script_detection_is_dominant_not_incidental() -> None:
    strings = (
        UiString(value="Login", locale="DEFAULT", resource_id="a", evidence_ref="ev_1"),
        UiString(
            value="केवाईसी सत्यापन आवश्यक है", locale="DEFAULT", resource_id="b", evidence_ref="ev_2"
        ),
    )
    script, refs = detect_script(strings)
    assert script == "Devanagari"
    assert "ev_2" in refs


def test_a_resource_locale_names_the_language_authoritatively() -> None:
    strings = (UiString(value="केवाईसी", locale="hi", resource_id="a", evidence_ref="ev_1"),)
    language, deterministic, _ = detect_language("Devanagari", strings)
    assert language == "hi"
    assert deterministic is True


def test_a_shared_script_without_a_locale_does_not_pick_a_language() -> None:
    """Hindi and Marathi share Devanagari. Guessing one would be dishonest."""
    strings = (UiString(value="खाते", locale="DEFAULT", resource_id="a", evidence_ref="ev_1"),)
    language, deterministic, notes = detect_language("Devanagari", strings)
    assert language is None
    assert deterministic is False
    assert any("shared" in n for n in notes)


# ── brand lexicon ────────────────────────────────────────────────────────────
def test_the_brand_lexicon_loads() -> None:
    lexicon = load_brands()
    assert lexicon, "the impersonation lexicon must be present"
    tokens = {row[0] for row in lexicon}
    assert "sbi" in tokens and "kyc" in tokens


def test_a_named_bank_is_matched_and_cited() -> None:
    strings = (
        UiString(
            value="Verify your SBI account now",
            locale="DEFAULT",
            resource_id="a",
            evidence_ref="ev_1",
        ),
    )
    tokens, target, refs = detect_brands(strings, _report())
    assert "sbi" in tokens
    assert target == "State Bank of India"
    assert "ev_1" in refs


def test_the_specific_brand_outranks_the_compliance_wrapper() -> None:
    strings = (
        UiString(
            value="Complete KYC for your HDFC account",
            locale="DEFAULT",
            resource_id="a",
            evidence_ref="ev_1",
        ),
    )
    _, target, _ = detect_brands(strings, _report())
    assert target == "HDFC Bank", "KYC is the lure; HDFC is who it impersonates"


def test_a_substring_does_not_false_match() -> None:
    """`rto` must not fire inside `important`."""
    strings = (
        UiString(
            value="This is important information",
            locale="DEFAULT",
            resource_id="a",
            evidence_ref="ev_1",
        ),
    )
    tokens, _, _ = detect_brands(strings, _report(label="Notes"))
    assert "rto" not in tokens


# ── the whole profile ────────────────────────────────────────────────────────
@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        groq_api_key="gsk-test",
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )


def test_a_stringless_app_yields_no_profile(ledger, settings) -> None:
    """The explicit null path from T3.8 — never a guess when there is nothing to read."""
    client = LLMClient(settings)
    assert profile_victim(_report(), (), ledger, "job_se", client) is None


def test_a_latin_only_app_with_no_brand_yields_no_profile(ledger, settings) -> None:
    strings = _recorded(ledger, [("Welcome to the app", "DEFAULT", "r1")])
    client = LLMClient(settings)
    assert profile_victim(_report(label="Notepad"), strings, ledger, "job_se", client) is None


def test_a_devanagari_bank_lure_yields_a_grounded_profile(ledger, settings) -> None:
    strings = _recorded(
        ledger,
        [
            ("आपका SBI खाता निलंबित है", "hi", "r1"),
            ("KYC verification required within 24 hours", "hi", "r2"),
        ],
    )
    client = LLMClient(settings)
    profile = profile_victim(_report(), strings, ledger, "job_se", client)
    assert profile is not None
    assert profile.script == "Devanagari"
    assert profile.language == "hi"
    assert profile.language_is_deterministic is True
    assert profile.impersonated_target == "State Bank of India"
    assert profile.evidence_refs, "every profile field must trace to a string node"
    for ref in profile.evidence_refs:
        assert ledger.get(ref) is not None


def test_the_certificate_conjunction_is_noted(ledger, settings) -> None:
    """Brand claim + signer mismatch is the conjunction that matters, and it is stated."""
    strings = _recorded(ledger, [("Login to your HDFC Bank account", "DEFAULT", "r1")])
    client = LLMClient(settings)
    profile = profile_victim(_report(label="HDFC"), strings, ledger, "job_se", client)
    assert profile is not None
    assert any("certificate" in n.lower() for n in profile.notes)
