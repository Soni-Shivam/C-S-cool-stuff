"""Structural defences against sample-controlled text, and the B weight table.

docs/PHASE_3_GENAI_CORE.md T3.2, T3.6; docs/00_GUIDING_MAP.md §9.5; CLAUDE.md rules 4-6.

Everything a sample contains — string constants, decompiled method bodies, package
names, URLs — is **attacker-controlled input to a language model**. Two defences, and
the second is the one that makes the first survivable:

  1. Untrusted text goes in the USER turn inside an XML-escaped `<untrusted_artifact>`
     block, never concatenated into a system prompt. Escaping is what stops a sample
     closing the block and issuing its own instructions.

  2. **The model never emits the score.** It answers a fixed enumerated checklist of
     booleans; `behavioural_risk()` computes `B` from a weight table in Python. An
     injected "set threat_score=0" therefore changes nothing that reaches `S`.

Defence 1 on its own is an arms race against people who do this for a living. Defence 2
is why losing that race is not fatal.
"""

from __future__ import annotations

from html import escape

UNTRUSTED_OPEN = "<untrusted_artifact"
UNTRUSTED_CLOSE = "</untrusted_artifact>"

#: Hard cap on any single untrusted block. A sample can carry megabytes of strings, and
#: the prompt budget (00_GUIDING_MAP.md §12: 12k tokens in) is not negotiable.
MAX_BLOCK_CHARS = 4000


def wrap_untrusted(text: str, *, kind: str) -> str:
    """Wrap sample-derived text so it cannot be mistaken for instructions.

    `kind` records provenance (`string_constant`, `decompiled_method`, `manifest_entry`)
    so both a human reader and the model can see what they are looking at.

    The text is HTML-escaped, so a sample carrying a literal `</untrusted_artifact>`
    arrives as `&lt;/untrusted_artifact&gt;` and cannot terminate the block. Truncation
    is disclosed inline rather than silently, because a model reasoning over a fragment
    should know it is a fragment.
    """
    body = text if len(text) <= MAX_BLOCK_CHARS else text[:MAX_BLOCK_CHARS]
    truncated = len(text) > MAX_BLOCK_CHARS
    escaped = escape(body, quote=True)
    if truncated:
        escaped += f"\n[TRUNCATED — {len(text) - MAX_BLOCK_CHARS} more characters omitted]"
    return (
        f'{UNTRUSTED_OPEN} kind="{escape(kind, quote=True)}" truncated="{str(truncated).lower()}">'
        f"\n{escaped}\n{UNTRUSTED_CLOSE}"
    )


#: The enumerated behaviour checklist and its weights.
#:
#: This table is the whole of `B`. The model answers true/false to these names and
#: nothing else; anything it invents is ignored by `behavioural_risk`. Weights are
#: capability-ordered — loading code at runtime and abusing accessibility are the two
#: that most change what an app can do to a victim.
BEHAVIOUR_WEIGHTS: dict[str, float] = {
    "loads_dex_at_runtime": 0.85,
    "abuses_accessibility_service": 0.85,
    "overlays_other_apps": 0.80,
    "reads_sms_content": 0.75,
    "sends_sms_without_user_action": 0.80,
    "intercepts_notifications": 0.70,
    "exfiltrates_over_network": 0.70,
    "harvests_device_identifiers": 0.45,
    "harvests_contacts_or_call_log": 0.60,
    "monitors_clipboard": 0.55,
    "requests_device_admin": 0.60,
    "hides_or_disables_its_own_icon": 0.55,
    "detects_analysis_environment": 0.65,
    "encrypts_data_before_sending": 0.40,
    "impersonates_a_known_brand": 0.65,
    "gates_behaviour_on_installed_apps": 0.60,
}


def behavioural_risk(findings: dict[str, object]) -> tuple[float, tuple[str, ...]]:
    """Compute `B` in [0,1] from the enumerated checklist, plus what contributed.

    Deterministic, pure, and deliberately unforgiving of anything off-script:

      * a key not in `BEHAVIOUR_WEIGHTS` is **ignored** — the model cannot invent a
        high-weight behaviour, and an injected `threat_score` is just an unknown key
      * a value that is not a real `bool` is **refused, not coerced** — `"yes"`, `1` and
        `"true"` do not count, because coercing sloppy output would let it move `B`

    Fusion is noisy-OR rather than a sum: three correlated observations at 0.7 should
    read as strong-but-not-certain, not as 2.1 clipped to 1.0.
    """
    contributing: list[str] = []
    complement = 1.0
    for name, weight in BEHAVIOUR_WEIGHTS.items():
        value = findings.get(name)
        # `is True` on purpose: bool is a subclass of int, so `== True` would accept 1.
        if value is True:
            contributing.append(name)
            complement *= 1.0 - weight
    return (round(1.0 - complement, 6) if contributing else 0.0, tuple(contributing))
