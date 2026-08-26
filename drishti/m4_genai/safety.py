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
from math import exp

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
#: This table is the whole of the inculpatory half of `B`. The model answers true/false
#: to these names and nothing else; anything it invents is ignored by `behavioural_risk`.
#:
#: **The weights are measured, not hand-assigned severities.** Each is the smoothed
#: log-likelihood ratio log(P(asserted|malware)/P(asserted|benign)) of the model's own
#: assertions over 45 labelled corpus samples (21 malware / 24 benign) with completed
#: GenAI verdicts, add-0.5 smoothed, capped at 2.0, and **clamped at 0.0** — see below.
#: Derivation: `scripts/fit_behaviour_weights.py` over the analysis VM's job store
#: joined to `/tmp/lift_results.csv` labels, 2026-08-26. Held-out quality was estimated
#: with 10x stratified 5-fold CV (weights refitted inside every fold): B AUC 0.64,
#: composite S AUC 0.86 on the 45 — against 0.47 / 0.57 for the previous hand-weighted
#: noisy-OR table, which ranked benign apps ABOVE malware.
#:
#: Why clamped at zero rather than signed: several capability behaviours fire *more*
#: often on large legitimate apps than on malware (measured signed LLRs:
#: `loads_dex_at_runtime` -1.09 — split-APK / dynamic-feature delivery;
#: `reads_sms_content` -1.06; `harvests_device_identifiers` -0.01;
#: `encrypts_data_before_sending` -0.14). A negative weight on a model-asserted boolean
#: would hand the sample an injection channel — strings that goad the model into
#: asserting a "benign-shaped" behaviour would LOWER its score — and it breaks the
#: monotonicity pinned by `test_b_is_monotone_in_the_behaviour_set`. So a
#: non-discriminative behaviour contributes exactly nothing, and exculpation is carried
#: by `CONTEXT_WEIGHTS`, whose exculpatory entries are computed deterministically in
#: Python from static evidence the sample cannot cheaply forge.
#:
#: A zero weight is still a real checklist entry: the assertion is recorded, grounded,
#: and shown to the analyst — it just does not move `B`, because on measurement it does
#: not separate malware from benign. Re-measure this table whenever the checklist
#: question text changes: the weights are properties of the question as asked.
# REFIT 2026-08-26 against the PURPOSE-phrased checklist, on 59 labelled corpus samples
# (29 malware) analysed through the live pipeline. The previous table was measured against
# the older CAPABILITY-phrased questions, so it described questions that were no longer
# being asked — a weight is a property of the question, not of the behaviour name.
#
# Held-out B AUC: **0.754** (10x stratified 5-fold CV, weights refitted inside every fold,
# min 0.736 max 0.770). The table below is fit on all 59 rows and is therefore in-sample;
# only the CV figure may be quoted. Reproduce with scripts/fit_behaviour_weights.py.
#
# Progression, all held out: 0.473 (capability questions, hand-assigned severities)
# -> 0.644 (purpose questions, weights still fitted to the old ones) -> 0.754.
BEHAVIOUR_WEIGHTS: dict[str, float] = {
    "abuses_accessibility_service": 2.00,
    "harvests_contacts_or_call_log": 2.00,
    "intercepts_notifications": 2.00,
    "overlays_other_apps": 2.00,
    "requests_device_admin": 2.00,
    "exfiltrates_over_network": 1.37,
    "harvests_device_identifiers": 1.13,
    "impersonates_a_known_brand": 1.13,
    "gates_behaviour_on_installed_apps": 0.85,
    "monitors_clipboard": 0.69,
    "sends_sms_without_user_action": 0.65,
    "encrypts_data_before_sending": 0.54,
    "detects_analysis_environment": 0.03,
    "hides_or_disables_its_own_icon": 0.03,
    # Both measured at or below zero and clamped. `loads_dex_at_runtime` is the
    # instructive one: it was 0.85 in the original hand-assigned table and measures
    # NEGATIVE, because split-APK delivery means most benign apps do it. A model-asserted
    # boolean may never carry negative weight (it would be an injection channel: goad the
    # model into a benign-shaped assertion to lower the score), so it is clamped to zero
    # and contributes nothing rather than exonerating.
    "loads_dex_at_runtime": 0.00,
    "reads_sms_content": 0.00,
}

#: Contextual evidence that shifts `B` in either direction — the exculpatory half the
#: old design lacked entirely (a legitimate app using SYSTEM_ALERT_WINDOW for
#: picture-in-picture used to score identically to an overlay banking trojan).
#:
#: Two provenances, deliberately asymmetric in trust:
#:
#:   * Deterministic static facts (computed in Python by `static_behaviour_context`,
#:     never by the model): signer stability, debug certificate, a trusted publisher,
#:     the lookalike assessment, a hardcoded roster of installed financial apps. These
#:     carry the large exculpatory weights, because the sample cannot talk its way into
#:     them — an old, stable signing key or a trusted publisher cert has to actually
#:     exist. `cert_signer_stable_years`, `debug_certificate` and
#:     `targets_installed_financial_apps` are measured LLRs from the same corpus fit
#:     (capped ±1.5, refit 2026-08-26 on 59 samples); `publisher_trusted` and
#:     `lookalike_legitimate_privileged` never fired on the corpus, so their weights are
#:     declared priors, not measurements.
#:
#:   * Two model-answered PURPOSE questions (`LLM_CONTEXT_KEYS`). These are priors
#:     pending live measurement, and their magnitudes are deliberately small (±0.5,
#:     ≈ one sigmoid step of 0.1 at the operating point) precisely because a
#:     model-asserted exculpatory boolean is an injection surface: sample strings could
#:     goad the model into "consistent with purpose". Small weight = bounded damage.
CONTEXT_WEIGHTS: dict[str, float] = {
    # deterministic static facts — Python-computed, model never touches them
    "cert_signer_stable_years": -1.13,  # measured LLR (refit), signer ≥ 730 days, not debug
    "publisher_trusted": -2.00,  # prior: never fired on the fit corpus
    "lookalike_legitimate_privileged": -1.00,  # prior: never fired on the fit corpus
    "targets_installed_financial_apps": 1.50,  # measured LLR, capped
    "debug_certificate": 1.50,  # measured LLR (refit), capped
    # model-answered purpose questions — priors, small on purpose (injection surface)
    "capability_use_consistent_with_declared_purpose": -0.50,
    "risky_capability_serves_no_plausible_feature": 0.50,
}

#: The context keys the MODEL is allowed to answer. Everything else in
#: `CONTEXT_WEIGHTS` is computed deterministically and a model-supplied value for it
#: must be ignored — `static_behaviour_context` in the controller owns those.
LLM_CONTEXT_KEYS: tuple[str, ...] = (
    "capability_use_consistent_with_declared_purpose",
    "risky_capability_serves_no_plausible_feature",
)

#: Sigmoid offset: with one behaviour asserted and no context, B stays small — the
#: combiner is a gradient, not the old step function (4 assertions used to pin B>0.97
#: regardless of which 4, which is how 33 of 45 corpus samples landed above 0.95 and
#: benign apps out-scored malware).
B_BASE = -2.0


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + exp(-z))
    e = exp(z)
    return e / (1.0 + e)


def behavioural_risk(
    findings: dict[str, object],
    context: dict[str, object] | None = None,
) -> tuple[float, tuple[str, ...]]:
    """Compute `B` in [0,1] from the enumerated checklist and context, plus contributors.

    `B = sigmoid(B_BASE + Σ behaviour_weights + Σ context_weights)` — bounded, monotone
    in every asserted behaviour (all behaviour weights are ≥ 0), and a genuine gradient:
    it does not saturate after four assertions the way the old noisy-OR did.

    Deterministic, pure, and deliberately unforgiving of anything off-script:

      * a key not in `BEHAVIOUR_WEIGHTS` / `CONTEXT_WEIGHTS` is **ignored** — the model
        cannot invent a high-weight behaviour, and an injected `threat_score` is just an
        unknown key
      * a value that is not a real `bool` is **refused, not coerced** — `"yes"`, `1` and
        `"true"` do not count, because coercing sloppy output would let it move `B`
      * if no positively-weighted behaviour is asserted, `B` is exactly 0.0: context
        alone never raises a risk claim out of nothing, and "no evidence" stays "no
        claim" rather than becoming a sigmoid floor

    `context` mixes deterministic static facts with the two model-answered purpose
    booleans; the split, and why the exculpatory weight lives on the deterministic side,
    is documented on `CONTEXT_WEIGHTS`.
    """
    contributing: list[str] = []
    z = B_BASE
    for name, weight in BEHAVIOUR_WEIGHTS.items():
        value = findings.get(name)
        # `is True` on purpose: bool is a subclass of int, so `== True` would accept 1.
        if value is True and weight > 0:
            contributing.append(name)
            z += weight
    if not contributing:
        return 0.0, ()
    for name, weight in CONTEXT_WEIGHTS.items():
        if context is not None and context.get(name) is True:
            z += weight
    return round(_sigmoid(z), 6), tuple(contributing)


def behavioural_evidence(
    findings: dict[str, object],
    context: dict[str, object] | None = None,
) -> float:
    """The SIGNED log-likelihood ratio behind `B`, for log-odds fusion in the scorer.

    `behavioural_risk` returns `sigmoid(B_BASE + Σw)`, which is bounded and displayable
    but discards the sign. The sign is what lets the behavioural layer *exonerate*: a
    trusted publisher and a signer key stable for years are negative evidence, and the
    scorer adds this number to the classifier's log-odds so that evidence can pull the
    fused score BELOW `p_calibrated`.

    `B_BASE` is excluded deliberately. It is a prior offset that calibrates B for display
    on its own; the classifier already supplies the prior in the fusion, so including it
    again would double-count and shift every score by a constant.

    Returns exactly 0.0 when no positively-weighted behaviour was asserted — the same
    "no claim" rule `behavioural_risk` uses. Context alone never creates evidence, in
    either direction: exonerating an app nobody accused is not a finding.
    """
    contributing = [
        name
        for name, weight in BEHAVIOUR_WEIGHTS.items()
        if findings.get(name) is True and weight > 0
    ]
    if not contributing:
        return 0.0
    z = sum(BEHAVIOUR_WEIGHTS[name] for name in contributing)
    for name, weight in CONTEXT_WEIGHTS.items():
        if context is not None and context.get(name) is True:
            z += weight
    return round(z, 6)
