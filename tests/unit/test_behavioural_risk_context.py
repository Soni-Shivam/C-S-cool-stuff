"""The redesigned B: measured weights, a bounded gradient, and exculpatory context.

What these tests pin, and why each property is load-bearing:

* the weight table is measured and CLAMPED — no model-asserted boolean may carry a
  negative weight, because that would let injected strings LOWER a sample's score by
  goading the model into "benign-shaped" assertions
* context shifts B in both directions, but only once at least one positively-weighted
  behaviour is asserted — context alone never manufactures risk out of nothing, and
  exculpatory context never turns "no evidence" into a claim of innocence
* the combiner is a gradient: the old noisy-OR pinned B > 0.97 after four assertions
  (33 of 45 corpus samples above 0.95, benign apps out-scoring malware, AUC 0.47)
"""

from __future__ import annotations

import pytest

from drishti.m4_genai.safety import (
    B_BASE,
    BEHAVIOUR_WEIGHTS,
    CONTEXT_WEIGHTS,
    LLM_CONTEXT_KEYS,
    behavioural_risk,
)


def test_no_behaviour_weight_is_negative() -> None:
    """A negative weight on a model-asserted boolean is an injection channel."""
    for name, weight in BEHAVIOUR_WEIGHTS.items():
        assert weight >= 0.0, f"{name} has negative weight {weight}"


def test_llm_context_keys_are_small_and_in_the_context_table() -> None:
    """Model-answered context is capped small: bounded damage if it is talked into one."""
    for name in LLM_CONTEXT_KEYS:
        assert name in CONTEXT_WEIGHTS
        assert name not in BEHAVIOUR_WEIGHTS
        assert abs(CONTEXT_WEIGHTS[name]) <= 0.5


def test_exculpatory_context_reduces_b() -> None:
    findings = {"overlays_other_apps": True, "monitors_clipboard": True}
    plain, _ = behavioural_risk(findings)
    excused, _ = behavioural_risk(findings, context={"cert_signer_stable_years": True})
    assert excused < plain


def test_aggravating_context_raises_b() -> None:
    findings = {"overlays_other_apps": True}
    plain, _ = behavioural_risk(findings)
    worse, _ = behavioural_risk(findings, context={"targets_installed_financial_apps": True})
    assert worse > plain


def test_context_alone_never_creates_risk() -> None:
    """No positively-weighted behaviour asserted -> B is exactly 0, whatever context says."""
    aggravating = dict.fromkeys((k for k, w in CONTEXT_WEIGHTS.items() if w > 0), True)
    b_value, contributing = behavioural_risk({}, context=aggravating)
    assert b_value == 0.0
    assert contributing == ()
    # zero-weight assertions do not open the door either
    zero_only = {k: True for k, w in BEHAVIOUR_WEIGHTS.items() if w == 0.0}
    assert behavioural_risk(zero_only, context=aggravating)[0] == 0.0


def test_unknown_context_keys_are_ignored() -> None:
    findings = {"overlays_other_apps": True}
    plain, _ = behavioural_risk(findings)
    injected, _ = behavioural_risk(
        findings, context={"definitely_innocent": True, "threat_score": 0}
    )
    assert injected == plain


def test_non_boolean_context_values_are_refused() -> None:
    findings = {"overlays_other_apps": True}
    plain, _ = behavioural_risk(findings)
    sloppy, _ = behavioural_risk(
        findings, context={"cert_signer_stable_years": "yes", "debug_certificate": 1}
    )
    assert sloppy == plain


def test_b_is_a_gradient_not_a_step_function() -> None:
    """Each additional weighted behaviour must still move B — no saturation at four.

    The old noisy-OR failure mode: any four assertions pinned B > 0.97, so assertion
    COUNT was the whole signal and benign apps (which assert more) out-scored malware.
    """
    ordered = [k for k, w in sorted(BEHAVIOUR_WEIGHTS.items(), key=lambda kv: -kv[1]) if w > 0]
    previous = 0.0
    values = []
    # Strict growth is asserted over the range a real sample occupies. Beyond it the
    # sigmoid reaches 1.0 within float precision — a sample asserting a dozen distinct
    # malicious behaviours at once is "everything is true", and saturating THERE is
    # correct. The pathology this guards was saturation at FOUR, where benign apps sat.
    REALISTIC = 8
    for i in range(1, len(ordered) + 1):
        b_value, _ = behavioural_risk(dict.fromkeys(ordered[:i], True))
        if i <= REALISTIC:
            assert b_value > previous, f"B saturated at {i} assertions, below {REALISTIC}"
        else:
            assert b_value >= previous, "B must never DECREASE with another assertion"
        previous = b_value
        values.append(b_value)
    assert values[-1] <= 1.0

    # The pathology restated precisely. It was never "four assertions produce a high B" —
    # four of the HEAVIEST (accessibility abuse, contacts harvesting, notification
    # interception, overlay) is the banking-trojan signature, and B=0.998 for it is
    # correct. What was wrong is that under the old table every weight was >= 0.40, so any
    # four assertions pinned B above 0.97 — including the weak, common ones that benign
    # apps assert, which is how benign out-scored malware. Four LOW-weight behaviours must
    # therefore stay well off the ceiling.
    weakest_four = [
        k
        for k, _ in sorted(BEHAVIOUR_WEIGHTS.items(), key=lambda kv: kv[1])
        if BEHAVIOUR_WEIGHTS[k] > 0
    ][:4]
    weak_b, _ = behavioural_risk(dict.fromkeys(weakest_four, True))
    assert weak_b < 0.75, f"four low-weight assertions pinned B to {weak_b} ({weakest_four})"


def test_one_weak_behaviour_yields_small_b() -> None:
    """A single low-lift assertion is a whisper, not half the risk scale.

    The behaviour is read OUT of the weight table rather than named. This test used to
    hardcode `intercepts_notifications` as the weak one; the 2026-08-26 refit measured it
    at 2.00 — among the heaviest — and the test failed for a reason that had nothing to do
    with the property it guards. Weights are measurements and will move again; which
    behaviour is weakest is not a fact a test may assume.
    """
    weakest = min((w, k) for k, w in BEHAVIOUR_WEIGHTS.items() if w > 0)[1]
    b_value, _ = behavioural_risk({weakest: True})
    assert b_value < 0.25, f"{weakest} (w={BEHAVIOUR_WEIGHTS[weakest]}) gave B={b_value}"


def test_full_exculpation_drives_b_towards_zero() -> None:
    """A trusted publisher with a stable key and coherent purpose reads as low risk."""
    findings = {"overlays_other_apps": True, "monitors_clipboard": True}
    context = {
        "cert_signer_stable_years": True,
        "publisher_trusted": True,
        "lookalike_legitimate_privileged": True,
        "capability_use_consistent_with_declared_purpose": True,
    }
    b_value, _ = behavioural_risk(findings, context=context)
    assert b_value < 0.05


def test_recomputable_from_verdict_shape() -> None:
    """B must be reproducible from (behaviours, behaviour_context) exactly."""
    findings = dict.fromkeys(BEHAVIOUR_WEIGHTS, True)
    context = {"cert_signer_stable_years": True, "targets_installed_financial_apps": True}
    assert behavioural_risk(findings, context=context) == behavioural_risk(
        findings, context=context
    )


@pytest.mark.parametrize("base", [B_BASE])
def test_base_offset_keeps_a_below_median_assertion_under_half(base: float) -> None:
    """One below-median behaviour must not reach half the risk scale on its own.

    Deliberately NOT the heaviest. A single asserted accessibility abuse or overlay is a
    strong signal and B=0.5 for it is correct; the property worth protecting is that an
    ordinary assertion does not, which is what `B_BASE` buys.
    """
    positive = sorted(w for w in BEHAVIOUR_WEIGHTS.values() if w > 0)
    median = positive[len(positive) // 2]
    below = min((w, k) for k, w in BEHAVIOUR_WEIGHTS.items() if 0 < w <= median)[1]
    b_value, _ = behavioural_risk({below: True})
    assert b_value < 0.5, f"{below} (w={BEHAVIOUR_WEIGHTS[below]}) gave B={b_value}"
