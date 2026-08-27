"""`B` must be able to lower the fused score, not only raise it.

Noisy-OR — `F_AI = P + B - P·B` — is monotone increasing in `B` over `B >= 0`. That is
the whole problem: `F_AI >= P_cal` always, so the GenAI layer could decline to add risk
but could never subtract it. A legitimate app that the classifier condemns was therefore
unrescuable by construction, and the product's stated purpose is precisely that rescue —
"a genuine app that fails the statistical model, where the behavioural layer can say it
uses that capability for a fair purpose".

The replacement is Bayesian, not ad-hoc. `BEHAVIOUR_WEIGHTS` and `CONTEXT_WEIGHTS` are
already measured log-likelihood ratios, so the natural combination is in log-odds:

    logit(F_AI) = logit(P_cal) + evidence

`evidence` is the signed sum of those LLRs. Positive evidence raises the fused belief,
negative evidence lowers it, and zero leaves the classifier untouched — which is exactly
what "the model found nothing to say" should mean.

Two invariants are load-bearing and tested here:

* **Silence is neutral.** `evidence == 0` must return `P_cal` unchanged. A GenAI layer
  that shifts the score merely by running would make every verdict depend on whether the
  provider happened to answer.
* **The scorer stays pure.** No I/O, no clock, no randomness (CLAUDE.md rule 3).
"""

from __future__ import annotations

import math

import pytest

from drishti.m6_score.engine import _fuse


def _logit(p: float) -> float:
    return math.log(p / (1 - p))


# ── the point of the change ──────────────────────────────────────────────────
def test_negative_evidence_lowers_the_fused_score_below_the_classifier() -> None:
    """The rescue case. Under noisy-OR this was arithmetically impossible."""
    assert _fuse(0.80, evidence=-2.0) < 0.80


def test_positive_evidence_raises_it() -> None:
    assert _fuse(0.20, evidence=2.0) > 0.20


def test_zero_evidence_leaves_the_classifier_exactly_alone() -> None:
    """ "The model found nothing to say" must not move the number in either direction."""
    for p in (0.01, 0.2, 0.5, 0.8, 0.99):
        assert _fuse(p, evidence=0.0) == pytest.approx(p, abs=1e-9)


def test_it_is_bayesian_evidence_combination() -> None:
    """logit(F_AI) = logit(P) + evidence, so the fusion is auditable arithmetic."""
    p, evidence = 0.30, 1.4
    # The tolerance is the scorer's deliberate 6-dp rounding, which exists so a score
    # serialises and re-reads identically rather than drifting in the last bit.
    assert _logit(_fuse(p, evidence=evidence)) == pytest.approx(_logit(p) + evidence, abs=1e-5)


# ── monotonicity and bounds ──────────────────────────────────────────────────
def test_it_is_monotone_in_the_evidence() -> None:
    values = [_fuse(0.5, evidence=e) for e in (-3.0, -1.0, 0.0, 1.0, 3.0)]
    assert values == sorted(values)


def test_it_is_monotone_in_the_classifier_probability() -> None:
    values = [_fuse(p, evidence=0.5) for p in (0.05, 0.25, 0.5, 0.75, 0.95)]
    assert values == sorted(values)


def test_the_result_stays_a_probability() -> None:
    for p in (0.0, 0.001, 0.5, 0.999, 1.0):
        for evidence in (-40.0, -3.0, 0.0, 3.0, 40.0):
            assert 0.0 <= _fuse(p, evidence=evidence) <= 1.0


def test_certainty_at_the_edges_does_not_produce_nan() -> None:
    """`logit(0)` and `logit(1)` are infinite; the calibrator can and does emit both."""
    for p in (0.0, 1.0):
        for evidence in (-5.0, 0.0, 5.0):
            assert math.isfinite(_fuse(p, evidence=evidence))


def test_a_zero_probability_can_still_be_raised_by_evidence() -> None:
    """p_cal 0.0 is a calibrator floor, not proof of innocence — B must still speak."""
    assert _fuse(0.0, evidence=4.0) > _fuse(0.0, evidence=0.0)


# ── absent inputs ────────────────────────────────────────────────────────────
def test_no_classifier_falls_back_to_the_behavioural_belief_alone() -> None:
    """With no ML term there is no prior to update, so B is the whole signal."""
    assert _fuse(None, evidence=0.0, behavioural=0.7) == pytest.approx(0.7)


def test_no_behavioural_signal_returns_the_classifier() -> None:
    assert _fuse(0.42, evidence=None) == pytest.approx(0.42)


def test_neither_input_is_zero_not_an_error() -> None:
    assert _fuse(None, evidence=None) == 0.0


# ── purity (CLAUDE.md rule 3) ────────────────────────────────────────────────
def test_the_fusion_is_deterministic() -> None:
    """Same inputs, same output, 200 times. No clock, no randomness, no state."""
    results = {_fuse(0.37, evidence=-0.83) for _ in range(200)}
    assert len(results) == 1
