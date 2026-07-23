import pytest

from drishti.scoring.engine import composite_score, fused_ai


def test_fused_ai_joint_probability():
    # 0.6 + 0.5 - 0.3 = 0.8
    assert fused_ai(0.6, 0.5) == pytest.approx(0.8)


def test_fused_ai_bounds():
    assert fused_ai(0.0, 0.0) == 0.0
    assert fused_ai(1.0, 0.0) == 1.0
    assert fused_ai(1.0, 1.0) == 1.0


def test_composite_score_clamps_to_100():
    assert composite_score(1.0, 1.0, 1.0, 1.0) == 100.0


def test_composite_score_all_zero():
    assert composite_score(0.0, 0.0, 0.0, 0.0) == 0.0


def test_composite_score_weighted_sum():
    # 0.25*0.4 + 0.50*0.8 + 0.15*0.2 + 0.10*0.0 = 0.1+0.4+0.03+0 = 0.53
    assert composite_score(0.4, 0.8, 0.2, 0.0) == pytest.approx(53.0)
