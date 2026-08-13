import pytest

from drishti.scoring.engine import confidence, score_verdict, severity_band


@pytest.mark.parametrize("score,band", [
    (100, "Critical"), (85, "Critical"),
    (84, "High"), (65, "High"),
    (64, "Medium"), (40, "Medium"),
    (39, "Low"), (0, "Low"),
])
def test_severity_bands_boundaries(score, band):
    assert severity_band(score) == band


def test_confidence_high_when_signals_agree():
    assert confidence(1.0, 0.9, 0.9) == pytest.approx(1.0)


def test_confidence_drops_when_signals_disagree():
    # gamma=0.8, |0.9-0.4|=0.5 -> 0.8*0.5 = 0.4
    assert confidence(0.8, 0.9, 0.4) == pytest.approx(0.4)


def test_confirmed_hash_override():
    v = score_verdict(r=0.0, p_cal=0.0, b=0.0, g=0.0, d=0.0, gamma=0.2,
                      confirmed_malicious=True)
    assert v["score"] == 100
    assert v["confidence"] == 1.0
    assert v["band"] == "Critical"


def test_score_verdict_normal_path():
    v = score_verdict(r=0.4, p_cal=0.6, b=0.5, g=0.2, d=0.0, gamma=0.9)
    # f_ai=0.8 -> composite = 0.25*0.4+0.5*0.8+0.15*0.2+0 = 0.53 -> 53
    assert v["score"] == 53
    assert v["band"] == "Medium"
    # confidence = 0.9*(1-|0.6-0.5|) = 0.9*0.9 = 0.81
    assert v["confidence"] == pytest.approx(0.81)
