W_R = 0.25
W_AI = 0.50
W_G = 0.15
W_D = 0.10


def fused_ai(p_cal: float, b: float) -> float:
    """Joint probability of non-mutually-exclusive events (paper §4.6)."""
    return p_cal + b - (p_cal * b)


def composite_score(r: float, f_ai: float, g: float, d: float) -> float:
    weighted = W_R * r + W_AI * f_ai + W_G * g + W_D * d
    return 100.0 * min(1.0, weighted)


def confidence(gamma: float, p_cal: float, b: float) -> float:
    return gamma * (1.0 - abs(p_cal - b))


def severity_band(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def score_verdict(*, r, p_cal, b, g, d, gamma, confirmed_malicious=False) -> dict:
    if confirmed_malicious:
        return {"score": 100, "confidence": 1.0, "band": "Critical"}
    f_ai = fused_ai(p_cal, b)
    s = composite_score(r, f_ai, g, d)
    return {
        "score": int(round(s)),
        "confidence": round(confidence(gamma, p_cal, b), 4),
        "band": severity_band(s),
    }
