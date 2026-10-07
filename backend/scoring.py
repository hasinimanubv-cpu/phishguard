"""PhishGuard weighted risk scoring and API response generation."""
try:
    from detector import WEIGHTS
except ImportError:
    from .detector import WEIGHTS


def score_risk(factors: dict) -> int:
    """R = .25U + .20S + .20C + .15L + .10D + .10P, converted to 0–100."""
    return round(sum(WEIGHTS[key] * int(bool(factors.get(key, 0))) for key in WEIGHTS) * 100)


def build_result(factors: dict, indicators: list[dict]) -> dict:
    risk_score = score_risk(factors)
    if risk_score >= 61:
        level, action = "HIGH", "BLOCK/QUARANTINE (SIMULATION ONLY)"
    elif risk_score >= 31:
        level, action = "MEDIUM", "WARN"
    else:
        level, action = "LOW", "ALLOW"
    explanation = ("Detected: " + "; ".join(item["label"] for item in indicators) + "."
                   if indicators else "No configured phishing indicators were detected. This result does not prove the content is safe.")
    # Keep the dashboard contract to exactly the five fields requested by the frontend.
    return {
        "risk_score": risk_score,
        "risk_level": level,
        "indicators": indicators,
        "recommended_action": action,
        "explanation": explanation,
    }
