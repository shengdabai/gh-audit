from gh_audit.models import Severity, Confidence

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_CONFIDENCE_WEIGHT = {
    Confidence.CONFIRMED: 1.0,
    Confidence.LIKELY: 0.7,
    Confidence.POSSIBLE: 0.4,
}


def score_finding(severity: Severity, confidence: Confidence, is_public: bool) -> int:
    sev = _SEVERITY_WEIGHT[severity]
    conf = _CONFIDENCE_WEIGHT[confidence]
    exposure = 1.2 if is_public else 1.0
    # max raw = 5 * 1.0 * 1.2 * 4 = 24; divide by 24 to normalize to 0-100
    raw = sev * conf * exposure * 4
    return min(100, int(raw / 24 * 100))
