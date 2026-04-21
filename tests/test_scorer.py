from gh_audit.models import Severity, Confidence
from gh_audit.scorer import score_finding

def test_critical_confirmed_scores_highest():
    assert score_finding(Severity.CRITICAL, Confidence.CONFIRMED, is_public=True) >= 90

def test_low_possible_scores_lowest():
    assert score_finding(Severity.LOW, Confidence.POSSIBLE, is_public=False) <= 30

def test_public_repo_scores_higher_than_private():
    pub = score_finding(Severity.HIGH, Confidence.LIKELY, is_public=True)
    priv = score_finding(Severity.HIGH, Confidence.LIKELY, is_public=False)
    assert pub > priv
