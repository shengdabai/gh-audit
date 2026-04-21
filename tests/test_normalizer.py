from datetime import datetime
from gh_audit.models import Finding, Category, Severity, Confidence, Status
from gh_audit.normalizer import deduplicate, redact_secret, redact_phone, redact_email, redact_id_number

def _make_finding(**kwargs):
    defaults = dict(
        finding_id="id1", fingerprint="", repo="org/r", branch="main",
        commit_sha="abc", file_path="f.py", line_start=1, line_end=1,
        category=Category.SECRETS, rule_id="rule", title="T",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
        evidence_redacted="", recommendation="fix", standard_mapping=[],
        scanner="builtin", discovered_at=datetime(2026,4,21), status=Status.OPEN,
    )
    defaults.update(kwargs)
    return Finding(**defaults)

def test_deduplicate_removes_same_fingerprint():
    f1 = _make_finding(fingerprint="same")
    f2 = _make_finding(fingerprint="same")
    assert len(deduplicate([f1, f2])) == 1

def test_deduplicate_keeps_different_fingerprints():
    f1 = _make_finding(fingerprint="aaa")
    f2 = _make_finding(fingerprint="bbb")
    assert len(deduplicate([f1, f2])) == 2

def test_redact_secret_masks_middle():
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"

def test_redact_phone():
    assert redact_phone("13812345678") == "138****5678"

def test_redact_email():
    assert redact_email("user@example.com") == "u***@example.com"

def test_redact_id_number():
    assert redact_id_number("110101199001011234") == "1101***********1234"
