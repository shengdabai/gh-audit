from datetime import datetime
from gh_audit.models import Finding, Category, Severity, Confidence, Status

def test_finding_fingerprint_is_deterministic():
    f = Finding(
        finding_id="test-id", fingerprint="",
        repo="org/repo", branch="main", commit_sha="abc123",
        file_path="config/.env", line_start=1, line_end=1,
        category=Category.SECRETS, rule_id="aws-access-key",
        title="AWS Access Key", severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate this key immediately",
        standard_mapping=["CWE-798"], scanner="builtin",
        discovered_at=datetime(2026, 4, 21), status=Status.OPEN,
    )
    fp1 = f.compute_fingerprint()
    fp2 = f.compute_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64

def test_finding_to_dict_has_all_fields():
    f = Finding(
        finding_id="test-id", fingerprint="abc",
        repo="org/repo", branch="main", commit_sha="abc123",
        file_path="config/.env", line_start=1, line_end=1,
        category=Category.SECRETS, rule_id="aws-access-key",
        title="AWS Access Key", severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate key", standard_mapping=[],
        scanner="builtin", discovered_at=datetime(2026, 4, 21),
        status=Status.OPEN,
    )
    d = f.to_dict()
    assert d["repo"] == "org/repo"
    assert d["severity"] == "critical"
    assert d["category"] == "secrets"
