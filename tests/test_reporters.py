import json
from datetime import datetime
from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.reporters.html_report import HtmlReporter

def _finding():
    f = Finding(
        finding_id="abc", fingerprint="fp1",
        repo="org/repo", branch="main", commit_sha="abc123",
        file_path="app/config.py", line_start=10, line_end=10,
        category=Category.SECRETS, rule_id="aws-key",
        title="AWS Key", severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate key",
        standard_mapping=["CWE-798"],
        scanner="builtin",
        discovered_at=datetime(2026, 4, 21),
        status=Status.OPEN,
    )
    return f

def test_json_reporter_produces_valid_json(tmp_path):
    out = tmp_path / "report.json"
    JsonReporter().write([_finding()], str(out), repo="org/repo")
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["severity"] == "critical"

def test_html_reporter_produces_html_file(tmp_path):
    out = tmp_path / "report.html"
    HtmlReporter().write([_finding()], str(out), repo="org/repo")
    content = out.read_text()
    assert "<!DOCTYPE html>" in content
    assert "AWS Key" in content
    assert "AKIAIOSFODNN7EXAMPLE" not in content
