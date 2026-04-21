"""Tests for new fixes: expiry enforcement, entropy redaction, diff, suppress, luhn, confidence levels."""
import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.normalizer import (
    diff_findings,
    load_previous_content_fingerprints,
    load_suppressions,
)
from gh_audit.scanners.pii import _luhn_check
from gh_audit.scanners.secrets import SecretsScanner, _redact_entropy_token, _shannon_entropy
from gh_audit.scanners.base import ScanConfig


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_finding(rule_id="rule", evidence="ev", file_path="f.py", line_start=1,
                  category=Category.SECRETS):
    f = Finding(
        finding_id="id1", fingerprint="",
        repo="org/r", branch="main", commit_sha="abc",
        file_path=file_path, line_start=line_start, line_end=line_start,
        category=category, rule_id=rule_id, title="T",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
        evidence_redacted=evidence, recommendation="fix",
        standard_mapping=[], scanner="builtin",
        discovered_at=datetime(2026, 4, 21, tzinfo=timezone.utc),
        status=Status.OPEN,
    )
    f.fingerprint = f.compute_fingerprint()
    return f


def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc123", is_public=False)


# ── _luhn_check ──────────────────────────────────────────────────────────────

def test_luhn_check_valid_card():
    # Luhn-valid test card number
    assert _luhn_check("4532015112830366") is True


def test_luhn_check_invalid_card():
    # One digit off → fails Luhn
    assert _luhn_check("4532015112830367") is False


def test_luhn_check_short_number_rejected():
    assert _luhn_check("123456789012345") is False  # 15 digits < 16


def test_luhn_check_non_digits_ignored():
    # Spaces should be ignored, valid card still passes
    assert _luhn_check("4532 0151 1283 0366") is True


def test_pii_bank_card_invalid_luhn_skipped(tmp_path):
    # A 16-digit number that fails Luhn should not be reported
    (tmp_path / "data.txt").write_text("card=1234567890123456\n")
    from gh_audit.scanners.pii import PiiScanner
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert not any(f.rule_id == "cn-bank-card" for f in findings)


def test_pii_bank_card_valid_luhn_detected(tmp_path):
    (tmp_path / "data.txt").write_text("card=4532015112830366\n")
    from gh_audit.scanners.pii import PiiScanner
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "cn-bank-card" for f in findings)


# ── _redact_entropy_token ────────────────────────────────────────────────────

def test_redact_entropy_token_format():
    value = "xK9mP2qR7nL4wB6v"  # 16 chars
    result = _redact_entropy_token(value)
    assert result.startswith(value[:2])
    assert result.endswith(value[-2:])
    assert "*" * (len(value) - 4) in result
    assert len(result) == len(value)


def test_redact_entropy_token_short():
    assert _redact_entropy_token("abc") == "****"


def test_entropy_token_confidence_is_possible(tmp_path):
    (tmp_path / "secret.txt").write_text("TOKEN=xK9mP2qR7nL4wB6vY1sZ3hA8cE5jF0uG\n")
    findings = SecretsScanner().scan(str(tmp_path), _cfg())
    entropy_findings = [f for f in findings if f.rule_id == "high-entropy-string"]
    assert all(f.confidence == Confidence.POSSIBLE for f in entropy_findings)


# ── confidence levels for named patterns ─────────────────────────────────────

def test_aws_key_confidence_confirmed(tmp_path):
    (tmp_path / "c.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    findings = SecretsScanner().scan(str(tmp_path), _cfg())
    aws = [f for f in findings if f.rule_id == "aws-access-key"]
    assert aws and all(f.confidence == Confidence.CONFIRMED for f in aws)


def test_github_token_confidence_confirmed(tmp_path):
    (tmp_path / "c.env").write_text("GH_TOKEN=ghp_" + "A" * 36 + "\n")
    findings = SecretsScanner().scan(str(tmp_path), _cfg())
    gh = [f for f in findings if f.rule_id == "github-token"]
    assert gh and all(f.confidence == Confidence.CONFIRMED for f in gh)


def test_db_password_placeholder_skipped(tmp_path):
    # Low-entropy placeholder should be skipped
    (tmp_path / ".env.example").write_text("DB_PASSWORD=CHANGEME\n")
    findings = SecretsScanner().scan(str(tmp_path), _cfg())
    assert not any(f.rule_id == "db-password" for f in findings)


def test_db_password_real_secret_detected(tmp_path):
    # High-entropy real password should be detected
    (tmp_path / ".env").write_text("DB_PASSWORD=xK9mP2qR7nL4wB6v\n")
    findings = SecretsScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "db-password" for f in findings)


# ── diff_findings ─────────────────────────────────────────────────────────────

def test_diff_findings_excludes_previous():
    f = _make_finding(rule_id="aws-access-key", evidence="AKIA****WXYZ")
    prev = {f.compute_content_fingerprint()}
    result = diff_findings([f], prev)
    assert result == []


def test_diff_findings_includes_new():
    f = _make_finding(rule_id="aws-access-key", evidence="AKIA****WXYZ")
    result = diff_findings([f], set())
    assert result == [f]


def test_diff_findings_mixed():
    old_f = _make_finding(rule_id="rule-old", evidence="old-ev", file_path="a.py")
    new_f = _make_finding(rule_id="rule-new", evidence="new-ev", file_path="b.py")
    prev = {old_f.compute_content_fingerprint()}
    result = diff_findings([old_f, new_f], prev)
    assert result == [new_f]


# ── load_previous_content_fingerprints ───────────────────────────────────────

def test_load_previous_returns_empty_when_no_dir(tmp_path):
    fps = load_previous_content_fingerprints(tmp_path, "org/repo")
    assert fps == set()


def test_load_previous_returns_fingerprints(tmp_path):
    f = _make_finding()
    safe = "org_repo"
    repo_dir = tmp_path / safe
    repo_dir.mkdir()
    scan_data = {"findings": [f.to_dict()]}
    (repo_dir / "20260421_120000.json").write_text(json.dumps(scan_data))
    fps = load_previous_content_fingerprints(tmp_path, "org/repo")
    assert f.compute_content_fingerprint() in fps


def test_load_previous_uses_most_recent(tmp_path):
    f1 = _make_finding(rule_id="old-rule", evidence="old-ev")
    f2 = _make_finding(rule_id="new-rule", evidence="new-ev")
    safe = "org_repo"
    repo_dir = tmp_path / safe
    repo_dir.mkdir()
    (repo_dir / "20260420_000000.json").write_text(json.dumps({"findings": [f1.to_dict()]}))
    (repo_dir / "20260421_000000.json").write_text(json.dumps({"findings": [f2.to_dict()]}))
    fps = load_previous_content_fingerprints(tmp_path, "org/repo")
    assert f2.compute_content_fingerprint() in fps
    assert f1.compute_content_fingerprint() not in fps


# ── load_suppressions expiry ──────────────────────────────────────────────────

def test_load_suppressions_returns_active(tmp_path, monkeypatch):
    suppress_dir = tmp_path / ".gh-audit"
    suppress_dir.mkdir()
    suppress_file = suppress_dir / "suppressions.json"
    fresh_created = datetime.now(timezone.utc).isoformat()
    data = {"fp_active": {"reason": "test", "expires": "90d", "created_at": fresh_created}}
    suppress_file.write_text(json.dumps(data))

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = load_suppressions()
    assert "fp_active" in result


def test_load_suppressions_skips_expired(tmp_path, monkeypatch, tmp_path_factory):
    suppress_dir = tmp_path / ".gh-audit"
    suppress_dir.mkdir()
    suppress_file = suppress_dir / "suppressions.json"
    old_created = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    data = {"fp_expired": {"reason": "test", "expires": "30d", "created_at": old_created}}
    suppress_file.write_text(json.dumps(data))

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = load_suppressions()
    assert "fp_expired" not in result


def test_load_suppressions_keeps_active_entry(tmp_path, monkeypatch):
    suppress_dir = tmp_path / ".gh-audit"
    suppress_dir.mkdir()
    suppress_file = suppress_dir / "suppressions.json"
    fresh_created = datetime.now(timezone.utc).isoformat()
    data = {"fp_fresh": {"reason": "test", "expires": "30d", "created_at": fresh_created}}
    suppress_file.write_text(json.dumps(data))

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = load_suppressions()
    assert "fp_fresh" in result


def test_load_suppressions_no_expiry_keeps_entry(tmp_path, monkeypatch):
    suppress_dir = tmp_path / ".gh-audit"
    suppress_dir.mkdir()
    suppress_file = suppress_dir / "suppressions.json"
    # Legacy entry without created_at — should be kept (treated as non-expiring)
    data = {"fp_legacy": {"reason": "legacy", "expires": "30d"}}
    suppress_file.write_text(json.dumps(data))

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = load_suppressions()
    assert "fp_legacy" in result
