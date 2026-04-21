from gh_audit.scanners.secrets import SecretsScanner
from gh_audit.scanners.base import ScanConfig

def _make_config():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc123", is_public=False)

def test_detects_aws_key_pattern(tmp_path):
    (tmp_path / "config.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    findings = SecretsScanner().scan(str(tmp_path), _make_config())
    assert any("aws" in f.rule_id.lower() for f in findings)

def test_detects_high_entropy_string(tmp_path):
    (tmp_path / "secret.txt").write_text("TOKEN=xK9mP2qR7nL4wB6vY1sZ3hA8cE5jF0uG\n")
    findings = SecretsScanner().scan(str(tmp_path), _make_config())
    assert len(findings) >= 1

def test_skips_binary_files(tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    findings = SecretsScanner().scan(str(tmp_path), _make_config())
    assert len(findings) == 0

def test_redacts_evidence(tmp_path):
    (tmp_path / "config.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    findings = SecretsScanner().scan(str(tmp_path), _make_config())
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence_redacted
