from gh_audit.scanners.pii import PiiScanner
from gh_audit.scanners.base import ScanConfig

def _cfg():
    return ScanConfig(repo="org/r", branch="main", commit_sha="abc", is_public=False)

def test_detects_chinese_phone(tmp_path):
    (tmp_path / "data.csv").write_text("name,phone\n张三,13812345678\n", encoding="utf-8")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "cn-phone" for f in findings)

def test_detects_chinese_id_number(tmp_path):
    (tmp_path / "data.txt").write_text("id=110101199001011234\n", encoding="utf-8")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "cn-id-number" for f in findings)

def test_detects_email(tmp_path):
    (tmp_path / "users.txt").write_text("email: user@example.com\n", encoding="utf-8")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "email" for f in findings)

def test_redacts_phone_in_evidence(tmp_path):
    (tmp_path / "data.csv").write_text("13812345678\n", encoding="utf-8")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    for f in findings:
        assert "13812345678" not in f.evidence_redacted
