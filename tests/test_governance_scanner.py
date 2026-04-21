from unittest.mock import MagicMock, patch
from gh_audit.scanners.governance import GovernanceScanner
from gh_audit.scanners.base import ScanConfig

def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="HEAD", is_public=False)

def test_no_branch_protection_is_high_finding():
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.protected = False
    mock_repo.get_branch.return_value = mock_branch
    mock_repo.default_branch = "main"
    mock_repo.get_contents.side_effect = Exception("404")

    with patch("gh_audit.scanners.governance.Github") as MockGH:
        MockGH.return_value.get_repo.return_value = mock_repo
        findings = GovernanceScanner(token="fake").scan("", _cfg())

    branch_findings = [f for f in findings if f.rule_id == "no-branch-protection"]
    assert len(branch_findings) == 1
    assert branch_findings[0].severity.value in ("high", "medium")

def test_missing_security_md_is_finding():
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.protected = True
    mock_repo.get_branch.return_value = mock_branch
    mock_repo.default_branch = "main"
    mock_repo.get_contents.side_effect = Exception("404")

    with patch("gh_audit.scanners.governance.Github") as MockGH:
        MockGH.return_value.get_repo.return_value = mock_repo
        findings = GovernanceScanner(token="fake").scan("", _cfg())

    assert any(f.rule_id == "missing-security-md" for f in findings)
