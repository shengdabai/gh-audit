import json
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.base import ScanConfig


def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc", is_public=False)


def test_sca_available_by_default():
    # ScaScanner has no is_available override — defaults to True (fallback to API mode)
    with patch("shutil.which", return_value=None):
        assert ScaScanner().is_available() is True


def test_osv_scanner_returns_findings(tmp_path):
    osv_output = {
        "results": [{
            "source": {"path": "requirements.txt"},
            "packages": [{
                "package": {"name": "requests", "version": "2.20.0"},
                "vulnerabilities": [{"id": "GHSA-1234-5678-abcd"}]
            }]
        }]
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(osv_output)
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        with patch("subprocess.run", return_value=mock_result):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-1234-5678-abcd"
    assert "requests" in findings[0].evidence_redacted


def test_osv_scanner_timeout_returns_empty(tmp_path):
    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("osv-scanner", 120)):
            findings = ScaScanner().scan(str(tmp_path), _cfg())
    assert findings == []


def test_osv_api_fallback_parses_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\nflask==1.0.0\n")

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "results": [
            {"vulns": [{"id": "GHSA-1234"}]},  # requests has vuln
            {"vulns": []},                       # flask is clean
        ]
    }

    with patch("shutil.which", return_value=None):
        with patch("requests.post", return_value=mock_resp):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-1234"


def test_osv_api_fallback_handles_network_error(tmp_path):
    import requests as req_lib
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")

    with patch("shutil.which", return_value=None):
        with patch("requests.post", side_effect=req_lib.RequestException("timeout")):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert findings == []
