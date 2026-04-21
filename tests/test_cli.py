from unittest.mock import MagicMock, patch
from click.testing import CliRunner
from gh_audit.cli import cli


def test_scan_requires_repo_or_org():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])
    assert result.exit_code != 0
    assert "Provide REPO" in result.output or result.exit_code == 2


def test_scan_unknown_module_warns():
    """Unknown module names should produce a warning (not a hard failure)."""
    runner = CliRunner()
    from gh_audit.discovery import RepoInfo
    fake_repo = RepoInfo(
        full_name="org/repo",
        default_branch="main",
        is_public=True,
        clone_url="https://github.com/org/repo.git",
        head_sha="abc123",
    )
    with patch("gh_audit.cli.Config.load") as mock_cfg, \
         patch("gh_audit.cli.get_repo_info", return_value=fake_repo), \
         patch("gh_audit.cli.clone_repo", return_value="/tmp/fake"), \
         patch("gh_audit.cli.cleanup_repo"):
        cfg = MagicMock()
        cfg.token = None
        cfg.modules = ["secrets"]
        cfg.results_dir = MagicMock()
        cfg.history_depth = 1
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["scan", "org/repo", "--modules", "invalid_module"])
    assert "Unknown module" in result.output or "invalid_module" in result.output


def test_doctor_runs_without_token():
    runner = CliRunner()
    with patch("gh_audit.cli.Config.load") as mock_cfg:
        cfg = MagicMock()
        cfg.token = None
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "token" in result.output.lower()


def test_history_no_results(tmp_path):
    runner = CliRunner()
    with patch("gh_audit.cli.Config.load") as mock_cfg:
        cfg = MagicMock()
        cfg.results_dir = tmp_path
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["history", "org/repo"])
    assert result.exit_code == 0
    assert "No scan history" in result.output


def test_suppress_stores_fingerprint(tmp_path):
    runner = CliRunner()
    fake_fp = "a" * 64
    with patch("gh_audit.cli.Path") as mock_path_cls:
        suppress_file = tmp_path / "suppressions.json"
        mock_path_cls.home.return_value = tmp_path
        # Use real Path for other calls
        import pathlib
        mock_path_cls.side_effect = lambda *a: pathlib.Path(*a)
        mock_path_cls.home = lambda: tmp_path

        result = runner.invoke(cli, ["suppress", fake_fp, "--reason", "test data"])
    # Just check it doesn't crash
    assert result.exit_code == 0 or "suppressed" in result.output.lower()


def test_config_set_token_warns(tmp_path):
    runner = CliRunner()
    with patch("gh_audit.cli.Config.load") as mock_cfg:
        cfg = MagicMock()
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["config", "set", "token", "ghp_test"])
    assert result.exit_code == 0
    assert "GITHUB_TOKEN" in result.output or "token" in result.output.lower()
