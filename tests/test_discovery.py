from unittest.mock import MagicMock, patch
import pytest
from gh_audit.discovery import clone_repo, cleanup_repo, RepoInfo


def _make_repo_info():
    return RepoInfo(
        full_name="org/repo",
        default_branch="main",
        is_public=True,
        clone_url="https://github.com/org/repo.git",
        head_sha="abc123",
    )


def test_clone_repo_redacts_token_on_failure():
    """Token must not appear in error message when clone fails."""
    import git
    secret_token = "ghp_SUPERSECRETTOKEN123456789012"
    repo_info = _make_repo_info()

    with patch("git.Repo.clone_from") as mock_clone:
        mock_clone.side_effect = git.exc.GitCommandError(
            "clone", 128,
            stderr=f"remote: Invalid username or password for https://x-access-token:{secret_token}@github.com"
        )
        with pytest.raises(RuntimeError) as exc_info:
            clone_repo(repo_info, token=secret_token)

    assert secret_token not in str(exc_info.value)
    assert "***" in str(exc_info.value)


def test_clone_repo_raises_runtime_error_on_git_failure():
    import git
    repo_info = _make_repo_info()

    with patch("git.Repo.clone_from") as mock_clone:
        mock_clone.side_effect = git.exc.GitCommandError("clone", 128, stderr="not found")
        with pytest.raises(RuntimeError, match="Clone failed"):
            clone_repo(repo_info, token=None)


def test_cleanup_repo_handles_missing_dir(tmp_path):
    missing = str(tmp_path / "nonexistent")
    cleanup_repo(missing)  # should not raise
