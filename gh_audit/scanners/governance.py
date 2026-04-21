import uuid
from datetime import datetime, timezone

from github import Github, GithubException

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import BaseScanner, ScanConfig


class GovernanceScanner(BaseScanner):
    name = "governance"

    def __init__(self, token: str | None = None):
        self._token = token

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        gh = Github(self._token)
        try:
            repo = gh.get_repo(config.repo)
        except GithubException as e:
            return [self._make(config, "github-api-error", f"Cannot access repo: {e}",
                               Severity.INFO, "Check token permissions")]

        findings: list[Finding] = []

        try:
            branch = repo.get_branch(repo.default_branch)
            if not branch.protected:
                findings.append(self._make(
                    config, "no-branch-protection",
                    f"Default branch '{repo.default_branch}' has no protection rules",
                    Severity.HIGH, "Enable branch protection in Settings → Branches",
                ))
        except GithubException:
            pass

        for fname in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
            try:
                repo.get_contents(fname)
                break
            except Exception:
                continue
        else:
            findings.append(self._make(
                config, "missing-security-md", "No SECURITY.md found",
                Severity.LOW, "Add SECURITY.md with vulnerability reporting instructions",
            ))

        for fname in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
            try:
                repo.get_contents(fname)
                break
            except Exception:
                continue
        else:
            findings.append(self._make(
                config, "missing-codeowners", "No CODEOWNERS file found",
                Severity.LOW, "Add CODEOWNERS to enforce review requirements",
            ))

        return findings

    def _make(self, config: ScanConfig, rule_id: str, title: str,
              severity: Severity, rec: str) -> Finding:
        f = Finding(
            finding_id=str(uuid.uuid4()), fingerprint="",
            repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
            file_path="(repository)", line_start=0, line_end=0,
            category=Category.GOVERNANCE, rule_id=rule_id, title=title,
            severity=severity, confidence=Confidence.CONFIRMED,
            evidence_redacted=title, recommendation=rec,
            standard_mapping=["SLSA-L1", "OpenSSF-Scorecard"],
            scanner=self.name, discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
        )
        f.fingerprint = f.compute_fingerprint()
        return f
