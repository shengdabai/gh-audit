import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from gh_audit.config import Config
from gh_audit.discovery import cleanup_repo, clone_repo, get_repo_info, list_org_repos
from gh_audit.models import Severity
from gh_audit.normalizer import deduplicate
from gh_audit.reporters.html_report import HtmlReporter
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.reporters.terminal import TerminalReporter
from gh_audit.scanners.base import ScanConfig
from gh_audit.scanners.governance import GovernanceScanner
from gh_audit.scanners.iac import IacScanner
from gh_audit.scanners.pii import PiiScanner
from gh_audit.scanners.sast import SastScanner
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.secrets import SecretsScanner

console = Console()

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_ALL_SCANNERS = {
    "secrets": SecretsScanner,
    "pii": PiiScanner,
    "sast": SastScanner,
    "sca": ScaScanner,
    "iac": IacScanner,
}


@click.group()
def cli():
    """GitHub repository security audit tool."""


@cli.command()
@click.argument("repo", required=False)
@click.option("--org", help="Scan all repos in this GitHub org")
@click.option("--branch", default=None)
@click.option("--modules", default=None, help="Comma-separated: secrets,pii,sast,sca,iac,governance")
@click.option("--output", default="terminal", help="Comma-separated: terminal,json,html")
@click.option("--min-severity", default="low",
              type=click.Choice(["info", "low", "medium", "high", "critical"]))
@click.option("--diff", is_flag=True, help="Only report new findings vs last scan")
def scan(repo, org, branch, modules, output, min_severity, diff):
    """Scan a repo or org for security issues."""
    cfg = Config.load()
    output_formats = [o.strip() for o in output.split(",")]
    enabled_modules = [m.strip() for m in modules.split(",")] if modules else cfg.modules

    if org:
        console.print(f"[bold]Discovering repos in org:[/bold] {org}")
        repos = list_org_repos(org, cfg.token)
    elif repo:
        repos = [get_repo_info(repo, cfg.token)]
    else:
        raise click.UsageError("Provide REPO or --org")

    min_sev_idx = _SEVERITY_ORDER.index(min_severity)

    for repo_info in repos:
        console.print(f"\n[bold cyan]Scanning:[/bold cyan] {repo_info.full_name}")
        scan_cfg = ScanConfig(
            repo=repo_info.full_name,
            branch=branch or repo_info.default_branch,
            commit_sha=repo_info.head_sha,
            is_public=repo_info.is_public,
            history_depth=cfg.history_depth,
        )

        all_findings = []
        repo_path = None
        try:
            repo_path = clone_repo(repo_info, cfg.token)
            for mod_name in enabled_modules:
                if mod_name == "governance":
                    scanner = GovernanceScanner(token=cfg.token)
                elif mod_name in _ALL_SCANNERS:
                    scanner = _ALL_SCANNERS[mod_name]()
                else:
                    console.print(f"[yellow]Unknown module: {mod_name}[/yellow]")
                    continue
                if not scanner.is_available():
                    console.print(f"[dim][SKIP] {mod_name} — tool not found[/dim]")
                    continue
                findings = scanner.scan(repo_path, scan_cfg)
                all_findings.extend(findings)
                console.print(f"  [green]✓[/green] {mod_name}: {len(findings)} findings")
        finally:
            if repo_path:
                cleanup_repo(repo_path)

        all_findings = deduplicate(all_findings)
        filtered = [f for f in all_findings
                    if _SEVERITY_ORDER.index(f.severity.value) >= min_sev_idx]
        _write_reports(filtered, repo_info.full_name, output_formats, cfg)


def _write_reports(findings, repo_name, output_formats, cfg):
    safe_name = repo_name.replace("/", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_dir = cfg.results_dir / safe_name
    results_dir.mkdir(parents=True, exist_ok=True)

    if "terminal" in output_formats:
        TerminalReporter().print(findings, repo_name)
    if "json" in output_formats:
        out = results_dir / f"{ts}.json"
        JsonReporter().write(findings, str(out), repo=repo_name)
        console.print(f"[dim]JSON → {out}[/dim]")
    if "html" in output_formats:
        out = results_dir / f"{ts}.html"
        HtmlReporter().write(findings, str(out), repo=repo_name)
        console.print(f"[dim]HTML → {out}[/dim]")


@cli.command()
def doctor():
    """Check tool availability and token status."""
    from github import Github
    cfg = Config.load()
    console.print("\n[bold]gh-audit doctor[/bold]\n")
    if cfg.token:
        try:
            gh = Github(cfg.token)
            rate = gh.get_rate_limit().core
            console.print(f"[green]✓[/green] GitHub token   valid (rate limit: {rate.remaining}/{rate.limit})")
        except Exception as e:
            console.print(f"[red]✗[/red] GitHub token   invalid: {e}")
    else:
        console.print("[yellow]![/yellow] GitHub token   not set (export GITHUB_TOKEN=...)")

    checks = [
        ("secrets",    ["gitleaks", "trufflehog"]),
        ("pii",        []),
        ("sast",       ["semgrep", "bandit"]),
        ("sca",        ["osv-scanner"]),
        ("iac",        ["trivy", "checkov"]),
        ("governance", []),
    ]
    for mod, tools in checks:
        found = [t for t in tools if shutil.which(t)]
        if mod in ("governance", "pii"):
            console.print(f"[green]✓[/green] {mod:<14} builtin (always available)")
        elif found:
            console.print(f"[green]✓[/green] {mod:<14} {', '.join(found)}")
        else:
            hint = f"pip install {tools[0]}" if tools else ""
            console.print(f"[dim]○[/dim] {mod:<14} builtin only  ({hint})")


@cli.command()
@click.argument("repo")
def history(repo):
    """Show past scan results for a repo."""
    cfg = Config.load()
    results_dir = cfg.results_dir / repo.replace("/", "_")
    if not results_dir.exists():
        console.print(f"[yellow]No scan history found for {repo}[/yellow]")
        return
    for f in sorted(results_dir.glob("*.json"), reverse=True)[:10]:
        data = json.loads(f.read_text())
        s = data.get("summary", {})
        console.print(
            f"[dim]{f.stem}[/dim]  "
            f"[red]{s.get('critical',0)}c[/red] "
            f"[orange1]{s.get('high',0)}h[/orange1] "
            f"[yellow]{s.get('medium',0)}m[/yellow] "
            f"[green]{s.get('low',0)}l[/green]"
        )


@cli.command()
@click.argument("finding_id")
@click.option("--reason", required=True)
@click.option("--expires", default="30d")
def suppress(finding_id, reason, expires):
    """Mark a finding as suppressed (false positive)."""
    suppress_file = Path.home() / ".gh-audit" / "suppressions.json"
    data = json.loads(suppress_file.read_text()) if suppress_file.exists() else {}
    data[finding_id] = {"reason": reason, "expires": expires}
    suppress_file.parent.mkdir(parents=True, exist_ok=True)
    suppress_file.write_text(json.dumps(data, indent=2))
    console.print(f"[green]✓[/green] Finding {finding_id} suppressed ({expires}): {reason}")


@cli.group()
def config():
    """Manage gh-audit configuration."""


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a config value."""
    cfg = Config.load()
    cfg.set(key, value)
    console.print(f"[green]✓[/green] Set {key}={value}")
