from rich.console import Console
from rich.table import Table
from rich import box
from gh_audit.models import Finding, Severity

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "green",
    "info": "dim",
}

console = Console()


class TerminalReporter:
    def print(self, findings: list[Finding], repo: str) -> None:
        console.rule(f"[bold]gh-audit: {repo}[/bold]")

        if not findings:
            console.print("[green]No findings.[/green]")
            console.rule()
            return

        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Category", width=12)
        table.add_column("Title", width=30)
        table.add_column("Location", width=30)
        table.add_column("Evidence", width=25)
        table.add_column("Recommendation", width=35)

        for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
            style = _SEVERITY_STYLE.get(f.severity.value, "")
            table.add_row(
                f"[{style}]{f.severity.value.upper()}[/{style}]",
                f.category.value,
                f.title,
                f"{f.file_path}:{f.line_start}",
                f.evidence_redacted,
                f.recommendation,
            )

        console.print(table)
        counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
        console.rule()
        console.print(
            f"[bold red]{counts['critical']} critical[/] · "
            f"[bold orange1]{counts['high']} high[/] · "
            f"[bold yellow]{counts['medium']} medium[/] · "
            f"[green]{counts['low']} low[/]"
        )
