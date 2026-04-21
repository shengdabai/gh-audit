import json
from datetime import datetime, timezone
from gh_audit.models import Finding, Severity


class JsonReporter:
    def write(self, findings: list[Finding], output_path: str, repo: str) -> None:
        summary = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        }
        data = {
            "repo": repo,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
