import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.normalizer import redact_email, redact_id_number, redact_phone, redact_secret
from gh_audit.scanners.base import BaseScanner, ScanConfig

_TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".log", ".sql", ".md", ".yml", ".yaml", ".xml", ".env"}

_PII_PATTERNS = [
    ("cn-phone",    r"(?<!\d)1[3-9]\d{9}(?!\d)",                          Severity.HIGH,   redact_phone,     "Replace with faker-generated data"),
    ("cn-id-number", r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
                                                                           Severity.HIGH,   redact_id_number, "Remove or anonymise PII"),
    ("email",       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", Severity.MEDIUM, redact_email,     "Use anonymised test emails"),
    ("cn-bank-card", r"(?<!\d)\d{16,19}(?!\d)",                           Severity.HIGH,   redact_secret,    "Remove financial data from repo"),
]


class PiiScanner(BaseScanner):
    name = "pii"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path in Path(repo_path).rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _TEXT_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(repo_path))
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule_id, pattern, severity, redact_fn, rec in _PII_PATTERNS:
                    for match in re.finditer(pattern, line):
                        raw = match.group(0)
                        redacted = redact_fn(raw)
                        f = Finding(
                            finding_id=str(uuid.uuid4()), fingerprint="",
                            repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                            file_path=rel, line_start=lineno, line_end=lineno,
                            category=Category.PII, rule_id=rule_id,
                            title=f"PII detected: {rule_id}",
                            severity=severity, confidence=Confidence.LIKELY,
                            evidence_redacted=redacted, recommendation=rec,
                            standard_mapping=["GDPR-Art5", "OWASP-A02"],
                            scanner=self.name, discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
                        )
                        f.fingerprint = f.compute_fingerprint()
                        findings.append(f)
        return findings
