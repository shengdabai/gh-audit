import re
from gh_audit.models import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            result.append(f)
    return result


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def redact_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11:
        return digits[:3] + "****" + digits[-4:]
    return "***"


def redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "***"
    return local[0] + "***@" + domain


def redact_id_number(value: str) -> str:
    if len(value) == 18:
        return value[:4] + "*" * 11 + value[-4:]
    return "***"


def diff_findings(current: list[Finding], previous_content_fps: set[str]) -> list[Finding]:
    """Return only findings whose content_fingerprint was not in previous scan."""
    return [f for f in current if f.compute_content_fingerprint() not in previous_content_fps]


def load_previous_content_fingerprints(results_dir, repo_name: str) -> set[str]:
    """Load content fingerprints from the most recent previous scan JSON."""
    import json
    from pathlib import Path
    safe_name = repo_name.replace("/", "_")
    repo_dir = Path(results_dir) / safe_name
    if not repo_dir.exists():
        return set()
    files = sorted(repo_dir.glob("*.json"), reverse=True)
    if not files:
        return set()
    try:
        data = json.loads(files[0].read_text())
        return {f.get("content_fingerprint", "") for f in data.get("findings", [])}
    except Exception:
        return set()


def load_suppressions() -> set[str]:
    """Load suppressed content fingerprints."""
    from pathlib import Path
    suppress_file = Path.home() / ".gh-audit" / "suppressions.json"
    if not suppress_file.exists():
        return set()
    try:
        import json
        data = json.loads(suppress_file.read_text())
        return set(data.keys())
    except Exception:
        return set()
