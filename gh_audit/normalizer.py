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
    masked_local = (local[0] + "***") if local else "***"
    return masked_local + "@" + domain


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
    """Load suppressed content fingerprints, skipping expired entries."""
    import json
    from datetime import datetime, timezone, timedelta
    from pathlib import Path
    suppress_file = Path.home() / ".gh-audit" / "suppressions.json"
    if not suppress_file.exists():
        return set()
    try:
        data = json.loads(suppress_file.read_text())
        now = datetime.now(timezone.utc)
        active = set()
        for fp, meta in data.items():
            expires_str = meta.get("expires", "")
            created_str = meta.get("created_at", "")
            if expires_str and created_str:
                try:
                    days = int(expires_str.rstrip("d"))
                    created = datetime.fromisoformat(created_str)
                    if now > created + timedelta(days=days):
                        continue  # expired, skip
                except (ValueError, TypeError):
                    pass  # malformed, treat as non-expiring
            active.add(fp)
        return active
    except Exception:
        return set()
