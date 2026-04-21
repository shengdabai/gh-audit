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
