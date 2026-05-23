from __future__ import annotations

from cleantrace.config import config_get
from cleantrace.models import Finding
from cleantrace.security import redact_text


def alert_summary(findings: list[Finding]) -> str | None:
    if not bool(config_get("alerts.enabled", False)):
        return None
    include_sensitive = bool(config_get("alerts.include_sensitive_in_alerts", False))
    lines = [
        f"CleanTrace alert: {len(findings)} finding(s) changed.",
        "Sensitive values included: yes" if include_sensitive else "Sensitive values included: no",
    ]
    for finding in findings[:5]:
        title = finding.title if include_sensitive else redact_text(finding.title)
        lines.append(f"- {finding.severity}: {title}")
    return "\n".join(lines)
