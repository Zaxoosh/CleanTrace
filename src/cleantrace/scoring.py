from __future__ import annotations

from cleantrace.constants import RISK_BANDS, SEVERITY_ORDER
from cleantrace.models import Finding, Profile


def finding_points(finding: Finding, profile: Profile | None = None) -> int:
    base = {
        "info": 1,
        "low": 4,
        "medium": 10,
        "high": 20,
        "critical": 35,
    }.get(finding.severity, 1)
    confidence_factor = max(finding.confidence, 10) / 100
    tags = set(finding.tags)
    if "breach" in tags:
        base += 8
    if tags & {"password", "credential", "secret"}:
        base += 15
    if "identity-link" in tags:
        base += 4
    protected_tags = {"location", "phone", "family", "work-role", "real-name", "professional"}
    if profile and profile.risk_sensitivity == "protected-role" and tags & protected_tags:
        base += 8
    return round(base * confidence_factor)


def exposure_score(findings: list[Finding], profile: Profile | None = None) -> int:
    visible = [finding for finding in findings if not finding.false_positive]
    points = sum(finding_points(finding, profile) for finding in visible)
    severity_boost = 0
    if any(SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["critical"] for f in visible):
        severity_boost = 20
    elif any(SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["high"] for f in visible):
        severity_boost = 10
    return min(100, points + severity_boost)


def score_band(score: int) -> tuple[str, str]:
    for upper, label, colour in RISK_BANDS:
        if score <= upper:
            return label, colour
    return "critical", "red"


def top_actions(findings: list[Finding], limit: int = 5) -> list[str]:
    ranked = sorted(
        [finding for finding in findings if not finding.false_positive],
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.confidence),
        reverse=True,
    )
    actions: list[str] = []
    seen: set[str] = set()
    for finding in ranked:
        action = finding.remediation.strip()
        if action and action not in seen:
            actions.append(action)
            seen.add(action)
        if len(actions) == limit:
            break
    defaults = [
        (
            "Review public profiles for real name, location, employer, family links, "
            "and contact details."
        ),
        "Remove or hide unused accounts that reuse current usernames.",
        "Use distinct usernames for sensitive communities and public professional profiles.",
        "Set up a recurring monthly review for exposed identifiers.",
        "Export a report and track cleanup actions until each item is resolved.",
    ]
    for action in defaults:
        if len(actions) == limit:
            break
        if action not in seen:
            actions.append(action)
    return actions
