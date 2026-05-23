from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cleantrace.models import Finding
from cleantrace.paths import ensure_app_dirs, monitor_state_path


@dataclass(frozen=True)
class MonitorDiff:
    new: list[str]
    removed: list[str]
    reappeared: list[str]
    changed: list[str]


def finding_snapshot(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    return {
        finding.id: {
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "url": finding.url or "",
            "false_positive": finding.false_positive,
        }
        for finding in findings
    }


def load_monitor_state() -> dict[str, Any]:
    ensure_app_dirs()
    path = monitor_state_path()
    if not path.exists():
        return {}
    try:
        return dict(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return {}


def save_monitor_state(state: dict[str, Any]) -> None:
    ensure_app_dirs()
    monitor_state_path().write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def diff_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> MonitorDiff:
    previous_ids = set(previous)
    current_ids = set(current)
    new = sorted(current_ids - previous_ids)
    removed = sorted(previous_ids - current_ids)
    changed = sorted(
        finding_id
        for finding_id in previous_ids & current_ids
        if previous[finding_id].get("severity") != current[finding_id].get("severity")
        or previous[finding_id].get("confidence") != current[finding_id].get("confidence")
    )
    reappeared = [
        finding_id
        for finding_id in current_ids
        if previous.get(finding_id, {}).get("false_positive")
        and not current[finding_id].get("false_positive")
    ]
    return MonitorDiff(new=new, removed=removed, reappeared=reappeared, changed=changed)


def update_monitor_snapshot(profile_slug: str, findings: list[Finding]) -> MonitorDiff:
    state = load_monitor_state()
    profiles = dict(state.get("profiles", {}))
    previous = dict(profiles.get(profile_slug, {}).get("findings", {}))
    current = finding_snapshot(findings)
    diff = diff_snapshots(previous, current)
    profiles[profile_slug] = {
        "last_run": datetime.now(UTC).isoformat(),
        "findings": current,
        "last_diff": diff.__dict__,
    }
    state["profiles"] = profiles
    save_monitor_state(state)
    return diff
