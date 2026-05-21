from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from cleantrace.models import Finding, Profile, build_profile
from cleantrace.plugins.base import PluginFinding, ScanTarget
from cleantrace.plugins.manager import plugins_for_input
from cleantrace.security import CryptoBox, stable_hash


def create_profile(
    session: Session,
    crypto: CryptoBox,
    *,
    slug: str,
    legal_name: str | None,
    display_names: list[str],
    usernames: list[str],
    emails: list[str],
    phones: list[str],
    location: str | None,
    domains: list[str],
    social_links: list[str],
    role_notes: str | None,
    risk_sensitivity: str,
    consent: bool,
) -> Profile:
    profile = build_profile(
        slug=slug,
        crypto=crypto,
        legal_name=legal_name,
        display_names=display_names,
        usernames=usernames,
        emails=emails,
        phones=phones,
        location=location,
        domains=domains,
        social_links=social_links,
        role_notes=role_notes,
        risk_sensitivity=risk_sensitivity,
        consent=consent,
    )
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return profile


async def scan_username(
    session: Session,
    *,
    profile: Profile,
    username: str,
    depth: str,
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    target = ScanTarget(
        profile_id=profile.id,
        input_type="username",
        value=username,
        value_hash=stable_hash(username),
        depth=depth,
    )
    stored: list[Finding] = []
    for plugin in plugins_for_input("username"):
        for plugin_finding in await plugin.run(target):
            stored.append(upsert_finding(session, profile, plugin_finding))
    session.commit()
    return stored


def upsert_finding(session: Session, profile: Profile, plugin_finding: PluginFinding) -> Finding:
    if profile.id is None:
        raise ValueError("Profile id is required.")
    existing = session.exec(
        select(Finding).where(
            Finding.profile_id == profile.id,
            Finding.source_plugin == plugin_finding.source_plugin,
            Finding.input_type == plugin_finding.input_type,
            Finding.input_value_hash == plugin_finding.input_value_hash,
            Finding.url == plugin_finding.url,
        )
    ).first()
    now = datetime.now(UTC)
    if existing:
        existing.title = plugin_finding.title
        existing.description = plugin_finding.description
        existing.evidence_json = json.dumps(plugin_finding.evidence, sort_keys=True)
        existing.confidence = plugin_finding.confidence
        existing.severity = plugin_finding.severity
        existing.last_seen = now
        existing.remediation = plugin_finding.remediation
        existing.tags_json = json.dumps(plugin_finding.tags, sort_keys=True)
        session.add(existing)
        return existing
    finding = Finding(
        profile_id=profile.id,
        source_plugin=plugin_finding.source_plugin,
        input_type=plugin_finding.input_type,
        input_value_hash=plugin_finding.input_value_hash,
        title=plugin_finding.title,
        description=plugin_finding.description,
        url=plugin_finding.url,
        evidence_json=json.dumps(plugin_finding.evidence, sort_keys=True),
        confidence=plugin_finding.confidence,
        severity=plugin_finding.severity,
        remediation=plugin_finding.remediation,
        tags_json=json.dumps(plugin_finding.tags, sort_keys=True),
    )
    session.add(finding)
    session.flush()
    return finding
