from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from cleantrace.models import Profile
from cleantrace.plugins.base import PluginFinding
from cleantrace.security import CryptoBox, redact, stable_hash


@dataclass(frozen=True)
class SocialSite:
    name: str
    category: str
    profile_url_template: str
    check_url_template: str
    username_regex: str
    claimed_indicators: list[str]
    unclaimed_indicators: list[str]
    expected_status_codes: list[int]
    false_positive_rules: list[str]
    rate_limit_seconds: float
    requires_javascript: bool
    enabled_by_default: bool
    confidence_rules: dict[str, Any]
    tags: list[str]
    notes: str
    privacy_notes: str

    def profile_url(self, username: str) -> str:
        return self.profile_url_template.format(username=username)

    def check_url(self, username: str) -> str:
        return self.check_url_template.format(username=username)


def load_social_sites() -> list[SocialSite]:
    data_file = Path(__file__).parents[2] / "data" / "social_sites.yaml"
    payload = yaml.safe_load(data_file.read_text(encoding="utf-8")) if data_file.exists() else []
    sites: list[SocialSite] = []
    for item in payload or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        sites.append(
            SocialSite(
                name=str(item["name"]),
                category=str(item.get("category") or "social"),
                profile_url_template=str(item.get("profile_url_template") or ""),
                check_url_template=str(item.get("check_url_template") or ""),
                username_regex=str(item.get("username_regex") or r"^[A-Za-z0-9_.-]{2,}$"),
                claimed_indicators=[str(v) for v in item.get("claimed_indicators", [])],
                unclaimed_indicators=[str(v) for v in item.get("unclaimed_indicators", [])],
                expected_status_codes=[int(v) for v in item.get("expected_status_codes", [200])],
                false_positive_rules=[str(v) for v in item.get("false_positive_rules", [])],
                rate_limit_seconds=float(item.get("rate_limit_seconds", 1)),
                requires_javascript=bool(item.get("requires_javascript", False)),
                enabled_by_default=bool(item.get("enabled_by_default", True)),
                confidence_rules=dict(item.get("confidence_rules", {})),
                tags=[str(v) for v in item.get("tags", [])],
                notes=str(item.get("notes") or ""),
                privacy_notes=str(item.get("privacy_notes") or ""),
            )
        )
    return sites


def sites_for_depth(depth: str, category: str | None = None) -> list[SocialSite]:
    sites = [site for site in load_social_sites() if site.enabled_by_default]
    if category:
        sites = [site for site in sites if site.category == category or category in site.tags]
    limits = {"quick": 12, "standard": 35, "deep": 80}
    return sites[: limits.get(depth, 12)]


def classify_social_response(
    site: SocialSite,
    status_code: int,
    body: str,
) -> tuple[int, str, list[str]]:
    lowered = body.lower()
    tags = ["social-profile", site.category, *site.tags]
    if status_code not in site.expected_status_codes:
        return 20, "info", [*tags, "possible_false_positive"]
    if site.requires_javascript:
        return 45, "info", [*tags, "needs_manual_review"]
    if any(rule.lower() in lowered for rule in site.false_positive_rules):
        return 25, "info", [*tags, "possible_false_positive"]
    if any(indicator.lower() in lowered for indicator in site.unclaimed_indicators):
        return 15, "info", [*tags, "unclaimed"]
    if site.claimed_indicators and any(
        indicator.lower() in lowered for indicator in site.claimed_indicators
    ):
        return 82, "medium", [*tags, "identity-link"]
    return 62, "low", [*tags, "needs_manual_review"]


async def scan_social_profiles(
    profile: Profile,
    crypto: CryptoBox,
    *,
    depth: str = "quick",
    username: str | None = None,
    category: str | None = None,
    timeout: float = 10,
) -> list[PluginFinding]:
    usernames = [username] if username else profile.usernames(crypto)
    findings: list[PluginFinding] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for site in sites_for_depth(depth, category):
            for handle in usernames:
                if not handle:
                    continue
                findings.append(await scan_one_social_site(client, site, handle))
                await asyncio.sleep(min(site.rate_limit_seconds, 2))
    return findings


async def scan_one_social_site(
    client: httpx.AsyncClient,
    site: SocialSite,
    username: str,
) -> PluginFinding:
    url = site.check_url(username)
    status_code = 0
    body = ""
    if url.startswith("manual://"):
        confidence, severity, tags = 20, "info", ["social-profile", site.category, "manual"]
    else:
        try:
            response = await client.get(url, headers={"User-Agent": "CleanTrace self-assessment"})
            status_code = response.status_code
            content_type = response.headers.get("content-type", "")
            if "text" in content_type or "html" in content_type:
                body = response.text[:50_000]
        except httpx.HTTPError:
            pass
        confidence, severity, tags = classify_social_response(site, status_code, body)
    return PluginFinding(
        source_plugin="social_profiles",
        input_type="username",
        input_value_hash=stable_hash(username),
        title=f"{site.name} public profile lead for {redact(username)}",
        description=(
            "CleanTrace checked a public profile endpoint only. This is a lead for manual "
            "review, not proof that the account belongs to the profile owner."
        ),
        url=site.profile_url(username),
        evidence={
            "site": site.name,
            "category": site.category,
            "username": redact(username),
            "http_status": status_code,
            "requires_javascript": site.requires_javascript,
            "privacy_notes": site.privacy_notes,
            "identity_linking_risk": "identity-link" in tags,
        },
        confidence=confidence,
        severity=severity,
        remediation="Review profile visibility and remove unnecessary links to real identity.",
        tags=tags,
    )
