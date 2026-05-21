from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Any, cast

import httpx
import yaml

from cleantrace.plugins.base import PluginFinding, PluginMeta, ScanTarget

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
USER_AGENT = "CleanTrace/0.1 self-assessment contact: local-only"


@dataclass(frozen=True)
class SiteDefinition:
    name: str
    url: str
    check_url: str
    username_claimed_regex: str | None
    username_unclaimed_regex: str | None
    expected_status: list[int]
    tags: list[str]
    country: str | None
    enabled_by_default: bool
    confidence_rules: dict[str, int]
    notes: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SiteDefinition:
        status = raw.get("expected_status", [200])
        expected_status = [status] if isinstance(status, int) else [int(v) for v in status]
        tags = raw.get("tags", [])
        confidence_rules = raw.get("confidence_rules", {})
        return cls(
            name=str(raw["name"]),
            url=str(raw["url"]),
            check_url=str(raw["check_url"]),
            username_claimed_regex=optional_str(raw.get("username_claimed_regex")),
            username_unclaimed_regex=optional_str(raw.get("username_unclaimed_regex")),
            expected_status=expected_status,
            tags=[str(v) for v in tags],
            country=str(raw["country"]) if raw.get("country") else None,
            enabled_by_default=bool(raw.get("enabled_by_default", True)),
            confidence_rules={
                str(k): int(v) for k, v in dict(confidence_rules).items()
            },
            notes=str(raw["notes"]) if raw.get("notes") else None,
        )


class UsernameDiscoveryPlugin:
    meta = PluginMeta(
        name="username_discovery",
        description="Checks public profile URLs from local site definitions.",
        input_types=["username"],
        risk_level="safe",
        needs_api_key=False,
        uses_scraping=False,
        enabled_by_default=True,
        rate_limit_per_minute=60,
        tags=["username", "public-web"],
    )

    def __init__(self, site_file: Path | None = None, timeout: float = 8.0) -> None:
        self.site_file = site_file or Path(__file__).parent / "sites" / "username_sites.yaml"
        self.timeout = timeout

    def load_sites(self, depth: str = "quick") -> list[SiteDefinition]:
        raw = cast(
            "list[dict[str, Any]]",
            yaml.safe_load(self.site_file.read_text(encoding="utf-8")) or [],
        )
        sites = [SiteDefinition.from_dict(item) for item in raw]
        sites = [site for site in sites if site.enabled_by_default]
        if depth == "quick":
            return sites[:10]
        if depth == "standard":
            return sites[:20]
        return sites

    async def run(self, target: ScanTarget) -> list[PluginFinding]:
        semaphore = asyncio.Semaphore(8 if target.depth == "quick" else 12)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            tasks = [
                self._check_site(client, semaphore, site, target)
                for site in self.load_sites(target.depth)
            ]
            results = await asyncio.gather(*tasks)
        return [finding for finding in results if finding is not None]

    async def _check_site(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        site: SiteDefinition,
        target: ScanTarget,
    ) -> PluginFinding | None:
        url = site.check_url.format(username=target.value)
        async with semaphore:
            try:
                response = await client.get(url)
            except httpx.HTTPError as exc:
                return self._info_result(site, target, url, {"error": type(exc).__name__})

        text = response.text[:100_000]
        page_title = extract_title(text)
        claimed = response.status_code in site.expected_status
        if site.username_unclaimed_regex and re.search(site.username_unclaimed_regex, text, re.I):
            claimed = False
        if site.username_claimed_regex:
            pattern = site.username_claimed_regex.format(username=re.escape(target.value))
            claimed = bool(re.search(pattern, text, re.I))
        if not claimed:
            return None

        confidence = site.confidence_rules.get("status_and_pattern", 82)
        if site.username_claimed_regex:
            confidence = max(confidence, 88)
        severity = "low"
        if {"professional", "dev"} & set(site.tags):
            severity = "medium"
        evidence = {
            "site": site.name,
            "http_status": response.status_code,
            "final_url": str(response.url),
            "page_title": page_title,
            "matched_username_hash": target.value_hash,
        }
        return PluginFinding(
            source_plugin=self.meta.name,
            input_type=target.input_type,
            input_value_hash=target.value_hash,
            title=f"Possible public profile on {site.name}",
            description=(
                f"A public profile URL responded like a claimed account on {site.name}. "
                "Review the profile manually before treating it as confirmed."
            ),
            url=str(response.url),
            evidence=evidence,
            confidence=confidence,
            severity=severity,
            remediation=(
                "Review whether this account still needs to be public. Remove personal details, "
                "unlink reused identifiers, or close the account if it is no longer needed."
            ),
            tags=["username", *site.tags],
        )

    def _info_result(
        self,
        site: SiteDefinition,
        target: ScanTarget,
        url: str,
        evidence: dict[str, object],
    ) -> PluginFinding | None:
        if target.depth == "deep":
            return PluginFinding(
                source_plugin=self.meta.name,
                input_type=target.input_type,
                input_value_hash=target.value_hash,
                title=f"Could not check {site.name}",
                description="The public profile check failed and needs manual review.",
                url=url,
                evidence=evidence,
                confidence=10,
                severity="info",
                remediation=(
                    "Open the profile URL manually if this site matters to your exposure review."
                ),
                tags=["username", "manual-review", *site.tags],
            )
        return None


def extract_title(html: str) -> str | None:
    match = TITLE_RE.search(html)
    if not match:
        return None
    title = unescape(re.sub(r"\s+", " ", match.group(1)).strip())
    return title[:160] if title else None


def optional_str(value: object) -> str | None:
    return str(value) if value else None


def finding_to_jsonable(finding: PluginFinding) -> dict[str, object]:
    return {
        "source_plugin": finding.source_plugin,
        "input_type": finding.input_type,
        "input_value_hash": finding.input_value_hash,
        "title": finding.title,
        "description": finding.description,
        "url": finding.url,
        "evidence": json.dumps(finding.evidence, sort_keys=True),
        "confidence": finding.confidence,
        "severity": finding.severity,
        "remediation": finding.remediation,
        "tags": finding.tags,
    }
