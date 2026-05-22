from __future__ import annotations

from dataclasses import dataclass

import httpx

from cleantrace.plugins.base import PluginFinding, PluginMeta, ScanTarget

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_USER_AGENT = "CleanTrace/0.2 local-first self-assessment"


@dataclass(frozen=True)
class BreachSummary:
    name: str
    title: str
    domain: str
    breach_date: str
    data_classes: list[str]
    is_verified: bool
    is_sensitive: bool


class HIBPEmailPlugin:
    meta = PluginMeta(
        name="hibp_email",
        description="Checks email exposure with the official Have I Been Pwned API.",
        input_types=["email"],
        risk_level="API",
        needs_api_key=True,
        uses_scraping=False,
        enabled_by_default=False,
        rate_limit_per_minute=10,
        tags=["email", "breach"],
    )

    def __init__(self, api_key: str, timeout: float = 10.0) -> None:
        self.api_key = api_key
        self.timeout = timeout

    async def run(self, target: ScanTarget) -> list[PluginFinding]:
        headers = {
            "hibp-api-key": self.api_key,
            "User-Agent": HIBP_USER_AGENT,
        }
        url = f"{HIBP_BASE_URL}/breachedaccount/{target.value}"
        params = {"truncateResponse": "false"}
        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            response = await client.get(url, params=params)
        if response.status_code == 404:
            return []
        if response.status_code in {401, 403}:
            return [
                self._api_status_finding(
                    target,
                    "HIBP API key rejected",
                    "Have I Been Pwned rejected the configured API key.",
                    response.status_code,
                    "Update the HIBP API key in the CleanTrace config or environment.",
                )
            ]
        if response.status_code == 429:
            return [
                self._api_status_finding(
                    target,
                    "HIBP rate limit reached",
                    "Have I Been Pwned rate-limited this email exposure check.",
                    response.status_code,
                    "Wait before retrying. CleanTrace does not bypass API limits.",
                )
            ]
        response.raise_for_status()
        breaches = [parse_breach(item) for item in response.json()]
        return [breach_to_finding(target, breach) for breach in breaches]

    def _api_status_finding(
        self,
        target: ScanTarget,
        title: str,
        description: str,
        status_code: int,
        remediation: str,
    ) -> PluginFinding:
        return PluginFinding(
            source_plugin=self.meta.name,
            input_type=target.input_type,
            input_value_hash=target.value_hash,
            title=title,
            description=description,
            url=None,
            evidence={"http_status": status_code, "provider": "Have I Been Pwned"},
            confidence=100,
            severity="info",
            remediation=remediation,
            tags=["email", "api-status"],
        )


def parse_breach(raw: dict[str, object]) -> BreachSummary:
    data_classes = raw.get("DataClasses", [])
    if not isinstance(data_classes, list):
        data_classes = []
    return BreachSummary(
        name=str(raw.get("Name") or ""),
        title=str(raw.get("Title") or raw.get("Name") or "Unknown breach"),
        domain=str(raw.get("Domain") or ""),
        breach_date=str(raw.get("BreachDate") or ""),
        data_classes=[str(item) for item in data_classes],
        is_verified=bool(raw.get("IsVerified", False)),
        is_sensitive=bool(raw.get("IsSensitive", False)),
    )


def breach_to_finding(target: ScanTarget, breach: BreachSummary) -> PluginFinding:
    data_classes = {item.lower() for item in breach.data_classes}
    severity = "medium"
    if "passwords" in data_classes or "password hints" in data_classes:
        severity = "high"
    if breach.is_sensitive:
        severity = "high"
    tags = ["email", "breach", "hibp"]
    if any("password" in item for item in data_classes):
        tags.append("password")
    return PluginFinding(
        source_plugin="hibp_email",
        input_type=target.input_type,
        input_value_hash=target.value_hash,
        title=f"Email appears in {breach.title}",
        description=(
            "The official Have I Been Pwned API reports this email in a breach. "
            "CleanTrace stores only the breach summary, not leaked records."
        ),
        url=f"https://haveibeenpwned.com/PwnedWebsites#{breach.name}" if breach.name else None,
        evidence={
            "breach_name": breach.name,
            "breach_title": breach.title,
            "domain": breach.domain,
            "breach_date": breach.breach_date,
            "data_classes": sorted(breach.data_classes),
            "verified": breach.is_verified,
            "sensitive": breach.is_sensitive,
        },
        confidence=96 if breach.is_verified else 82,
        severity=severity,
        remediation=(
            "Change passwords on affected services, use unique passwords, enable MFA, "
            "and review account recovery details. Do not store breached passwords in CleanTrace."
        ),
        tags=tags,
    )
