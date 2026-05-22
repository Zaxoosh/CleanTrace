from __future__ import annotations

import httpx

from cleantrace.plugins.base import PluginFinding, ScanTarget
from cleantrace.plugins.breach_intel.providers.base import (
    BreachMetadata,
    ProviderSettings,
    metadata_to_finding,
)


class MetadataOnlyAPIProvider:
    name = "metadata"
    description = "Metadata-only breach intelligence provider."
    terms_url = ""
    supported_inputs = ["email", "username", "phone"]
    enabled_by_default = False
    risk_label = "API"
    endpoint = ""

    def __init__(self, settings: ProviderSettings, timeout: float = 15.0) -> None:
        self.settings = settings
        self.timeout = timeout

    async def query(self, target: ScanTarget) -> list[PluginFinding]:
        if not self._can_query(target):
            return []
        try:
            payload = await self._request_metadata(target)
        except httpx.HTTPError as exc:
            return [self._status_finding(target, f"{self.name} request failed", str(exc))]
        return [metadata_to_finding(target, item) for item in self._parse_metadata(payload)]

    def _can_query(self, target: ScanTarget) -> bool:
        return (
            self.settings.enabled
            and bool(self.settings.api_key)
            and self.settings.terms_accepted
            and target.input_type in self.supported_inputs
        )

    async def _request_metadata(self, target: ScanTarget) -> object:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                self.endpoint,
                params={"query": target.value, "type": target.input_type},
                headers={"Authorization": f"Bearer {self.settings.api_key}"},
            )
        response.raise_for_status()
        return response.json()

    def _parse_metadata(self, payload: object) -> list[BreachMetadata]:
        if not isinstance(payload, dict):
            return []
        records = payload.get("breaches") or payload.get("results") or payload.get("sources") or []
        if not isinstance(records, list):
            return []
        parsed: list[BreachMetadata] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            classes = (
                record.get("data_classes")
                or record.get("fields")
                or record.get("classes")
                or []
            )
            if not isinstance(classes, list):
                classes = []
            parsed.append(
                BreachMetadata(
                    provider=self.description,
                    source_name=str(record.get("name") or record.get("source") or "Unknown source"),
                    breach_date=str(record.get("breach_date") or record.get("date") or ""),
                    data_classes=[str(item) for item in classes],
                    verified=bool(record.get("verified", False)),
                    sensitive=bool(record.get("sensitive", False)),
                    reference_url=str(record.get("url") or "") or None,
                )
            )
        return parsed

    def _status_finding(self, target: ScanTarget, title: str, detail: str) -> PluginFinding:
        return PluginFinding(
            source_plugin="breach_intel",
            input_type=target.input_type,
            input_value_hash=target.value_hash,
            title=title,
            description="Provider status only. No leaked records were stored or displayed.",
            url=None,
            evidence={
                "provider": self.name,
                "status": detail[:160],
                "metadata_only": True,
                "stored_raw_provider_response": False,
            },
            confidence=100,
            severity="info",
            remediation="Check provider configuration and retry later.",
            tags=["breach-intel", "api-status", "metadata-only"],
        )


class LeakCheckProvider(MetadataOnlyAPIProvider):
    name = "leakcheck"
    description = "LeakCheck API"
    terms_url = "https://leakcheck.io/terms"
    endpoint = "https://leakcheck.io/api/public"


class DeHashedProvider(MetadataOnlyAPIProvider):
    name = "dehashed"
    description = "DeHashed API"
    terms_url = "https://www.dehashed.com/terms"
    endpoint = "https://api.dehashed.com/search"


class IntelligenceXProvider(MetadataOnlyAPIProvider):
    name = "intelx"
    description = "Intelligence X API"
    terms_url = "https://intelx.io/terms-of-service"
    endpoint = "https://2.intelx.io/intelligent/search"
