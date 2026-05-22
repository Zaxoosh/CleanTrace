from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from cleantrace.plugins.base import PluginFinding, ScanTarget


@dataclass(frozen=True)
class ProviderSettings:
    name: str
    enabled: bool = False
    api_key: str | None = None
    terms_accepted: bool = False


@dataclass(frozen=True)
class BreachMetadata:
    provider: str
    source_name: str
    breach_date: str | None = None
    data_classes: list[str] = field(default_factory=list)
    verified: bool = False
    sensitive: bool = False
    reference_url: str | None = None


class BreachIntelProvider(Protocol):
    name: str
    description: str
    terms_url: str
    supported_inputs: list[str]
    enabled_by_default: bool
    risk_label: str

    async def query(self, target: ScanTarget) -> list[PluginFinding]:
        ...


def metadata_to_finding(target: ScanTarget, item: BreachMetadata) -> PluginFinding:
    classes = sorted({value for value in item.data_classes if value})
    lower_classes = {value.lower() for value in classes}
    severity = "medium"
    if item.sensitive or any("password" in value for value in lower_classes):
        severity = "high"
    return PluginFinding(
        source_plugin="breach_intel",
        input_type=target.input_type,
        input_value_hash=target.value_hash,
        title=f"Identifier appears in breach metadata: {item.source_name}",
        description=(
            f"Identifier appeared in breach metadata from {item.provider}. "
            "CleanTrace stores only source metadata and exposed data classes, not leaked records."
        ),
        url=item.reference_url,
        evidence={
            "provider": item.provider,
            "source_name": item.source_name,
            "breach_date": item.breach_date or "",
            "data_classes": classes,
            "metadata_only": True,
            "stored_raw_provider_response": False,
        },
        confidence=95 if item.verified else 80,
        severity=severity,
        remediation=(
            "Change reused passwords, enable MFA, review recovery options, and monitor accounts. "
            "Do not import leaked records into CleanTrace."
        ),
        tags=["breach", "breach-intel", "metadata-only", item.provider.lower()],
    )
