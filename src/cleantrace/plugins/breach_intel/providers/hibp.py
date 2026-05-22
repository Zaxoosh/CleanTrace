from __future__ import annotations

from cleantrace.plugins.base import PluginFinding, ScanTarget
from cleantrace.plugins.breach_intel.providers.base import ProviderSettings
from cleantrace.plugins.hibp import HIBPEmailPlugin


class HIBPBreachIntelProvider:
    name = "hibp"
    description = "Have I Been Pwned official breach metadata API."
    terms_url = "https://haveibeenpwned.com/API/v3"
    supported_inputs = ["email"]
    enabled_by_default = False
    risk_label = "API"

    def __init__(self, settings: ProviderSettings) -> None:
        self.settings = settings

    async def query(self, target: ScanTarget) -> list[PluginFinding]:
        if not self.settings.enabled or not self.settings.api_key or target.input_type != "email":
            return []
        plugin = HIBPEmailPlugin(self.settings.api_key)
        findings = await plugin.run(target)
        return [
            PluginFinding(
                source_plugin="breach_intel",
                input_type=finding.input_type,
                input_value_hash=finding.input_value_hash,
                title=finding.title,
                description=(
                    "Breach & Dark Web Intelligence metadata from Have I Been Pwned. "
                    "CleanTrace stores only breach summaries, not leaked records."
                ),
                url=finding.url,
                evidence={
                    **finding.evidence,
                    "provider": "Have I Been Pwned",
                    "metadata_only": True,
                    "stored_raw_provider_response": False,
                },
                confidence=finding.confidence,
                severity=finding.severity,
                remediation=finding.remediation,
                tags=sorted({*finding.tags, "breach-intel", "metadata-only"}),
            )
            for finding in findings
        ]
