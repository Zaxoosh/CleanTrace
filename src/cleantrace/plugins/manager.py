from __future__ import annotations

from cleantrace.plugins.base import CleanTracePlugin, PluginMeta
from cleantrace.plugins.github import GitHubConnectorPlugin
from cleantrace.plugins.username import UsernameDiscoveryPlugin


def built_in_plugins() -> list[CleanTracePlugin]:
    return [UsernameDiscoveryPlugin(), GitHubConnectorPlugin()]


def built_in_plugin_metadata() -> list[PluginMeta]:
    return [
        UsernameDiscoveryPlugin.meta,
        GitHubConnectorPlugin.meta,
        PluginMeta(
            name="hibp_email",
            description="Checks email exposure with the official Have I Been Pwned API.",
            input_types=["email"],
            risk_level="API",
            needs_api_key=True,
            uses_scraping=False,
            enabled_by_default=False,
            rate_limit_per_minute=10,
            tags=["email", "breach"],
        ),
        PluginMeta(
            name="web_discovery",
            description="Search-provider-backed public web discovery for consent profiles.",
            input_types=["web_query", "name", "email", "username", "phone", "domain"],
            risk_level="API",
            needs_api_key=False,
            uses_scraping=False,
            enabled_by_default=False,
            rate_limit_per_minute=30,
            tags=["public-web", "search-provider"],
        ),
        PluginMeta(
            name="breach_intel",
            description="Metadata-only breach and dark-web intelligence provider layer.",
            input_types=["email", "username", "phone"],
            risk_level="API",
            needs_api_key=True,
            uses_scraping=False,
            enabled_by_default=False,
            rate_limit_per_minute=10,
            tags=["breach", "metadata-only"],
        ),
        PluginMeta(
            name="tor_public_check",
            description="Checks only explicit user-provided public onion URLs without crawling.",
            input_types=["tor_url"],
            risk_level="sensitive",
            needs_api_key=False,
            uses_scraping=False,
            enabled_by_default=False,
            rate_limit_per_minute=10,
            tags=["tor", "no-crawl"],
        ),
        PluginMeta(
            name="manual_evidence",
            description="Local-only metadata import for user-provided evidence files.",
            input_types=["evidence_import"],
            risk_level="safe",
            needs_api_key=False,
            uses_scraping=False,
            enabled_by_default=True,
            rate_limit_per_minute=60,
            tags=["manual", "metadata-only"],
        ),
    ]


def plugins_for_input(input_type: str) -> list[CleanTracePlugin]:
    return [plugin for plugin in built_in_plugins() if input_type in plugin.meta.input_types]
