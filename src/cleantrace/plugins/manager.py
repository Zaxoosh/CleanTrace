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
    ]


def plugins_for_input(input_type: str) -> list[CleanTracePlugin]:
    return [plugin for plugin in built_in_plugins() if input_type in plugin.meta.input_types]
