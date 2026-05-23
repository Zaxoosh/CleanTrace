from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cleantrace.config import config_get, get_api_key
from cleantrace.plugin_state import plugin_enabled


@dataclass(frozen=True)
class ModuleDependency:
    name: str
    label: str
    required_config_keys: list[str] = field(default_factory=list)
    optional_config_keys: list[str] = field(default_factory=list)
    required_api_keys: list[str] = field(default_factory=list)
    privacy_impact: str = "Local metadata only."
    setup_instructions: str = ""
    setup_command: str = ""
    can_run_without_config: bool = True
    fallback_mode: str = "manual review"
    plugin_name: str | None = None


@dataclass(frozen=True)
class ModuleReadiness:
    dependency: ModuleDependency
    ready: bool
    missing_config_keys: list[str]
    missing_api_keys: list[str]
    plugin_enabled: bool
    reason: str


MODULE_DEPENDENCIES: dict[str, ModuleDependency] = {
    "username": ModuleDependency(
        name="username",
        label="Usernames and Social Profiles",
        plugin_name="username_discovery",
        privacy_impact="Direct public profile URL checks may contact listed websites.",
        setup_instructions="No API key required. Uses local site definitions.",
        setup_command="cleantrace plugins enable username_discovery",
    ),
    "social": ModuleDependency(
        name="social",
        label="Expanded Social/Profile Sites",
        plugin_name="social_profiles",
        privacy_impact="Checks public profile URLs for profile usernames.",
        setup_instructions="Enabled by default; sensitive categories remain disabled.",
        setup_command="cleantrace plugins enable social_profiles",
    ),
    "email": ModuleDependency(
        name="email",
        label="Email Exposure",
        plugin_name="hibp_email",
        required_api_keys=["hibp"],
        privacy_impact="HIBP receives the email address when enabled.",
        setup_instructions="Add a HIBP API key or skip this module.",
        setup_command="cleantrace config set api_keys.hibp <key>",
        can_run_without_config=False,
        fallback_mode="skip",
    ),
    "phone": ModuleDependency(
        name="phone",
        label="Phone Exposure",
        privacy_impact="Phone parsing is local. Web discovery may send phone queries if enabled.",
    ),
    "web": ModuleDependency(
        name="web",
        label="Public Web Discovery",
        plugin_name="web_discovery",
        required_config_keys=["web_discovery.enabled"],
        privacy_impact="Selected search provider may receive queries containing identifiers.",
        setup_instructions=(
            "Recommended local option: SearXNG. Recommended API option: Brave Search."
        ),
        setup_command="cleantrace config wizard",
        can_run_without_config=False,
        fallback_mode="manual URL/evidence import",
    ),
    "brokers": ModuleDependency(
        name="brokers",
        label="Data Brokers and People Search",
        plugin_name="data_brokers",
        privacy_impact=(
            "Manual guidance is local. Provider-backed checks use the configured web provider."
        ),
        fallback_mode="manual broker guidance",
    ),
    "intel": ModuleDependency(
        name="intel",
        label="Breach & Dark Web Intelligence",
        plugin_name="breach_intel",
        required_config_keys=["breach_intel.enabled"],
        privacy_impact="Enabled providers receive identifiers. Stored findings are metadata-only.",
        setup_instructions="Enable HIBP or another lawful provider and accept provider terms.",
        setup_command="cleantrace config wizard",
        can_run_without_config=False,
        fallback_mode="skip",
    ),
    "github": ModuleDependency(
        name="github",
        label="GitHub Exposure",
        plugin_name="github_connector",
        privacy_impact="Uses official GitHub APIs for accounts you explicitly link.",
        fallback_mode="skip if no linked account",
    ),
    "takeout": ModuleDependency(
        name="takeout",
        label="Google Takeout Exposure",
        privacy_impact="Local import only. No Google Takeout data is uploaded.",
        fallback_mode="manual import",
    ),
    "tor": ModuleDependency(
        name="tor",
        label="Tor Public URL Checks",
        plugin_name="tor_public_check",
        required_config_keys=["tor_public_check.enabled"],
        privacy_impact="Uses your local Tor SOCKS proxy for explicit user-provided URLs only.",
        setup_instructions="Install/run Tor separately and configure socks_proxy.",
        setup_command="cleantrace config set tor_public_check.enabled true",
        can_run_without_config=False,
        fallback_mode="skip",
    ),
}


def module_readiness(module: str) -> ModuleReadiness:
    dependency = MODULE_DEPENDENCIES[module]
    missing_config = [
        key for key in dependency.required_config_keys if not bool(config_get(key, False))
    ]
    missing_api = [key for key in dependency.required_api_keys if not get_api_key(key)]
    if module == "web" and not missing_config:
        provider = str(config_get("web_discovery.default_provider", "searxng"))
        if not bool(config_get(f"web_discovery.providers.{provider}.enabled", False)):
            missing_config.append(f"web_discovery.providers.{provider}.enabled")
        provider_key = f"web_discovery.providers.{provider}.api_key"
        if provider != "searxng" and not config_get(provider_key, ""):
            missing_config.append(f"web_discovery.providers.{provider}.api_key")
        if provider == "google_cse" and not config_get(
            "web_discovery.providers.google_cse.search_engine_id",
            "",
        ):
            missing_config.append("web_discovery.providers.google_cse.search_engine_id")
    if module == "intel" and not missing_config:
        hibp_enabled = bool(config_get("breach_intel.providers.hibp.enabled", False))
        if not hibp_enabled:
            missing_config.append("breach_intel.providers.hibp.enabled")
        if hibp_enabled and not (
            config_get("breach_intel.providers.hibp.api_key", "") or get_api_key("hibp")
        ):
            missing_api.append("hibp")
    enabled = True
    if dependency.plugin_name:
        enabled = plugin_enabled(dependency.plugin_name)
    ready = enabled and not missing_config and not missing_api
    if ready:
        reason = "Ready"
    elif not enabled:
        reason = "Plugin disabled"
    elif missing_config:
        reason = f"Missing config: {', '.join(missing_config)}"
    else:
        reason = f"Missing API key: {', '.join(missing_api)}"
    if not ready and dependency.can_run_without_config:
        reason = f"{reason}; fallback available: {dependency.fallback_mode}"
    return ModuleReadiness(
        dependency=dependency,
        ready=ready,
        missing_config_keys=missing_config,
        missing_api_keys=missing_api,
        plugin_enabled=enabled,
        reason=reason,
    )


def readiness_for(modules: list[str]) -> list[ModuleReadiness]:
    return [module_readiness(module) for module in modules if module in MODULE_DEPENDENCIES]


def config_sections() -> list[dict[str, Any]]:
    return [
        {
            "name": "General settings",
            "purpose": "Controls default scan depth, country, and redaction.",
            "required": "Recommended",
            "privacy": "Local only.",
            "setting": "scan.default_depth",
        },
        {
            "name": "Storage and encryption",
            "purpose": "Local SQLite database and Fernet key paths.",
            "required": "Required",
            "privacy": "Raw identifiers and tokens are encrypted locally.",
            "setting": "storage.database",
        },
        {
            "name": "Web discovery providers",
            "purpose": "Searches public search providers for consented identifiers.",
            "required": "Only for public web discovery.",
            "privacy": "Provider may receive identifier-bearing queries.",
            "setting": "web_discovery.default_provider",
        },
        {
            "name": "Breach intelligence providers",
            "purpose": "Metadata-only lawful breach provider checks.",
            "required": "Only for breach intelligence.",
            "privacy": "Enabled providers receive identifiers.",
            "setting": "breach_intel.enabled",
        },
        {
            "name": "Phone/country defaults",
            "purpose": "Normalises phone numbers using a default country.",
            "required": "Recommended",
            "privacy": "Local parsing only.",
            "setting": "scan.default_country",
        },
        {
            "name": "Social-site scanner settings",
            "purpose": "Controls broad public profile-site checks.",
            "required": "Recommended",
            "privacy": "Public profile sites may receive profile URL requests.",
            "setting": "social_profiles.enabled",
        },
        {
            "name": "Data broker scanner settings",
            "purpose": "Controls broker guidance and provider-backed broker queries.",
            "required": "Recommended",
            "privacy": "Manual guidance is local; web-backed checks use web provider.",
            "setting": "data_brokers.enabled",
        },
        {
            "name": "Linked accounts",
            "purpose": "Optional connectors for accounts you own.",
            "required": "Optional",
            "privacy": "Tokens are encrypted locally.",
            "setting": "plugins.json",
        },
        {
            "name": "AI/Ollama settings",
            "purpose": "Optional local AI summarisation.",
            "required": "Optional",
            "privacy": "Prefer local Ollama. Cloud-compatible AI requires explicit opt-in.",
            "setting": "ai.provider",
        },
        {
            "name": "Report/export settings",
            "purpose": "Controls report defaults and identity graph output.",
            "required": "Optional",
            "privacy": "Reports are local files and may contain sensitive summaries.",
            "setting": "reports.default_format",
        },
        {
            "name": "Monitoring settings",
            "purpose": "Local scheduled re-checks and finding diffs.",
            "required": "Optional",
            "privacy": "No cloud scheduler is used.",
            "setting": "monitoring.enabled",
        },
    ]
