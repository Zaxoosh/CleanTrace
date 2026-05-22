from __future__ import annotations

from typing import Any

from cleantrace.config import config_get
from cleantrace.plugins.web_discovery.providers.api_stubs import (
    BingProvider,
    BraveProvider,
    GoogleCSEProvider,
    SerpAPIProvider,
)
from cleantrace.plugins.web_discovery.providers.base import ProviderConfig, SearchProvider
from cleantrace.plugins.web_discovery.providers.searxng import SearXNGProvider


def provider_config(name: str) -> ProviderConfig:
    root = config_get(f"web_discovery.providers.{name}", {})
    if not isinstance(root, dict):
        root = {}
    return ProviderConfig(
        name=name,
        enabled=bool(root.get("enabled", False)),
        api_key=str(root.get("api_key") or "") or None,
        base_url=str(root.get("base_url") or "") or None,
        search_engine_id=str(root.get("search_engine_id") or "") or None,
    )


def get_provider(name: str | None = None) -> SearchProvider:
    selected = name or str(config_get("web_discovery.default_provider", "searxng"))
    providers: dict[str, type[SearchProvider]] = {
        "searxng": SearXNGProvider,
        "brave": BraveProvider,
        "bing": BingProvider,
        "google_cse": GoogleCSEProvider,
        "serpapi": SerpAPIProvider,
    }
    provider_cls = providers.get(selected)
    if not provider_cls:
        raise ValueError(f"Unsupported web discovery provider: {selected}")
    return provider_cls(provider_config(selected))


def provider_statuses() -> list[dict[str, Any]]:
    return [
        {"name": name, "enabled": provider_config(name).enabled}
        for name in ["searxng", "brave", "bing", "google_cse", "serpapi"]
    ]
