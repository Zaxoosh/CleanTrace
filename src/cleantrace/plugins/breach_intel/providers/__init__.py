from __future__ import annotations

from typing import Any, cast

from cleantrace.config import config_get, get_api_key
from cleantrace.plugins.breach_intel.providers.base import BreachIntelProvider, ProviderSettings
from cleantrace.plugins.breach_intel.providers.hibp import HIBPBreachIntelProvider
from cleantrace.plugins.breach_intel.providers.metadata_only import (
    DeHashedProvider,
    IntelligenceXProvider,
    LeakCheckProvider,
)


def provider_settings(name: str) -> ProviderSettings:
    root = config_get(f"breach_intel.providers.{name}", {})
    if not isinstance(root, dict):
        root = {}
    api_key = str(root.get("api_key") or "") or get_api_key(name)
    if name == "hibp":
        api_key = api_key or get_api_key("hibp")
    return ProviderSettings(
        name=name,
        enabled=bool(root.get("enabled", False)),
        api_key=api_key,
        terms_accepted=bool(root.get("terms_accepted", False)),
    )


def get_intel_provider(name: str) -> BreachIntelProvider:
    providers: dict[str, Any] = {
        "hibp": HIBPBreachIntelProvider,
        "leakcheck": LeakCheckProvider,
        "dehashed": DeHashedProvider,
        "intelx": IntelligenceXProvider,
    }
    provider_cls = providers.get(name)
    if provider_cls is None:
        raise ValueError(f"Unsupported breach intelligence provider: {name}")
    return cast("BreachIntelProvider", provider_cls(provider_settings(name)))


def provider_statuses() -> list[dict[str, Any]]:
    statuses: list[dict[str, Any]] = []
    for name in ["hibp", "leakcheck", "dehashed", "intelx"]:
        settings = provider_settings(name)
        statuses.append(
            {
                "name": name,
                "enabled": settings.enabled,
                "has_api_key": bool(settings.api_key),
                "terms_accepted": settings.terms_accepted or name == "hibp",
            }
        )
    return statuses
